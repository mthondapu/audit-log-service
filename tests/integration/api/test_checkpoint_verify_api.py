"""GET /audit/verify against the latest checkpoint (FR-4, Phase 10 decisions CP8 to CP10, CP16).

Checkpoints are created with the checkpoint application service through the read-only checkpoint
role. Tampering is done only with the owner engine, outside the application path.
"""

import logging
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Connection, Engine, text

from audit_log_service.api.app import CHECKPOINT_STORE_ERROR_DETAIL
from audit_log_service.application import verification as verification_module
from audit_log_service.application.checkpoints import create_checkpoint
from audit_log_service.application.verification import VIOLATION_MESSAGES
from audit_log_service.integrity.checkpoints import (
    Checkpoint,
    encode_artifact,
    key_id,
    sign_checkpoint,
)
from audit_log_service.integrity.hashing import AuditRecord
from audit_log_service.integrity.verification import ChainEntry, ViolationType
from audit_log_service.persistence.audit_log import NewEvent, append_event, load_chain_entries
from audit_log_service.persistence.checkpoint_store import checkpoint_file_name
from audit_log_service.persistence.checkpoint_writer import write_checkpoint

Headers = dict[str, str]
Seed = Callable[..., list[AuditRecord]]
Verify = Callable[[], dict[str, Any]]
Checkpointer = Callable[[], None]


@pytest.fixture
def seed(app_engine: Engine, new_event: Callable[..., NewEvent]) -> Seed:
    def run(count: int = 1, **changes: Any) -> list[AuditRecord]:
        with app_engine.begin() as connection:
            return [append_event(connection, new_event(**changes)) for _ in range(count)]

    return run


@pytest.fixture
def checkpoint(
    checkpoint_engine: Engine, checkpoint_store: Path, checkpoint_key: Ed25519PrivateKey
) -> Checkpointer:
    def run() -> None:
        create_checkpoint(checkpoint_engine, checkpoint_store, checkpoint_key, "ops.admin")

    return run


@pytest.fixture
def verify(client: httpx.Client, auditor: Headers) -> Verify:
    def run() -> dict[str, Any]:
        response = client.get("/audit/verify", headers=auditor)
        assert response.status_code == 200, response.text
        body: dict[str, Any] = response.json()
        return body

    return run


def _truncate_after(owner_engine: Engine, sequence: int) -> None:
    with owner_engine.begin() as connection:
        connection.execute(
            text(
                "DELETE FROM audit_payload_values WHERE record_id IN "
                "(SELECT id FROM audit_records WHERE sequence > :sequence)"
            ),
            {"sequence": sequence},
        )
        connection.execute(
            text("DELETE FROM audit_records WHERE sequence > :sequence"), {"sequence": sequence}
        )


def test_without_a_checkpoint_the_anchor_is_none(verify: Verify, seed: Seed) -> None:
    seed(2)
    report = verify()
    assert report["intact"] is True
    assert report["anchor"] == {"status": "NONE", "sequence": None}


def test_checkpointed_chain_is_verified(
    verify: Verify, seed: Seed, checkpoint: Checkpointer
) -> None:
    seed(3)
    checkpoint()

    report = verify()

    assert report["intact"] is True
    assert report["anchor"] == {"status": "VERIFIED", "sequence": 3}


def test_records_after_the_checkpoint_keep_it_verified(
    verify: Verify, seed: Seed, checkpoint: Checkpointer
) -> None:
    seed(2)
    checkpoint()
    seed(3)

    report = verify()

    assert (report["intact"], report["head"]["sequence"]) == (True, 5)
    assert report["anchor"] == {"status": "VERIFIED", "sequence": 2}


def test_latest_checkpoint_is_the_anchor(
    verify: Verify, seed: Seed, checkpoint: Checkpointer
) -> None:
    seed(1)
    checkpoint()
    seed(2)
    checkpoint()
    assert verify()["anchor"] == {"status": "VERIFIED", "sequence": 3}


def test_tail_truncation_below_the_checkpoint_is_detected(
    verify: Verify, seed: Seed, checkpoint: Checkpointer, owner_engine: Engine
) -> None:
    seed(4)
    checkpoint()
    _truncate_after(owner_engine, 2)

    report = verify()

    assert report["intact"] is False
    assert report["head"]["sequence"] == 2
    assert report["anchor"] == {"status": "TRUNCATED", "sequence": 4}
    assert report["violationCount"] == 1
    assert report["firstViolation"] == {
        "type": "CHAIN_TRUNCATED",
        "sequence": 3,
        "recordId": None,
        "message": VIOLATION_MESSAGES[ViolationType.CHAIN_TRUNCATED],
    }


def test_truncation_of_every_record_is_detected(
    verify: Verify, seed: Seed, checkpoint: Checkpointer, owner_engine: Engine
) -> None:
    seed(2)
    checkpoint()
    _truncate_after(owner_engine, 0)

    report = verify()

    assert (report["intact"], report["head"], report["recordsChecked"]) == (False, None, 0)
    assert report["anchor"] == {"status": "TRUNCATED", "sequence": 2}
    assert report["firstViolation"]["sequence"] == 1


def test_full_rewrite_with_recomputed_hashes_is_an_anchor_mismatch(
    verify: Verify, seed: Seed, checkpoint: Checkpointer, owner_engine: Engine
) -> None:
    seed(3)
    checkpoint()
    # The tamper actor deletes everything and rebuilds a consistent chain through the append path.
    _truncate_after(owner_engine, 0)
    rewritten = seed(3, actor_id="rewritten")

    report = verify()

    assert report["intact"] is False
    assert report["anchor"] == {"status": "MISMATCH", "sequence": 3}
    assert report["violationCount"] == 1
    assert report["firstViolation"] == {
        "type": "ANCHOR_MISMATCH",
        "sequence": 3,
        "recordId": rewritten[2].content.id,
        "message": VIOLATION_MESSAGES[ViolationType.ANCHOR_MISMATCH],
    }


def test_truncation_after_the_checkpoint_is_not_detected(
    verify: Verify, seed: Seed, checkpoint: Checkpointer, owner_engine: Engine
) -> None:
    # The documented limitation: records after the latest checkpoint are unanchored (FR-4).
    seed(2)
    checkpoint()
    seed(2)
    _truncate_after(owner_engine, 3)

    report = verify()

    assert report["intact"] is True
    assert report["anchor"] == {"status": "VERIFIED", "sequence": 2}


def test_middle_modification_below_the_checkpoint_is_still_located(
    verify: Verify, seed: Seed, checkpoint: Checkpointer, owner_engine: Engine
) -> None:
    seed(3)
    checkpoint()
    with owner_engine.begin() as connection:
        connection.execute(text("UPDATE audit_records SET actor_id = 'forged' WHERE sequence = 2"))

    report = verify()

    assert (report["firstViolation"]["type"], report["firstViolation"]["sequence"]) == (
        "CONTENT_HASH_MISMATCH",
        2,
    )
    assert report["anchor"] == {"status": "VERIFIED", "sequence": 3}


# --- An invalid store fails closed (CP8) ---------------------------------------------------------


def _assert_store_problem(response: httpx.Response) -> None:
    assert response.status_code == 500
    assert response.headers["content-type"] == "application/problem+json"
    body = response.json()
    assert body["detail"] == CHECKPOINT_STORE_ERROR_DETAIL
    assert body["requestId"] == response.headers["x-request-id"]


def test_corrupt_artifact_is_a_500_that_logs_only_the_file_name(
    client: httpx.Client,
    auditor: Headers,
    seed: Seed,
    checkpoint_store: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    seed(1)
    name = checkpoint_file_name(1)
    (checkpoint_store / name).write_bytes(b"test-only-corrupt-content")
    caplog.set_level(logging.ERROR, logger="audit_log_service.api")

    response = client.get("/audit/verify", headers=auditor)

    _assert_store_problem(response)
    assert "test-only-corrupt-content" not in response.text
    assert name in caplog.text
    assert "test-only-corrupt-content" not in caplog.text


def test_artifact_signed_by_an_untrusted_key_is_a_500(
    client: httpx.Client, auditor: Headers, seed: Seed, checkpoint_store: Path
) -> None:
    [record] = seed(1)
    untrusted = Ed25519PrivateKey.generate()
    forged = Checkpoint(
        sequence=1,
        record_hash=record.record_hash,
        created_at="2026-09-28T10:15:30.123456Z",
        created_by="ops.admin",
        key_id=key_id(untrusted.public_key()),
    )
    write_checkpoint(checkpoint_store, sign_checkpoint(untrusted, forged))

    _assert_store_problem(client.get("/audit/verify", headers=auditor))


def test_forged_higher_checkpoint_is_not_trusted(
    client: httpx.Client,
    auditor: Headers,
    seed: Seed,
    checkpoint: Checkpointer,
    checkpoint_store: Path,
    checkpoint_key: Ed25519PrivateKey,
) -> None:
    seed(1)
    checkpoint()
    signed = sign_checkpoint(
        checkpoint_key,
        Checkpoint(
            sequence=9,
            record_hash="ab" * 32,
            created_at="2026-09-28T10:15:30.123456Z",
            created_by="ops.admin",
            key_id=key_id(checkpoint_key.public_key()),
        ),
    )
    data = bytearray(encode_artifact(signed))
    data[data.index(b'"sequence":9') + len('"sequence":')] = ord("8")
    (checkpoint_store / checkpoint_file_name(8)).write_bytes(bytes(data))

    _assert_store_problem(client.get("/audit/verify", headers=auditor))


def test_unreadable_store_is_a_500(
    client: httpx.Client, auditor: Headers, checkpoint_store: Path
) -> None:
    checkpoint_store.rmdir()
    _assert_store_problem(client.get("/audit/verify", headers=auditor))


def test_store_is_not_read_before_authentication(
    client: httpx.Client, writer: Headers, checkpoint_store: Path
) -> None:
    checkpoint_store.rmdir()
    assert client.get("/audit/verify").status_code == 401
    assert client.get("/audit/verify", headers=writer).status_code == 403


# --- The store is read before the snapshot (CP16) ----------------------------------------------


def test_checkpoint_written_after_the_store_read_is_not_mistaken_for_truncation(
    verify: Verify,
    seed: Seed,
    checkpoint: Checkpointer,
    app_engine: Engine,
    new_event: Callable[..., NewEvent],
    checkpoint_store: Path,
    checkpoint_key: Ed25519PrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed(2)
    checkpoint()

    def load_after_a_concurrent_checkpoint(connection: Connection) -> list[ChainEntry]:
        # Inside the open snapshot: another session appends and checkpoints the new head.
        with app_engine.begin() as other:
            appended = [append_event(other, new_event()) for _ in range(2)]
        head = appended[-1]
        write_checkpoint(
            checkpoint_store,
            sign_checkpoint(
                checkpoint_key,
                Checkpoint(
                    sequence=head.sequence,
                    record_hash=head.record_hash,
                    created_at="2026-09-28T10:15:30.123456Z",
                    created_by="ops.admin",
                    key_id=key_id(checkpoint_key.public_key()),
                ),
            ),
        )
        return load_chain_entries(connection)

    monkeypatch.setattr(
        verification_module, "load_chain_entries", load_after_a_concurrent_checkpoint
    )

    report = verify()

    # The snapshot predates the new records and the store was read before it, so the anchor is
    # the earlier checkpoint. Reading the store after the snapshot would report CHAIN_TRUNCATED.
    assert report["intact"] is True
    assert report["recordsChecked"] == 2
    assert report["anchor"] == {"status": "VERIFIED", "sequence": 2}
    assert sorted(p.name for p in checkpoint_store.iterdir()) == [
        checkpoint_file_name(2),
        checkpoint_file_name(4),
    ]


def test_report_discloses_no_protected_fields_after_a_rewrite(
    client: httpx.Client,
    auditor: Headers,
    seed: Seed,
    checkpoint: Checkpointer,
    owner_engine: Engine,
    fake_keys: dict[str, str],
) -> None:
    seed(2, payload={"card": "test-only-card-4111"})
    checkpoint()
    _truncate_after(owner_engine, 0)
    seed(2, actor_id="actor-secret", resource_id="resource-secret")

    body = client.get("/audit/verify", headers=auditor).text

    for secret in ("test-only-card-4111", "actor-secret", "resource-secret", "ops.admin"):
        assert secret not in body
    assert not any(key in body for key in fake_keys.values())
    assert str(uuid.UUID(int=0)) not in body
