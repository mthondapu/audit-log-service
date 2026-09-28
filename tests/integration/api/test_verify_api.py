"""API tests for GET /audit/verify (FR-3) against real PostgreSQL.

Tampering is done only here, inside tests, with the owner role (Phase 7 decision D6).
"""

import dataclasses
import re
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from sqlalchemy import URL, Connection, Engine, create_engine, pool, text

from audit_log_service.application import verification as verification_module
from audit_log_service.application.verification import VIOLATION_MESSAGES, verify_audit_chain
from audit_log_service.integrity.hashing import AuditRecord, seal_record
from audit_log_service.integrity.timestamps import parse_timestamp
from audit_log_service.integrity.verification import ChainEntry, ViolationType
from audit_log_service.persistence.audit_log import NewEvent, append_event, load_chain_entries

Headers = dict[str, str]
Seed = Callable[..., list[AuditRecord]]
Load = Callable[[], list[ChainEntry]]
CANONICAL_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")
OTHER_HASH = "e" * 64


@pytest.fixture
def seed(app_engine: Engine, new_event: Callable[..., NewEvent]) -> Seed:
    def run(count: int = 1, **changes: Any) -> list[AuditRecord]:
        with app_engine.begin() as connection:
            return [append_event(connection, new_event(**changes)) for _ in range(count)]

    return run


@pytest.fixture
def verify(client: httpx.Client, auditor: Headers) -> Callable[[], dict[str, Any]]:
    def run() -> dict[str, Any]:
        response = client.get("/audit/verify", headers=auditor)
        assert response.status_code == 200, response.text
        body: dict[str, Any] = response.json()
        return body

    return run


Verify = Callable[[], dict[str, Any]]


def _tamper(engine: Engine, statement: str, **parameters: Any) -> None:
    with engine.begin() as connection:
        connection.execute(text(statement), parameters)


def _first(report: dict[str, Any]) -> tuple[str, int] | None:
    violation = report["firstViolation"]
    return None if violation is None else (violation["type"], violation["sequence"])


def _assert_problem(response: httpx.Response, status: int) -> dict[str, Any]:
    assert response.status_code == status
    assert response.headers["content-type"] == "application/problem+json"
    body: dict[str, Any] = response.json()
    assert body["requestId"] == response.headers["x-request-id"]
    return body


# --- Access and parameters ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "authorization",
    [{}, {"Authorization": "Bearer unknown-test-key"}, {"Authorization": "Basic x"}],
    ids=["missing", "unknown-key", "non-bearer"],
)
def test_authentication_failures_are_401_before_validation(
    client: httpx.Client, authorization: Headers
) -> None:
    response = client.get("/audit/verify", params={"unknown": "x"}, headers=authorization)
    _assert_problem(response, 401)
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("principal", ["writer", "administrator"])
def test_principals_without_chain_verify_are_403(
    client: httpx.Client, request: pytest.FixtureRequest, principal: str
) -> None:
    headers: Headers = request.getfixturevalue(principal)
    _assert_problem(client.get("/audit/verify", params={"x": "1"}, headers=headers), 403)


@pytest.mark.parametrize("principal", ["auditor", "regulator"])
def test_auditor_and_regulator_can_verify(
    client: httpx.Client, principal: str, fake_keys: Any
) -> None:
    key = fake_keys[principal]
    response = client.get("/audit/verify", headers={"Authorization": f"Bearer {key}"})
    assert response.status_code == 200


@pytest.mark.parametrize(
    "params",
    [[("unknown", "x")], [("limit", "5"), ("limit", "6")], [("x", "")]],
    ids=["unknown", "repeated", "empty-value"],
)
def test_query_parameters_are_rejected(
    client: httpx.Client, auditor: Headers, params: list[tuple[str, str]]
) -> None:
    response = client.get("/audit/verify", params=tuple(params), headers=auditor)
    assert _assert_problem(response, 422)["detail"] == (
        "the verification endpoint accepts no query parameters"
    )


# --- Intact chains ------------------------------------------------------------------------------


def test_empty_chain_is_intact(verify: Verify) -> None:
    report = verify()
    assert {key: value for key, value in report.items() if key != "verifiedAt"} == {
        "intact": True,
        "scheme": "audit-log/v1",
        "recordsChecked": 0,
        "head": None,
        "anchor": {"status": "NONE", "sequence": None},
        "violationCount": 0,
        "firstViolation": None,
    }


def test_intact_chain_reports_its_head(verify: Verify, seed: Seed) -> None:
    records = seed(4)

    report = verify()

    assert report["intact"] is True
    assert report["recordsChecked"] == 4
    assert report["head"] == {"sequence": 4, "recordHash": records[-1].record_hash}
    assert report["violationCount"] == 0


def test_verified_at_comes_from_the_database_clock(verify: Verify, app_engine: Engine) -> None:
    with app_engine.connect() as connection:
        before = connection.execute(text("SELECT clock_timestamp()")).scalar_one()
    verified_at = verify()["verifiedAt"]
    with app_engine.connect() as connection:
        after = connection.execute(text("SELECT clock_timestamp()")).scalar_one()

    assert CANONICAL_TIME.fullmatch(verified_at)
    assert before <= parse_timestamp(verified_at) <= after


def test_verification_reads_one_read_only_repeatable_read_snapshot(
    app_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, str] = {}

    def spy(connection: Connection) -> list[ChainEntry]:
        observed["isolation"] = connection.execute(text("SHOW transaction_isolation")).scalar_one()
        observed["read_only"] = connection.execute(text("SHOW transaction_read_only")).scalar_one()
        return load_chain_entries(connection)

    monkeypatch.setattr(verification_module, "load_chain_entries", spy)

    verify_audit_chain(app_engine)

    assert observed == {"isolation": "repeatable read", "read_only": "on"}


def test_verification_does_not_change_the_chain(verify: Verify, seed: Seed, load: Load) -> None:
    seed(3)
    before = load()
    verify()
    verify()
    assert load() == before


# --- Detected tampering --------------------------------------------------------------------------


def test_modified_actor_is_a_content_hash_mismatch(
    verify: Verify, seed: Seed, owner_engine: Engine
) -> None:
    records = seed(3)
    _tamper(owner_engine, "UPDATE audit_records SET actor_id = 'forged' WHERE sequence = 2")

    report = verify()

    assert report["intact"] is False
    assert report["violationCount"] == 1
    assert report["firstViolation"] == {
        "type": "CONTENT_HASH_MISMATCH",
        "sequence": 2,
        "recordId": records[1].content.id,
        "message": VIOLATION_MESSAGES[ViolationType.CONTENT_HASH_MISMATCH],
    }


def test_modified_committed_payload_is_a_content_hash_mismatch(
    verify: Verify, seed: Seed, owner_engine: Engine
) -> None:
    seed(2)
    _tamper(owner_engine, "UPDATE audit_records SET committed_payload = '{}' WHERE sequence = 1")
    assert _first(verify()) == ("CONTENT_HASH_MISMATCH", 1)


def test_modified_stored_value_is_a_payload_value_mismatch(
    verify: Verify, seed: Seed, owner_engine: Engine
) -> None:
    records = seed(2)
    _tamper(
        owner_engine,
        "UPDATE audit_payload_values SET canonical_value = '\"forged\"' WHERE record_id = :id",
        id=uuid.UUID(records[1].content.id),
    )
    assert _first(verify()) == ("PAYLOAD_VALUE_MISMATCH", 2)


def test_modified_record_hash_breaks_this_record_and_the_next_link(
    verify: Verify, seed: Seed, owner_engine: Engine
) -> None:
    seed(3)
    _tamper(
        owner_engine, "UPDATE audit_records SET record_hash = :h WHERE sequence = 2", h=OTHER_HASH
    )

    report = verify()

    assert _first(report) == ("RECORD_HASH_MISMATCH", 2)
    assert report["violationCount"] == 2


def test_modified_previous_hash_is_a_previous_hash_mismatch(
    verify: Verify, seed: Seed, owner_engine: Engine
) -> None:
    seed(3)
    _tamper(
        owner_engine, "UPDATE audit_records SET previous_hash = :h WHERE sequence = 3", h=OTHER_HASH
    )
    assert _first(verify()) == ("PREVIOUS_HASH_MISMATCH", 3)


def test_modified_genesis_link_is_a_genesis_mismatch(
    verify: Verify, seed: Seed, owner_engine: Engine
) -> None:
    seed(2)
    _tamper(
        owner_engine, "UPDATE audit_records SET previous_hash = :h WHERE sequence = 1", h=OTHER_HASH
    )
    assert _first(verify()) == ("GENESIS_MISMATCH", 1)


def _delete(engine: Engine, sequence: int) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "DELETE FROM audit_payload_values WHERE record_id = "
                "(SELECT id FROM audit_records WHERE sequence = :s)"
            ),
            {"s": sequence},
        )
        connection.execute(text("DELETE FROM audit_records WHERE sequence = :s"), {"s": sequence})


def test_deleted_middle_record_is_a_sequence_gap(
    verify: Verify, seed: Seed, owner_engine: Engine
) -> None:
    seed(4)
    _delete(owner_engine, 2)

    report = verify()

    assert _first(report) == ("SEQUENCE_GAP", 3)
    assert report["recordsChecked"] == 3


def _shift(connection: Connection, from_sequence: int, offset: int) -> None:
    # Two steps, so UNIQUE(sequence) holds after each statement.
    connection.execute(
        text("UPDATE audit_records SET sequence = sequence + 1000000 WHERE sequence >= :s"),
        {"s": from_sequence},
    )
    connection.execute(
        text(
            "UPDATE audit_records SET sequence = sequence - 1000000 + :o WHERE sequence >= 1000000"
        ),
        {"o": offset},
    )


def test_forged_insertion_is_detected(
    verify: Verify, seed: Seed, owner_engine: Engine, insert_sealed: Any
) -> None:
    records = seed(3)
    forged_content = dataclasses.replace(
        records[1].content, id=str(uuid.uuid4()), actor_id="forged", payload={}
    )
    forged = seal_record(forged_content, 2, "f" * 64)
    with owner_engine.begin() as connection:
        _shift(connection, 2, 1)
        insert_sealed(connection, forged)

    report = verify()

    assert _first(report) == ("PREVIOUS_HASH_MISMATCH", 2)
    assert report["recordsChecked"] == 4
    assert report["intact"] is False


def test_reordering_is_detected(verify: Verify, seed: Seed, owner_engine: Engine) -> None:
    seed(4)
    with owner_engine.begin() as connection:
        connection.execute(text("UPDATE audit_records SET sequence = 1000002 WHERE sequence = 2"))
        connection.execute(text("UPDATE audit_records SET sequence = 2 WHERE sequence = 3"))
        connection.execute(text("UPDATE audit_records SET sequence = 3 WHERE sequence = 1000002"))

    report = verify()

    assert _first(report) == ("PREVIOUS_HASH_MISMATCH", 2)
    assert report["violationCount"] >= 2


def test_recorded_at_regression_is_detected(
    verify: Verify, seed: Seed, owner_engine: Engine, insert_sealed: Any
) -> None:
    records = seed(2)
    earlier = dataclasses.replace(
        records[1].content, id=str(uuid.uuid4()), recorded_at="2000-01-01T00:00:00.000000Z"
    )
    with owner_engine.begin() as connection:
        insert_sealed(connection, seal_record(earlier, 3, records[1].record_hash))

    report = verify()

    assert _first(report) == ("RECORDED_AT_REGRESSION", 3)
    assert report["violationCount"] == 1


def test_verification_continues_after_the_first_violation(
    verify: Verify, seed: Seed, owner_engine: Engine
) -> None:
    seed(5)
    _tamper(owner_engine, "UPDATE audit_records SET actor_id = 'x' WHERE sequence IN (2, 4)")

    report = verify()

    assert _first(report) == ("CONTENT_HASH_MISMATCH", 2)
    assert report["violationCount"] == 2
    assert report["recordsChecked"] == 5


@pytest.fixture
def fresh_owner_engine(
    create_database: Callable[[], URL], run_migrations: Callable[[Engine], None]
) -> Iterator[Engine]:
    engine = create_engine(create_database(), poolclass=pool.NullPool)
    run_migrations(engine)
    yield engine
    engine.dispose()


def test_duplicate_sequence_is_detected(
    fresh_owner_engine: Engine, new_event: Callable[..., NewEvent], insert_sealed: Any
) -> None:
    # Only possible once the tamper actor drops UNIQUE(sequence); done in a throwaway database.
    with fresh_owner_engine.begin() as connection:
        records = [append_event(connection, new_event()) for _ in range(3)]
        connection.execute(
            text("ALTER TABLE audit_records DROP CONSTRAINT uq_audit_records_sequence")
        )
        duplicate = dataclasses.replace(
            records[1],
            previous_hash="d" * 64,
            content=dataclasses.replace(
                records[1].content, id="ffffffff-ffff-4fff-bfff-ffffffffffff"
            ),
        )
        insert_sealed(connection, duplicate)

    result = verify_audit_chain(fresh_owner_engine).result

    assert result.first_violation is not None
    assert (result.first_violation.type, result.first_violation.sequence) == (
        ViolationType.SEQUENCE_DUPLICATE,
        2,
    )
    assert result.first_violation.record_id == "ffffffff-ffff-4fff-bfff-ffffffffffff"


# --- Documented limitations until later phases --------------------------------------------------


def test_tail_truncation_is_not_detected_before_checkpoints(
    verify: Verify, seed: Seed, owner_engine: Engine
) -> None:
    seed(3)
    _delete(owner_engine, 3)
    assert verify()["intact"] is True


def test_deleted_payload_value_is_not_detected_before_redaction(
    verify: Verify, seed: Seed, owner_engine: Engine
) -> None:
    records = seed(2)
    _tamper(
        owner_engine,
        "DELETE FROM audit_payload_values WHERE record_id = :id",
        id=uuid.UUID(records[0].content.id),
    )
    assert verify()["intact"] is True


def test_consistent_full_rewrite_is_not_detected_before_checkpoints(
    verify: Verify, seed: Seed, owner_engine: Engine
) -> None:
    records = seed(3)
    previous_hash = records[0].record_hash
    with owner_engine.begin() as connection:
        for record in records[1:]:
            content = dataclasses.replace(record.content, actor_id="rewritten")
            forged = seal_record(content, record.sequence, previous_hash)
            connection.execute(
                text(
                    "UPDATE audit_records SET actor_id = :actor, previous_hash = :previous, "
                    "content_hash = :content, record_hash = :record WHERE sequence = :sequence"
                ),
                {
                    "actor": "rewritten",
                    "previous": forged.previous_hash,
                    "content": forged.content_hash,
                    "record": forged.record_hash,
                    "sequence": record.sequence,
                },
            )
            previous_hash = forged.record_hash
    assert verify()["intact"] is True


# --- Disclosure and availability -----------------------------------------------------------------


def test_broken_chain_report_discloses_no_protected_fields(
    client: httpx.Client, auditor: Headers, seed: Seed, owner_engine: Engine
) -> None:
    seed(
        2,
        actor_id="sensitive-actor",
        resource_id="sensitive-resource",
        payload={"sensitive-key": "sensitive-value"},
    )
    _tamper(owner_engine, "UPDATE audit_records SET actor_id = 'forged-actor' WHERE sequence = 1")

    response = client.get("/audit/verify", headers=auditor)

    assert response.json()["intact"] is False
    for protected in (
        "sensitive-actor",
        "forged-actor",
        "sensitive-resource",
        "sensitive-key",
        "sensitive-value",
        "svc-writer",
    ):
        assert protected not in response.text


def _nested_json(depth: int) -> str:
    return '{"n":' * depth + '{"leaf":"x"}' + "}" * depth


@pytest.mark.parametrize("depth", [900, 5000], ids=["walk-too-deep", "decode-too-deep"])
def test_deeply_nested_tampered_payload_is_reported_not_a_500(
    client: httpx.Client, auditor: Headers, seed: Seed, owner_engine: Engine, depth: int
) -> None:
    # 900 levels decode but are too deep for the verifier to walk; 5000 are too deep to decode.
    records = seed(
        5,
        actor_id="sensitive-actor",
        resource_id="sensitive-resource",
        payload={"sensitive-key": "sensitive-value"},
    )
    _tamper(
        owner_engine,
        "UPDATE audit_records SET committed_payload = CAST(:doc AS jsonb) WHERE sequence = 2",
        doc=_nested_json(depth),
    )
    _tamper(owner_engine, "UPDATE audit_records SET event_type = 'CHANGED' WHERE sequence = 4")

    response = client.get("/audit/verify", headers=auditor)

    assert response.status_code == 200
    report = response.json()
    assert report["firstViolation"] == {
        "type": "CONTENT_HASH_MISMATCH",
        "sequence": 2,
        "recordId": records[1].content.id,
        "message": VIOLATION_MESSAGES[ViolationType.CONTENT_HASH_MISMATCH],
    }
    assert report["violationCount"] == 2
    assert report["recordsChecked"] == 5
    for protected in (
        "sensitive-actor",
        "sensitive-resource",
        "sensitive-key",
        "sensitive-value",
        "svc-writer",
        '"n"',
        "leaf",
    ):
        assert protected not in response.text
