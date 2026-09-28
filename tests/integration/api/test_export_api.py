"""POST /audit/exports against PostgreSQL (FR-7, Phase 11 decisions E1 to E17).

Every successful bundle is verified with the offline verification code, using only the export
public key. Tampering is done with the owner engine, outside the application path.
"""

import dataclasses
import io
import json
import logging
import threading
import uuid
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Connection, Engine, insert, text
from sqlalchemy.exc import OperationalError

from audit_log_service.api.app import CHECKPOINT_STORE_ERROR_DETAIL, create_app
from audit_log_service.api.exports import (
    SIGNING_UNAVAILABLE_DETAIL,
    TOO_LARGE_DETAIL,
    VERIFICATION_FAILED_DETAIL,
)
from audit_log_service.application import exports as exports_module
from audit_log_service.application.checkpoints import create_checkpoint
from audit_log_service.application.exports import SCOPE_ERROR
from audit_log_service.application.retention import (
    RetentionIncompleteError,
    RetentionPolicy,
    run_retention,
)
from audit_log_service.config.settings import Settings
from audit_log_service.integrity.canonical import JsonValue
from audit_log_service.integrity.checkpoints import key_id
from audit_log_service.integrity.commitments import commit_payload
from audit_log_service.integrity.exports import ExportVerification, verify_export
from audit_log_service.integrity.hashing import GENESIS_PREVIOUS_HASH, EventContent, seal_record
from audit_log_service.integrity.timestamps import (
    format_timestamp,
    is_canonical_timestamp,
    parse_timestamp,
)
from audit_log_service.integrity.verification import ChainEntry
from audit_log_service.offline import verify as offline
from audit_log_service.persistence.audit_log import (
    acquire_append_lock,
    load_chain_entries,
)
from audit_log_service.persistence.checkpoint_store import checkpoint_file_name
from audit_log_service.persistence.schema import audit_payload_values, audit_records

Headers = dict[str, str]
PostEvent = Callable[..., httpx.Response]
OLD = datetime(2020, 1, 1, tzinfo=UTC)
PAYLOAD: dict[str, JsonValue] = {"card": "test-only-4111", "email": "person@example.test"}


# --- Helpers ------------------------------------------------------------------------------------


@pytest.fixture
def export(client: httpx.Client, auditor: Headers) -> Callable[..., httpx.Response]:
    def post(body: object, headers: Headers | None = None) -> httpx.Response:
        return client.post(
            "/audit/exports", json=body, headers=auditor if headers is None else headers
        )

    return post


Export = Callable[..., httpx.Response]


@pytest.fixture
def verified(export_key: Ed25519PrivateKey) -> Callable[[httpx.Response], dict[str, Any]]:
    """Check a 200 response and verify its bundle offline; return the decoded bundle."""

    def check(response: httpx.Response) -> dict[str, Any]:
        assert response.status_code == 200, response.text
        result = verify_export(response.content, export_key.public_key())
        assert result.valid, result.first_violation
        bundle: dict[str, Any] = json.loads(response.content)
        return bundle

    return check


Verified = Callable[[httpx.Response], dict[str, Any]]


def events(engine: Engine) -> list[dict[str, Any]]:
    with engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT sequence, event_type, actor_id, resource_type, resource_id, recorded_by "
                "FROM audit_records ORDER BY sequence"
            )
        ).mappings()
        return [dict(row) for row in rows]


def export_events(engine: Engine) -> list[dict[str, Any]]:
    return [row for row in events(engine) if row["event_type"] == "AUDIT_LOG_EXPORT"]


def stored_payload(engine: Engine, sequence: int) -> dict[str, Any]:
    with engine.connect() as connection:
        entries = load_chain_entries(connection)
    entry = entries[sequence - 1]
    return {
        pointer: json.loads(value.canonical_text) for pointer, value in entry.payload_values.items()
    }


def insert_old(owner_engine: Engine, actor: str, count: int) -> None:
    """Append sealed records with an old recordedAt, which a 30-day retention window archives."""
    for _ in range(count):
        with owner_engine.begin() as connection:
            chain = load_chain_entries(connection)
            sequence = len(chain) + 1
            previous = chain[-1].record.record_hash if chain else GENESIS_PREVIOUS_HASH
            committed = commit_payload(PAYLOAD)
            content = EventContent(
                id=str(uuid.uuid4()),
                event_type="ORDER_PLACED",
                actor_id=actor,
                resource_type="ORDER",
                resource_id="order-1",
                timestamp=None,
                recorded_at=format_timestamp(OLD + timedelta(seconds=sequence)),
                recorded_by="svc-writer",
                payload=committed.structure,
            )
            record = seal_record(content, sequence, previous)
            connection.execute(
                insert(audit_records).values(
                    id=uuid.UUID(content.id),
                    sequence=sequence,
                    previous_hash=record.previous_hash,
                    content_hash=record.content_hash,
                    record_hash=record.record_hash,
                    event_type=content.event_type,
                    actor_id=actor,
                    resource_type="ORDER",
                    resource_id="order-1",
                    timestamp=None,
                    recorded_at=parse_timestamp(content.recorded_at),
                    recorded_by="svc-writer",
                    committed_payload=content.payload,
                )
            )
            connection.execute(
                insert(audit_payload_values),
                [
                    {
                        "record_id": uuid.UUID(content.id),
                        "pointer": pointer,
                        "canonical_value": value.canonical_text,
                        "salt": value.salt,
                    }
                    for pointer, value in committed.values.items()
                ],
            )


def _problem(response: httpx.Response, status: int, detail: str) -> dict[str, Any]:
    assert response.status_code == status, response.text
    assert response.headers["content-type"] == "application/problem+json"
    body: dict[str, Any] = response.json()
    assert body["detail"] == detail
    assert body["requestId"] == response.headers["x-request-id"]
    return body


def _truncate_after(owner_engine: Engine, sequence: int) -> None:
    with owner_engine.begin() as connection:
        connection.execute(
            text(
                "DELETE FROM audit_payload_values WHERE record_id IN "
                "(SELECT id FROM audit_records WHERE sequence > :s)"
            ),
            {"s": sequence},
        )
        connection.execute(text("DELETE FROM audit_records WHERE sequence > :s"), {"s": sequence})


@pytest.fixture
def client_with(
    settings: Settings, app_engine: Engine, make_client: Callable[[Any], httpx.Client]
) -> Iterator[Callable[..., httpx.Client]]:
    clients: list[httpx.Client] = []

    def build(**changes: Any) -> httpx.Client:
        client = make_client(create_app(dataclasses.replace(settings, **changes), app_engine))
        client.__enter__()
        clients.append(client)
        return client

    yield build
    for client in clients:
        client.__exit__(None, None, None)


# --- Authentication, authorization, and check order ---------------------------------------------


def test_missing_credentials_are_401_before_body_validation(client: httpx.Client) -> None:
    response = client.post("/audit/exports", content=b"not json")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("role", ["writer", "administrator"])
def test_principals_without_export_create_are_403_before_validation(
    client: httpx.Client, fake_keys: Mapping[str, str], role: str
) -> None:
    response = client.post(
        "/audit/exports",
        json={"nope": 1},
        headers={"Authorization": f"Bearer {fake_keys[role]}"},
    )
    assert response.status_code == 403


@pytest.mark.parametrize("role", ["auditor", "regulator"])
def test_auditors_and_regulators_can_export(
    export: Export,
    verified: Verified,
    fake_keys: Mapping[str, str],
    post_event: PostEvent,
    role: str,
) -> None:
    post_event()
    bundle = verified(
        export({"actorId": "user-7"}, headers={"Authorization": f"Bearer {fake_keys[role]}"})
    )
    assert (
        bundle["manifest"]["requestedBy"]
        == {"auditor": "auditor-1", "regulator": "regulator-1"}[role]
    )


def test_body_is_validated_before_the_signing_key_is_checked(
    client_with: Callable[..., httpx.Client], auditor: Headers, app_engine: Engine
) -> None:
    client = client_with(export_signing_key=None)

    invalid = client.post(
        "/audit/exports", json={"actorId": "a", "resourceType": "X"}, headers=auditor
    )
    missing_key = client.post("/audit/exports", json={"actorId": "a"}, headers=auditor)

    _problem(invalid, 422, SCOPE_ERROR)
    _problem(missing_key, 503, SIGNING_UNAVAILABLE_DETAIL)
    assert events(app_engine) == []


def test_database_and_store_are_not_touched_without_a_signing_key(
    client_with: Callable[..., httpx.Client], auditor: Headers, checkpoint_store: Path
) -> None:
    checkpoint_store.rmdir()  # an unreadable store would be a 500 if it were read
    client = client_with(export_signing_key=None)
    _problem(
        client.post("/audit/exports", json={"actorId": "a"}, headers=auditor),
        503,
        SIGNING_UNAVAILABLE_DETAIL,
    )


# --- Request validation -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"resourceType": "ORDER"},
        {"actorId": "user-7", "resourceType": "ORDER"},
        {"actorId": "user-7", "resourceId": "order-1"},
        {"actorId": "user-7", "resourceId": "order-1", "resourceType": "ORDER"},
    ],
    ids=["empty", "type-only", "actor-and-type", "actor-and-resource", "all"],
)
def test_invalid_scope_combinations_are_422(
    export: Export, body: dict[str, str], app_engine: Engine
) -> None:
    _problem(export(body), 422, SCOPE_ERROR)
    assert events(app_engine) == []


@pytest.mark.parametrize(
    ("content", "content_type", "status"),
    [
        (b"not json", "application/json", 400),
        (b'{"actorId": "a", "actorId": "b"}', "application/json", 422),
        (b'{"actorId": "a"}', "text/plain", 415),
        (b'{"actorId": "' + b"a" * 70_000 + b'"}', "application/json", 413),
        (b'{"actorId": "a", "limit": 1}', "application/json", 422),
        (b'{"actorId": ""}', "application/json", 422),
        (b'{"resourceId": "r", "resourceType": "order"}', "application/json", 422),
    ],
    ids=[
        "malformed",
        "duplicate-key",
        "content-type",
        "too-large",
        "unknown-field",
        "empty-id",
        "type-pattern",
    ],
)
def test_body_errors(
    client: httpx.Client, auditor: Headers, content: bytes, content_type: str, status: int
) -> None:
    response = client.post(
        "/audit/exports", content=content, headers={**auditor, "Content-Type": content_type}
    )
    assert response.status_code == status
    assert response.headers["content-type"] == "application/problem+json"


# --- Successful exports -------------------------------------------------------------------------


def test_each_scope_exports_exactly_the_matching_records(
    export: Export, verified: Verified, post_event: PostEvent
) -> None:
    post_event(actorId="user-7", resourceType="ORDER", resourceId="order-1")
    post_event(actorId="user-8", resourceType="INVOICE", resourceId="order-1")
    post_event(actorId="user-7", resourceType="ORDER", resourceId="order-2")

    by_actor = verified(export({"actorId": "user-7"}))
    by_resource = verified(export({"resourceId": "order-1"}))
    by_resource_and_type = verified(export({"resourceId": "order-1", "resourceType": "INVOICE"}))

    assert [r["sequence"] for r in by_actor["records"]] == [1, 3]
    # Each export event is appended after its own snapshot, so later exports see earlier ones.
    assert [r["sequence"] for r in by_resource["records"]] == [1, 2]
    assert [r["sequence"] for r in by_resource_and_type["records"]] == [2]
    assert by_actor["manifest"]["scope"] == {"actorId": "user-7"}
    assert by_resource_and_type["manifest"]["scope"] == {
        "resourceId": "order-1",
        "resourceType": "INVOICE",
    }


def test_bundle_is_the_exact_canonical_signed_bytes(
    export: Export, verified: Verified, post_event: PostEvent, export_key: Ed25519PrivateKey
) -> None:
    post_event()
    response = export({"actorId": "user-7"})
    bundle = verified(response)

    assert rfc8785.dumps(bundle) == response.content
    assert response.headers["content-type"] == "application/json"
    assert response.headers["cache-control"] == "no-store"
    manifest = bundle["manifest"]
    assert manifest["format"] == "audit-log-export/v1"
    assert manifest["scheme"] == "audit-log/v1"
    assert manifest["keyId"] == key_id(export_key.public_key())
    assert manifest["requestedBy"] == "auditor-1"
    assert is_canonical_timestamp(manifest["generatedAt"])
    assert (manifest["asOfSequence"], manifest["recordCount"]) == (1, 1)
    record = bundle["records"][0]
    assert record["payloadValues"]["/amount"]["value"] == 12.5
    assert set(record["payloadValues"]["/amount"]) == {"value", "salt"}


def test_empty_result_is_a_signed_manifest_with_no_records(
    export: Export, verified: Verified, post_event: PostEvent, app_engine: Engine
) -> None:
    post_event()
    bundle = verified(export({"actorId": "nobody"}))
    assert (bundle["manifest"]["recordCount"], bundle["records"]) == (0, [])
    assert bundle["manifest"]["asOfSequence"] == 1
    assert len(export_events(app_engine)) == 1


def test_empty_chain_export(export: Export, verified: Verified, app_engine: Engine) -> None:
    bundle = verified(export({"actorId": "user-7"}))
    assert (bundle["manifest"]["asOfSequence"], bundle["manifest"]["asOfRecordHash"]) == (0, None)
    assert [e["sequence"] for e in export_events(app_engine)] == [1]


# --- The export audit event (E9) ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("scope", "identity"),
    [
        ({"actorId": "user-7"}, ("user-7", "AUDIT_LOG", "audit-log")),
        (
            {"resourceId": "acct-42", "resourceType": "CLIENT_ACCOUNT"},
            ("audit-log-service", "CLIENT_ACCOUNT", "acct-42"),
        ),
        ({"resourceId": "acct-42"}, ("audit-log-service", "AUDIT_LOG", "acct-42")),
    ],
    ids=["actor", "resource-and-type", "resource"],
)
def test_export_event_identity_and_payload(
    export: Export,
    verified: Verified,
    post_event: PostEvent,
    app_engine: Engine,
    scope: dict[str, str],
    identity: tuple[str, str, str],
) -> None:
    post_event()
    post_event()
    bundle = verified(export(scope))

    [event] = export_events(app_engine)
    assert (event["actor_id"], event["resource_type"], event["resource_id"]) == identity
    assert event["recorded_by"] == "auditor-1"
    assert event["sequence"] == bundle["manifest"]["asOfSequence"] + 1 == 3
    assert stored_payload(app_engine, event["sequence"]) == {
        **{f"/scope/{name}": value for name, value in scope.items()},
        "/asOfSequence": 2,
        "/recordCount": bundle["manifest"]["recordCount"],
        "/keyId": bundle["manifest"]["keyId"],
        "/manifestSignature": bundle["signature"],
    }
    assert all(r["sequence"] <= 2 for r in bundle["records"])


def test_export_event_never_contains_payload_values_or_salts(
    export: Export, post_event: PostEvent, app_engine: Engine
) -> None:
    post_event(payload={"card": "test-only-4111"})
    response = export({"actorId": "user-7"})
    salts = [v["salt"] for r in response.json()["records"] for v in r["payloadValues"].values()]

    stored = json.dumps(stored_payload(app_engine, export_events(app_engine)[0]["sequence"]))

    assert "test-only-4111" not in stored
    assert salts and not any(salt in stored for salt in salts)


def test_export_event_is_in_later_exports_of_the_same_scope_but_not_its_own(
    export: Export, verified: Verified, post_event: PostEvent
) -> None:
    post_event()
    first = verified(export({"actorId": "user-7"}))
    second = verified(export({"actorId": "user-7"}))

    assert [r["eventType"] for r in first["records"]] == ["ORDER_PLACED"]
    assert [r["eventType"] for r in second["records"]] == ["ORDER_PLACED", "AUDIT_LOG_EXPORT"]
    assert second["records"][1]["sequence"] == first["manifest"]["asOfSequence"] + 1


def test_client_account_scope_needs_no_access_vocabulary(
    export: Export, verified: Verified, app_engine: Engine
) -> None:
    # System events are exempt from Scenario C validation (FR-8).
    verified(export({"resourceId": "acct-42", "resourceType": "CLIENT_ACCOUNT"}))
    assert export_events(app_engine)[0]["resource_type"] == "CLIENT_ACCOUNT"


# --- Redaction and retention --------------------------------------------------------------------


def test_redacted_values_are_absent_and_authorized_by_the_included_redaction_event(
    client: httpx.Client,
    export: Export,
    verified: Verified,
    post_event: PostEvent,
    administrator: Headers,
) -> None:
    target = post_event().json()
    redaction = client.post(
        f"/audit/events/{target['id']}/redactions",
        json={"paths": ["/amount"], "reason": "test-only reason"},
        headers=administrator,
    )
    assert redaction.status_code == 201

    bundle = verified(export({"actorId": "user-7"}))

    record, event = bundle["records"]
    assert "/amount" not in record["payloadValues"]
    assert record["redactedPaths"] == ["/amount"]
    # The redacted value keeps its commitment, so the record still verifies (E3).
    assert len(record["committedPayload"]["amount"]) == 64
    assert event["eventType"] == "AUDIT_LOG_REDACTION"
    assert bundle["manifest"]["retention"] is None


def test_archived_records_are_exported_without_values_with_signed_retention_evidence(
    export: Export, verified: Verified, owner_engine: Engine, app_engine: Engine
) -> None:
    insert_old(owner_engine, "old-actor", 3)
    run_retention(app_engine, RetentionPolicy(timedelta(days=30), 500, 20), "ops.admin")

    bundle = verified(export({"actorId": "old-actor"}))

    retention_event = events(app_engine)[3]
    assert retention_event["event_type"] == "AUDIT_LOG_RETENTION"
    evidence = bundle["manifest"]["retention"]
    assert (evidence["upToSequence"], evidence["eventSequence"]) == (3, 4)
    with app_engine.connect() as connection:
        entry = load_chain_entries(connection)[3]
    assert (evidence["eventId"], evidence["eventRecordHash"]) == (
        entry.record.content.id,
        entry.record.record_hash,
    )
    assert [r["archived"] for r in bundle["records"]] == [True, True, True]
    assert all(r["payloadValues"] == {} for r in bundle["records"])


def test_archived_records_have_no_values_even_mid_purge(
    export: Export, verified: Verified, owner_engine: Engine, app_engine: Engine
) -> None:
    insert_old(owner_engine, "old-actor", 3)
    with pytest.raises(RetentionIncompleteError):
        run_retention(app_engine, RetentionPolicy(timedelta(days=30), 1, 1), "ops.admin")

    bundle = verified(export({"actorId": "old-actor"}))

    assert all(r["archived"] and r["payloadValues"] == {} for r in bundle["records"])
    with app_engine.connect() as connection:
        still_stored = connection.execute(
            text("SELECT count(*) FROM audit_payload_values")
        ).scalar_one()
    assert still_stored > 0


# --- Pre-signing verification and checkpoints ---------------------------------------------------


def test_tampered_chain_is_409_and_nothing_is_signed_or_appended(
    export: Export, post_event: PostEvent, owner_engine: Engine, app_engine: Engine
) -> None:
    post_event()
    post_event(actorId="user-8")
    with owner_engine.begin() as connection:
        connection.execute(
            text("UPDATE audit_records SET recorded_by = 'forged' WHERE sequence = 2")
        )

    body = _problem(export({"actorId": "user-7"}), 409, VERIFICATION_FAILED_DETAIL)

    assert set(body) == {"type", "title", "status", "detail", "requestId"}
    assert len(events(app_engine)) == 2


@pytest.mark.parametrize("tamper", ["deleted-middle", "reordered", "deleted-value"])
def test_other_tampering_is_409(
    export: Export, post_event: PostEvent, owner_engine: Engine, app_engine: Engine, tamper: str
) -> None:
    for _ in range(3):
        post_event()
    with owner_engine.begin() as connection:
        if tamper == "deleted-middle":
            connection.execute(
                text(
                    "DELETE FROM audit_payload_values WHERE record_id = "
                    "(SELECT id FROM audit_records WHERE sequence = 2)"
                )
            )
            connection.execute(text("DELETE FROM audit_records WHERE sequence = 2"))
        elif tamper == "reordered":
            connection.execute(
                text("UPDATE audit_records SET sequence = sequence + 10 WHERE sequence IN (2, 3)")
            )
            connection.execute(
                text(
                    "UPDATE audit_records SET sequence = 5 - (sequence - 10) "
                    "WHERE sequence IN (12, 13)"
                )
            )
        else:
            connection.execute(
                text(
                    "DELETE FROM audit_payload_values WHERE record_id = "
                    "(SELECT id FROM audit_records WHERE sequence = 1)"
                )
            )
    _problem(export({"actorId": "user-7"}), 409, VERIFICATION_FAILED_DETAIL)
    assert export_events(app_engine) == []


@pytest.mark.parametrize("tamper", ["truncation", "rewrite"])
def test_chain_failing_the_latest_checkpoint_is_409(
    export: Export,
    post_event: PostEvent,
    owner_engine: Engine,
    app_engine: Engine,
    checkpoint_engine: Engine,
    checkpoint_store: Path,
    checkpoint_key: Ed25519PrivateKey,
    tamper: str,
) -> None:
    post_event()
    post_event()
    create_checkpoint(checkpoint_engine, checkpoint_store, checkpoint_key, "ops.admin")
    _truncate_after(owner_engine, 1)
    if tamper == "rewrite":
        post_event(actorId="forger")

    _problem(export({"actorId": "user-7"}), 409, VERIFICATION_FAILED_DETAIL)
    assert export_events(app_engine) == []


def test_invalid_checkpoint_store_is_500_and_nothing_is_appended(
    export: Export, post_event: PostEvent, checkpoint_store: Path, app_engine: Engine
) -> None:
    post_event()
    (checkpoint_store / checkpoint_file_name(1)).write_bytes(b"corrupt")
    _problem(export({"actorId": "user-7"}), 500, CHECKPOINT_STORE_ERROR_DETAIL)
    assert export_events(app_engine) == []


def test_bundle_and_checkpoints_verify_offline_with_the_cli(
    export: Export,
    post_event: PostEvent,
    checkpoint_engine: Engine,
    checkpoint_store: Path,
    checkpoint_key: Ed25519PrivateKey,
    checkpoint_public_key_file: Path,
    export_public_key_file: Path,
    tmp_path: Path,
) -> None:
    post_event()
    post_event(actorId="user-8")
    create_checkpoint(checkpoint_engine, checkpoint_store, checkpoint_key, "ops.admin")
    bundle_path = tmp_path / "export.json"
    bundle_path.write_bytes(export({"actorId": "user-7"}).content)
    post_event()
    create_checkpoint(checkpoint_engine, checkpoint_store, checkpoint_key, "ops.admin")

    stdout, stderr = io.StringIO(), io.StringIO()
    code = offline.run(
        [
            "export",
            "--public-key",
            str(export_public_key_file),
            str(bundle_path),
            "--checkpoint-public-key",
            str(checkpoint_public_key_file),
            "--checkpoint",
            str(checkpoint_store / checkpoint_file_name(2)),
            "--checkpoint",
            str(checkpoint_store / checkpoint_file_name(4)),
        ],
        stdout=stdout,
        stderr=stderr,
    )

    lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert (code, stderr.getvalue()) == (0, "")
    assert lines[0]["result"] == "VALID"
    assert [(line["result"], line["sequence"]) for line in lines[1:]] == [
        ("MATCH", 2),  # at asOfSequence
        ("NOT_APPLICABLE", 4),  # after the export; no signed evidence there
    ]


def test_tampered_bundle_fails_offline_verification(
    export: Export, post_event: PostEvent, export_key: Ed25519PrivateKey
) -> None:
    post_event()
    bundle = export({"actorId": "user-7"}).json()
    bundle["records"][0]["payloadValues"]["/amount"]["value"] = 13
    result: ExportVerification = verify_export(json.dumps(bundle).encode(), export_key.public_key())
    assert not result.valid
    assert result.first_violation is not None
    assert result.first_violation.type.value == "PAYLOAD_VALUE_MISMATCH"


# --- Size limits (E8) ---------------------------------------------------------------------------


def test_record_limit_is_checked_before_anything_is_signed(
    client_with: Callable[..., httpx.Client],
    auditor: Headers,
    post_event: PostEvent,
    app_engine: Engine,
    owner_engine: Engine,
) -> None:
    for _ in range(3):
        post_event()
    client = client_with(export_max_records=2)

    _problem(
        client.post("/audit/exports", json={"actorId": "user-7"}, headers=auditor),
        422,
        TOO_LARGE_DETAIL,
    )
    assert (
        client.post("/audit/exports", json={"actorId": "user-8"}, headers=auditor).status_code
        == 200
    )
    # The limit is checked before verification: a broken chain still reports the size first.
    with owner_engine.begin() as connection:
        connection.execute(
            text("UPDATE audit_records SET recorded_by = 'forged' WHERE sequence = 1")
        )
    _problem(
        client.post("/audit/exports", json={"actorId": "user-7"}, headers=auditor),
        422,
        TOO_LARGE_DETAIL,
    )
    assert len(export_events(app_engine)) == 1


def test_exactly_the_record_limit_is_allowed(
    client_with: Callable[..., httpx.Client], auditor: Headers, post_event: PostEvent
) -> None:
    post_event()
    post_event()
    client = client_with(export_max_records=2)
    response = client.post("/audit/exports", json={"actorId": "user-7"}, headers=auditor)
    assert response.status_code == 200


def test_byte_limit_is_checked_after_serialization_and_before_the_event(
    client_with: Callable[..., httpx.Client],
    auditor: Headers,
    post_event: PostEvent,
    app_engine: Engine,
) -> None:
    post_event()
    size = len(
        client_with().post("/audit/exports", json={"actorId": "user-7"}, headers=auditor).content
    )
    exact = client_with(export_max_bytes=size + 2000)
    tight = client_with(export_max_bytes=size - 1)

    _problem(
        tight.post("/audit/exports", json={"actorId": "user-7"}, headers=auditor),
        422,
        TOO_LARGE_DETAIL,
    )
    assert len(export_events(app_engine)) == 1
    assert (
        exact.post("/audit/exports", json={"actorId": "user-7"}, headers=auditor).status_code == 200
    )


# --- Export event append failures (503) ---------------------------------------------------------


def test_failed_event_append_returns_503_and_no_bundle(
    export: Export, post_event: PostEvent, app_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    post_event(payload={"card": "test-only-4111"})

    def fail(_connection: Connection, _event: Any) -> None:
        raise OperationalError("INSERT", {}, Exception("unavailable"))

    monkeypatch.setattr(exports_module, "append_event", fail)

    response = export({"actorId": "user-7"})

    _problem(response, 503, "The service is temporarily unavailable.")
    assert "test-only-4111" not in response.text
    assert "manifest" not in response.text
    assert export_events(app_engine) == []


def test_append_lock_timeout_returns_503_and_no_bundle(
    export: Export, post_event: PostEvent, app_engine: Engine
) -> None:
    post_event()
    holding = threading.Event()
    release = threading.Event()

    def hold_lock() -> None:
        with app_engine.begin() as connection:
            acquire_append_lock(connection)
            holding.set()
            release.wait(30)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    try:
        assert holding.wait(10)
        response = export({"actorId": "user-7"})
    finally:
        release.set()
        holder.join()

    _problem(response, 503, "The service is temporarily unavailable.")
    assert "manifest" not in response.text
    assert export_events(app_engine) == []


# --- Snapshot consistency -----------------------------------------------------------------------


def test_concurrent_append_and_redaction_do_not_change_the_snapshot(
    export: Export,
    verified: Verified,
    post_event: PostEvent,
    client: httpx.Client,
    administrator: Headers,
    writer: Headers,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = post_event().json()
    real_load = exports_module.load_chain_entries

    def load_during_concurrent_changes(connection: Connection) -> list[ChainEntry]:
        # Inside the export's snapshot, other sessions append and redact, and commit.
        assert (
            client.post(
                "/audit/events",
                json={
                    "eventType": "ORDER_PLACED",
                    "actorId": "user-7",
                    "resourceType": "ORDER",
                    "resourceId": "order-9",
                    "payload": {},
                },
                headers=writer,
            ).status_code
            == 201
        )
        assert (
            client.post(
                f"/audit/events/{target['id']}/redactions",
                json={"paths": ["/amount"], "reason": "r"},
                headers=administrator,
            ).status_code
            == 201
        )
        return real_load(connection)

    monkeypatch.setattr(exports_module, "load_chain_entries", load_during_concurrent_changes)

    bundle = verified(export({"actorId": "user-7"}))

    assert bundle["manifest"]["asOfSequence"] == 1
    assert [r["sequence"] for r in bundle["records"]] == [1]
    assert "/amount" in bundle["records"][0]["payloadValues"]  # redacted after the snapshot


def test_concurrent_retention_does_not_change_the_snapshot(
    export: Export,
    verified: Verified,
    owner_engine: Engine,
    app_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    insert_old(owner_engine, "old-actor", 2)
    real_load = exports_module.load_chain_entries

    def load_during_retention(connection: Connection) -> list[ChainEntry]:
        run_retention(app_engine, RetentionPolicy(timedelta(days=30), 500, 20), "ops.admin")
        return real_load(connection)

    monkeypatch.setattr(exports_module, "load_chain_entries", load_during_retention)

    bundle = verified(export({"actorId": "old-actor"}))

    assert bundle["manifest"]["retention"] is None
    assert all(not r["archived"] and r["payloadValues"] for r in bundle["records"])
    # The retention event (3) committed during the export; the export event follows it.
    assert [e["event_type"] for e in events(app_engine)][2:] == [
        "AUDIT_LOG_RETENTION",
        "AUDIT_LOG_EXPORT",
    ]


# --- Logging ------------------------------------------------------------------------------------


def test_logs_contain_no_scope_identifiers_values_salts_or_manifest(
    export: Export, post_event: PostEvent, caplog: pytest.LogCaptureFixture
) -> None:
    post_event(actorId="test-only-actor", payload={"card": "test-only-4111"})
    caplog.set_level(logging.DEBUG)

    response = export({"actorId": "test-only-actor"})

    bundle = response.json()
    salts = [v["salt"] for r in bundle["records"] for v in r["payloadValues"].values()]
    logged = caplog.text
    assert f"records={bundle['manifest']['recordCount']}" in logged
    assert response.headers["x-request-id"] in logged
    for secret in ["test-only-actor", "test-only-4111", bundle["signature"], *salts]:
        assert secret not in logged
