"""API tests for POST /audit/retention-runs (FR-5) against real PostgreSQL."""

import dataclasses
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, insert, text

from audit_log_service.api.app import create_app
from audit_log_service.application import retention as retention_module
from audit_log_service.config.settings import Settings
from audit_log_service.integrity.canonical import JsonValue
from audit_log_service.integrity.commitments import commit_payload
from audit_log_service.integrity.hashing import GENESIS_PREVIOUS_HASH, EventContent, seal_record
from audit_log_service.integrity.timestamps import format_timestamp, parse_timestamp
from audit_log_service.persistence.audit_log import load_chain_entries
from audit_log_service.persistence.retention import highest_eligible_sequence
from audit_log_service.persistence.schema import audit_payload_values, audit_records

Headers = dict[str, str]
OLD = datetime(2020, 1, 1, tzinfo=UTC)
PAYLOAD: dict[str, JsonValue] = {"card": "4111", "email": "person@example.test"}
MakeClient = Callable[..., httpx.Client]


# --- Helpers ------------------------------------------------------------------------------------


def append_sealed(
    owner_engine: Engine,
    payload: dict[str, JsonValue],
    recorded_at: datetime,
    event_type: str = "ORDER_PLACED",
) -> str:
    """Append one properly sealed record, with its payload values, at the chain head."""
    with owner_engine.begin() as connection:
        chain = load_chain_entries(connection)
        previous = chain[-1].record.record_hash if chain else GENESIS_PREVIOUS_HASH
        sequence = len(chain) + 1
        committed = commit_payload(payload)
        content = EventContent(
            id=str(uuid.uuid4()),
            event_type=event_type,
            actor_id="old-actor",
            resource_type="ORDER",
            resource_id=f"order-{sequence}",
            timestamp=None,
            recorded_at=format_timestamp(recorded_at),
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
                actor_id=content.actor_id,
                resource_type=content.resource_type,
                resource_id=content.resource_id,
                timestamp=None,
                recorded_at=parse_timestamp(content.recorded_at),
                recorded_by=content.recorded_by,
                committed_payload=content.payload,
            )
        )
        if committed.values:
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
    return content.id


def seed_old(owner_engine: Engine, count: int, payload: dict[str, JsonValue] | None = None) -> None:
    """Append records with old recordedAt values, which a 30-day window makes eligible."""
    for offset in range(count):
        append_sealed(
            owner_engine,
            PAYLOAD if payload is None else payload,
            OLD + timedelta(seconds=offset + 1),
        )


def count(engine: Engine, sql: str, **parameters: Any) -> int:
    with engine.connect() as connection:
        result: int = connection.execute(text(sql), parameters).scalar_one()
    return result


def retention_events(engine: Engine) -> int:
    return count(
        engine, "SELECT count(*) FROM audit_records WHERE event_type = 'AUDIT_LOG_RETENTION'"
    )


def values_at_or_below(engine: Engine, sequence: int) -> int:
    return count(
        engine,
        "SELECT count(*) FROM audit_payload_values v JOIN audit_records r ON r.id = v.record_id "
        "WHERE r.sequence <= :s",
        s=sequence,
    )


def record_ids(engine: Engine) -> list[str]:
    with engine.connect() as connection:
        rows = connection.execute(text("SELECT id FROM audit_records ORDER BY sequence")).all()
    return [str(row[0]) for row in rows]


def stored_pointers(engine: Engine, record_id: str) -> list[str]:
    with engine.connect() as connection:
        rows = connection.execute(
            text("SELECT pointer FROM audit_payload_values WHERE record_id = :id ORDER BY pointer"),
            {"id": uuid.UUID(record_id)},
        ).all()
    return [row[0] for row in rows]


def chain_state(engine: Engine) -> list[tuple[Any, ...]]:
    with engine.connect() as connection:
        return [
            tuple(row)
            for row in connection.execute(
                text(
                    "SELECT sequence, id, previous_hash, content_hash, record_hash, actor_id, "
                    "recorded_at, committed_payload::text FROM audit_records ORDER BY sequence"
                )
            ).all()
        ]


@pytest.fixture
def retention_client(
    settings: Settings, app_engine: Engine, make_client: Callable[[Any], httpx.Client]
) -> Iterator[MakeClient]:
    """A client whose app has the given retention settings (window in seconds)."""
    with ExitStack() as stack:

        def build(
            window: int | None = 30 * 24 * 3600, batch_size: int = 500, max_batches: int = 20
        ) -> httpx.Client:
            configured = dataclasses.replace(
                settings,
                retention_window=None if window is None else timedelta(seconds=window),
                retention_batch_size=batch_size,
                retention_max_batches=max_batches,
            )
            return stack.enter_context(make_client(create_app(configured, app_engine)))

        yield build


def run(client: httpx.Client, administrator: Headers, **kwargs: Any) -> httpx.Response:
    return client.post("/audit/retention-runs", headers=administrator, **kwargs)


def _assert_problem(response: httpx.Response, status: int) -> dict[str, Any]:
    assert response.status_code == status, response.text
    assert response.headers["content-type"] == "application/problem+json"
    body: dict[str, Any] = response.json()
    assert body["requestId"] == response.headers["x-request-id"]
    return body


def verify(client: httpx.Client, auditor: Headers) -> dict[str, Any]:
    body: dict[str, Any] = client.get("/audit/verify", headers=auditor).json()
    return body


# --- Configuration, access, and request validation ----------------------------------------------


def test_disabled_retention_is_422(retention_client: MakeClient, administrator: Headers) -> None:
    response = run(retention_client(window=None), administrator)
    assert _assert_problem(response, 422)["detail"] == "Retention is not configured."


def test_unauthenticated_run_is_401_before_validation(retention_client: MakeClient) -> None:
    response = retention_client().post("/audit/retention-runs", params={"x": "1"}, content=b"{}")
    _assert_problem(response, 401)


@pytest.mark.parametrize("principal", ["writer", "auditor", "regulator"])
def test_only_retention_run_capability_may_run(
    retention_client: MakeClient, fake_keys: Any, principal: str
) -> None:
    headers = {"Authorization": f"Bearer {fake_keys[principal]}"}
    response = retention_client().post("/audit/retention-runs", params={"x": "1"}, headers=headers)
    _assert_problem(response, 403)


def test_query_parameters_are_rejected(
    retention_client: MakeClient, administrator: Headers
) -> None:
    response = run(retention_client(), administrator, params={"upToSequence": "5"})
    assert (
        _assert_problem(response, 422)["detail"] == "The retention run accepts no query parameters."
    )


@pytest.mark.parametrize(
    "body", [b"{}", b'{"window": 1}', b" "], ids=["empty-object", "field", "space"]
)
def test_request_bodies_are_rejected(
    retention_client: MakeClient, administrator: Headers, body: bytes
) -> None:
    response = retention_client().post(
        "/audit/retention-runs",
        content=body,
        headers={**administrator, "Content-Type": "application/json"},
    )
    assert _assert_problem(response, 422)["detail"] == "The retention run accepts no request body."


# --- Outcomes -----------------------------------------------------------------------------------


def test_nothing_eligible_on_an_empty_chain(
    retention_client: MakeClient, administrator: Headers
) -> None:
    response = run(retention_client(), administrator)

    assert response.status_code == 200
    assert response.json() == {
        "outcome": "NOTHING_ELIGIBLE",
        "upToSequence": None,
        "retentionEvent": None,
        "purgedValues": 0,
    }


def test_recent_records_are_not_eligible(
    retention_client: MakeClient, administrator: Headers, post_event: Any, app_engine: Engine
) -> None:
    post_event()
    assert run(retention_client(), administrator).json()["outcome"] == "NOTHING_ELIGIBLE"
    assert retention_events(app_engine) == 0


def test_new_boundary_records_an_event_and_purges(
    retention_client: MakeClient,
    administrator: Headers,
    auditor: Headers,
    owner_engine: Engine,
    app_engine: Engine,
    post_event: Any,
) -> None:
    seed_old(owner_engine, 3)
    recent = post_event().json()
    before = chain_state(app_engine)
    client = retention_client()

    response = run(client, administrator)

    assert response.status_code == 201
    body = response.json()
    event = body["retentionEvent"]
    assert response.headers["location"] == f"/audit/events/{event['id']}"
    assert (body["outcome"], body["upToSequence"], body["purgedValues"]) == (
        "RETENTION_RECORDED",
        3,
        6,
    )
    assert event["eventType"] == "AUDIT_LOG_RETENTION"
    assert (event["actorId"], event["resourceType"], event["resourceId"]) == (
        "audit-log-service",
        "AUDIT_LOG",
        "audit-log",
    )
    assert (event["recordedBy"], event["timestamp"], event["sequence"]) == ("ops.admin", None, 5)
    assert event["payload"]["upToSequence"] == 3
    # cutoff = database clock - window, read before the event was appended.
    cutoff = parse_timestamp(event["payload"]["cutoff"])
    assert parse_timestamp(event["recordedAt"]) - cutoff >= timedelta(days=30)
    assert event["archived"] is False
    assert values_at_or_below(app_engine, 3) == 0
    assert (
        client.get(f"/audit/events/{recent['id']}", headers=auditor).json()["payload"]
        == recent["payload"]
    )
    assert chain_state(app_engine)[:4] == before
    assert verify(client, auditor)["intact"] is True


def test_repeated_run_creates_no_duplicate_event(
    retention_client: MakeClient, administrator: Headers, owner_engine: Engine, app_engine: Engine
) -> None:
    seed_old(owner_engine, 2)
    client = retention_client()
    run(client, administrator)

    again = run(client, administrator)

    assert again.status_code == 200
    assert again.json() == {
        "outcome": "NOTHING_ELIGIBLE",
        "upToSequence": 2,
        "retentionEvent": None,
        "purgedValues": 0,
    }
    assert retention_events(app_engine) == 1


def test_boundary_never_moves_back(
    retention_client: MakeClient, administrator: Headers, owner_engine: Engine, app_engine: Engine
) -> None:
    seed_old(owner_engine, 3)
    run(retention_client(), administrator)

    # A far longer window makes nothing eligible; the existing boundary stays.
    wider = run(retention_client(window=100 * 365 * 24 * 3600), administrator).json()

    assert (wider["outcome"], wider["upToSequence"]) == ("NOTHING_ELIGIBLE", 3)
    assert retention_events(app_engine) == 1


def test_bounded_purge_returns_503_and_resumes_without_a_new_event(
    retention_client: MakeClient,
    administrator: Headers,
    auditor: Headers,
    owner_engine: Engine,
    app_engine: Engine,
) -> None:
    seed_old(owner_engine, 2, payload={f"k{i}": i for i in range(6)})
    client = retention_client(batch_size=5, max_batches=1)
    old_id = record_ids(app_engine)[0]

    first = run(client, administrator)
    body = _assert_problem(first, 503)
    assert (
        body["detail"] == "The retention purge reached its execution bound; a later run resumes it."
    )
    assert (retention_events(app_engine), values_at_or_below(app_engine, 2)) == (1, 7)

    # Mid-purge: archived, rendered null, verifiable, and not redactable.
    archived = client.get(f"/audit/events/{old_id}", headers=auditor).json()
    assert archived["archived"] is True
    assert set(archived["payload"].values()) == {None}
    assert verify(client, auditor)["intact"] is True
    redaction = client.post(
        f"/audit/events/{old_id}/redactions",
        json={"paths": ["/k1"], "reason": "privacy"},
        headers=administrator,
    )
    assert _assert_problem(redaction, 409)["detail"] == "Archived records cannot be redacted."

    _assert_problem(run(client, administrator), 503)
    resumed = run(client, administrator)

    assert resumed.status_code == 200
    assert resumed.json() == {
        "outcome": "PURGE_RESUMED",
        "upToSequence": 2,
        "retentionEvent": None,
        "purgedValues": 2,
    }
    assert (retention_events(app_engine), values_at_or_below(app_engine, 2)) == (1, 0)
    assert verify(client, auditor)["intact"] is True


def test_purge_that_exactly_fills_its_bound_completes(
    retention_client: MakeClient, administrator: Headers, owner_engine: Engine
) -> None:
    seed_old(owner_engine, 2, payload={f"k{i}": i for i in range(6)})

    response = run(retention_client(batch_size=6, max_batches=2), administrator)

    assert (response.status_code, response.json()["purgedValues"]) == (201, 12)


# --- Representation and queries -----------------------------------------------------------------


def test_archived_records_are_excluded_from_queries_by_default(
    retention_client: MakeClient,
    administrator: Headers,
    auditor: Headers,
    owner_engine: Engine,
    post_event: Any,
) -> None:
    seed_old(owner_engine, 2)
    post_event()
    client = retention_client()
    run(client, administrator)

    default = client.get("/audit/events", headers=auditor).json()["items"]
    included = client.get(
        "/audit/events", params={"includeArchived": "true"}, headers=auditor
    ).json()["items"]

    assert [item["sequence"] for item in default] == [3, 4]
    assert [item["sequence"] for item in included] == [1, 2, 3, 4]
    assert [item["archived"] for item in included] == [True, True, False, False]
    assert included[0]["payload"] == {"card": None, "email": None}
    assert included[0]["redactedPaths"] == []


def test_cursor_binds_include_archived(
    retention_client: MakeClient, administrator: Headers, auditor: Headers, owner_engine: Engine
) -> None:
    seed_old(owner_engine, 3)
    client = retention_client()
    run(client, administrator)
    cursor = client.get(
        "/audit/events", params={"includeArchived": "true", "limit": "1"}, headers=auditor
    ).json()["nextCursor"]

    response = client.get("/audit/events", params={"cursor": cursor}, headers=auditor)
    assert (
        _assert_problem(response, 422)["detail"]
        == "cursor was issued for a different set of filters"
    )


def test_archiving_keeps_redaction_paths_and_rejects_redaction(
    retention_client: MakeClient, administrator: Headers, auditor: Headers, owner_engine: Engine
) -> None:
    seed_old(owner_engine, 1)
    client = retention_client()
    target_id = client.get("/audit/events", headers=auditor).json()["items"][0]["id"]
    client.post(
        f"/audit/events/{target_id}/redactions",
        json={"paths": ["/card"], "reason": "privacy"},
        headers=administrator,
    )
    run(client, administrator)

    archived = client.get(f"/audit/events/{target_id}", headers=auditor).json()

    assert (archived["archived"], archived["redactedPaths"]) == (True, ["/card"])
    assert archived["payload"] == {"card": None, "email": None}
    response = client.post(
        f"/audit/events/{target_id}/redactions",
        json={"paths": ["/email"], "reason": "privacy"},
        headers=administrator,
    )
    assert _assert_problem(response, 409)["detail"] == "Archived records cannot be redacted."
    assert verify(client, auditor)["intact"] is True


def test_retention_event_is_a_system_event(
    retention_client: MakeClient, administrator: Headers, owner_engine: Engine
) -> None:
    seed_old(owner_engine, 1)
    client = retention_client()
    event_id = run(client, administrator).json()["retentionEvent"]["id"]

    response = client.post(
        f"/audit/events/{event_id}/redactions",
        json={"paths": ["/cutoff"], "reason": "privacy"},
        headers=administrator,
    )
    assert _assert_problem(response, 409)["detail"] == "System events cannot be redacted."


def test_older_retention_and_redaction_events_can_themselves_be_archived(
    retention_client: MakeClient,
    administrator: Headers,
    auditor: Headers,
    owner_engine: Engine,
    app_engine: Engine,
) -> None:
    seed_old(owner_engine, 1)
    client = retention_client()
    target_id = record_ids(app_engine)[0]
    client.post(
        f"/audit/events/{target_id}/redactions",
        json={"paths": ["/card"], "reason": "privacy"},
        headers=administrator,
    )
    run(client, administrator)  # sequence 3 archives 1
    time.sleep(1.2)

    later = run(retention_client(window=1), administrator).json()

    assert (later["outcome"], later["upToSequence"]) == ("RETENTION_RECORDED", 3)
    # Only the redaction event's kept evidence remains at or below the boundary.
    assert stored_pointers(app_engine, record_ids(app_engine)[1]) == ["/paths/0", "/targetId"]
    assert values_at_or_below(app_engine, 3) == 2
    assert verify(client, auditor)["intact"] is True
    first_event = client.get(f"/audit/events/{record_ids(app_engine)[2]}", headers=auditor).json()
    assert first_event["archived"] is True
    # The kept evidence still names the redacted path after both records are archived.
    assert client.get(f"/audit/events/{target_id}", headers=auditor).json()["redactedPaths"] == [
        "/card"
    ]


def test_redaction_evidence_is_kept_through_every_purge(
    retention_client: MakeClient,
    administrator: Headers,
    auditor: Headers,
    owner_engine: Engine,
    app_engine: Engine,
    post_event: Any,
) -> None:
    seed_old(owner_engine, 1, payload={"card": "4111", "email": "a@example.test", "phone": "5"})
    client = retention_client()
    target_id = record_ids(app_engine)[0]
    redaction_id = client.post(
        f"/audit/events/{target_id}/redactions",
        json={"paths": ["/card", "/email"], "reason": "privacy request"},
        headers=administrator,
    ).json()["id"]
    run(client, administrator)  # sequence 3 archives the target
    time.sleep(1.2)
    slow = retention_client(window=1, batch_size=1, max_batches=1)

    # Archives the redaction event (2) and the first retention event (3); three values are
    # purgeable (the reason, the cutoff, and upToSequence), one per run.
    _assert_problem(run(slow, administrator), 503)
    mid_purge = client.get(f"/audit/events/{target_id}", headers=auditor).json()
    assert mid_purge["redactedPaths"] == ["/card", "/email"]
    assert set(mid_purge["payload"].values()) == {None}

    _assert_problem(run(slow, administrator), 503)
    resumed = run(slow, administrator)
    assert (resumed.status_code, resumed.json()["outcome"]) == (200, "PURGE_RESUMED")
    # Kept evidence never leaves the purge unfinished.
    assert run(slow, administrator).json()["outcome"] == "NOTHING_ELIGIBLE"

    assert stored_pointers(app_engine, redaction_id) == ["/paths/0", "/paths/1", "/targetId"]
    archived_redaction = client.get(f"/audit/events/{redaction_id}", headers=auditor).json()
    assert archived_redaction["archived"] is True
    assert archived_redaction["payload"] == {
        "targetId": None,
        "paths": [None, None],
        "reason": None,
    }
    assert verify(client, auditor)["intact"] is True

    # A later run with a new boundary still keeps the evidence.
    post_event()
    time.sleep(1.2)
    assert run(retention_client(window=1), administrator).status_code == 201
    assert stored_pointers(app_engine, redaction_id) == ["/paths/0", "/paths/1", "/targetId"]
    assert client.get(f"/audit/events/{target_id}", headers=auditor).json()["redactedPaths"] == [
        "/card",
        "/email",
    ]
    assert verify(client, auditor)["intact"] is True

    # The kept values are still commitment-protected: tampering with one is detected.
    with owner_engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE audit_payload_values SET canonical_value = '\"/phone\"' "
                "WHERE record_id = :id AND pointer = '/paths/0'"
            ),
            {"id": uuid.UUID(redaction_id)},
        )
    report = verify(client, auditor)
    assert (report["firstViolation"]["type"], report["firstViolation"]["sequence"]) == (
        "PAYLOAD_VALUE_MISMATCH",
        2,
    )


# --- Verification against tampering -------------------------------------------------------------


def test_unauthorized_deletion_above_the_boundary_is_detected(
    retention_client: MakeClient,
    administrator: Headers,
    auditor: Headers,
    owner_engine: Engine,
    post_event: Any,
) -> None:
    seed_old(owner_engine, 2)
    recent = post_event().json()
    client = retention_client()
    run(client, administrator)
    with owner_engine.begin() as connection:
        connection.execute(
            text("DELETE FROM audit_payload_values WHERE record_id = :id"),
            {"id": uuid.UUID(recent["id"])},
        )

    report = verify(client, auditor)
    assert (report["firstViolation"]["type"], report["firstViolation"]["sequence"]) == (
        "PAYLOAD_VALUE_MISSING",
        3,
    )


def test_tampered_retention_event_does_not_extend_its_coverage(
    retention_client: MakeClient,
    administrator: Headers,
    auditor: Headers,
    owner_engine: Engine,
    post_event: Any,
) -> None:
    seed_old(owner_engine, 1)
    recent = post_event().json()
    client = retention_client()
    event_id = run(client, administrator).json()["retentionEvent"]["id"]
    with owner_engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE audit_payload_values SET canonical_value = '2' "
                "WHERE record_id = :id AND pointer = '/upToSequence'"
            ),
            {"id": uuid.UUID(event_id)},
        )
        connection.execute(
            text("DELETE FROM audit_payload_values WHERE record_id = :id"),
            {"id": uuid.UUID(recent["id"])},
        )

    report = verify(client, auditor)

    assert (report["firstViolation"]["type"], report["firstViolation"]["sequence"]) == (
        "PAYLOAD_VALUE_MISSING",
        1,
    )
    assert report["violationCount"] == 3


def test_retention_changes_no_hash_or_record(
    retention_client: MakeClient, administrator: Headers, owner_engine: Engine, app_engine: Engine
) -> None:
    seed_old(owner_engine, 4)
    before = chain_state(app_engine)

    run(retention_client(batch_size=1, max_batches=3), administrator)
    run(retention_client(), administrator)

    assert chain_state(app_engine)[:4] == before


# --- Concurrency ----------------------------------------------------------------------------------


def test_concurrent_runs_record_one_event(
    retention_client: MakeClient,
    administrator: Headers,
    auditor: Headers,
    owner_engine: Engine,
    app_engine: Engine,
) -> None:
    seed_old(owner_engine, 3)
    clients = [retention_client(), retention_client()]
    start = threading.Barrier(2)
    statuses: list[int] = []

    def worker(client: httpx.Client) -> None:
        start.wait()
        statuses.append(run(client, administrator).status_code)

    threads = [threading.Thread(target=worker, args=(c,)) for c in clients]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(statuses) == [200, 201]
    assert retention_events(app_engine) == 1
    assert verify(clients[0], auditor)["intact"] is True


def test_concurrent_retention_and_redaction_stay_consistent(
    retention_client: MakeClient,
    administrator: Headers,
    auditor: Headers,
    owner_engine: Engine,
    app_engine: Engine,
) -> None:
    seed_old(owner_engine, 1)
    target_id = record_ids(app_engine)[0]
    client = retention_client()
    start = threading.Barrier(2)
    results: dict[str, int] = {}

    def redact() -> None:
        start.wait()
        results["redaction"] = client.post(
            f"/audit/events/{target_id}/redactions",
            json={"paths": ["/card"], "reason": "privacy"},
            headers=administrator,
        ).status_code

    def retain() -> None:
        start.wait()
        results["retention"] = run(client, administrator).status_code

    threads = [threading.Thread(target=redact), threading.Thread(target=retain)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results["retention"] == 201
    assert results["redaction"] in (201, 409)
    assert verify(client, auditor)["intact"] is True


# --- Eligibility at the cutoff -------------------------------------------------------------------


def test_eligibility_is_strictly_before_the_cutoff_and_contiguous(
    owner_engine: Engine, insert_sealed: Any
) -> None:
    cutoff = OLD + timedelta(seconds=10)
    times = [cutoff - timedelta(microseconds=1), cutoff, cutoff - timedelta(seconds=5)]
    previous = GENESIS_PREVIOUS_HASH
    with owner_engine.begin() as connection:
        for sequence, moment in enumerate(times, start=1):
            content = EventContent(
                id=str(uuid.uuid4()),
                event_type="ORDER_PLACED",
                actor_id="a",
                resource_type="ORDER",
                resource_id="o",
                timestamp=None,
                recorded_at=format_timestamp(moment),
                recorded_by="svc",
                payload={},
            )
            record = seal_record(content, sequence, previous)
            insert_sealed(connection, record)
            previous = record.record_hash

        # Record 2 is exactly at the cutoff, so the block ends at 1 even though 3 is older.
        assert highest_eligible_sequence(connection, cutoff) == 1
        assert highest_eligible_sequence(connection, cutoff + timedelta(microseconds=1)) == 3
        assert highest_eligible_sequence(connection, OLD) == 0


def test_eligibility_of_an_empty_chain_is_zero(owner_engine: Engine) -> None:
    with owner_engine.begin() as connection:
        assert highest_eligible_sequence(connection, OLD) == 0


def test_boundary_falls_back_to_the_latest_valid_retention_event(
    retention_client: MakeClient,
    administrator: Headers,
    auditor: Headers,
    owner_engine: Engine,
) -> None:
    seed_old(owner_engine, 2)
    client = retention_client()
    run(client, administrator)  # the genuine event is sequence 3, with boundary 2
    # A forged, properly sealed retention event whose boundary is not below its own sequence.
    append_sealed(
        owner_engine,
        {"cutoff": "2026-01-01T00:00:00.000000Z", "upToSequence": 10},
        datetime.now(UTC),
        event_type="AUDIT_LOG_RETENTION",
    )

    listed = client.get("/audit/events", headers=auditor).json()["items"]

    assert [item["sequence"] for item in listed] == [3, 4]
    assert verify(client, auditor)["intact"] is True  # an unused forged event violates nothing


@pytest.mark.parametrize("stored", ["not json", "5"], ids=["unreadable", "not-a-string"])
def test_tampered_redaction_paths_are_not_reported(
    retention_client: MakeClient,
    administrator: Headers,
    auditor: Headers,
    post_event: Any,
    owner_engine: Engine,
    stored: str,
) -> None:
    client = retention_client()
    target = post_event().json()
    redaction = client.post(
        f"/audit/events/{target['id']}/redactions",
        json={"paths": ["/items"], "reason": "privacy"},
        headers=administrator,
    ).json()
    with owner_engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE audit_payload_values SET canonical_value = :stored "
                "WHERE record_id = :id AND pointer = '/paths/0'"
            ),
            {"id": uuid.UUID(redaction["id"]), "stored": stored},
        )

    fetched = client.get(f"/audit/events/{target['id']}", headers=auditor).json()
    assert fetched["redactedPaths"] == ["/items/1"]


def test_unreadable_appended_retention_event_is_a_500_and_rolls_back(
    retention_client: MakeClient,
    administrator: Headers,
    owner_engine: Engine,
    app_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed_old(owner_engine, 1)

    def missing(*_args: object) -> None:
        return None

    monkeypatch.setattr(retention_module, "load_entry", missing)

    _assert_problem(run(retention_client(), administrator), 500)
    assert retention_events(app_engine) == 0
