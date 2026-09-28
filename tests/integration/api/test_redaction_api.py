"""API tests for POST /audit/events/{id}/redactions (FR-6) against real PostgreSQL."""

import json
import threading
import uuid
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import Engine, text

from audit_log_service.application import redactions as redactions_module
from audit_log_service.application.verification import VIOLATION_MESSAGES
from audit_log_service.integrity.commitments import values_open_commitments
from audit_log_service.integrity.verification import ChainEntry, ViolationType

Headers = dict[str, str]
PostEvent = Callable[..., httpx.Response]
Load = Callable[[], list[ChainEntry]]
PAYLOAD: dict[str, Any] = {
    "card": "4111-1111",
    "email": "person@example.test",
    "nested": {"phone": "555-0100", "tags": ["vip", "eu"]},
    "items": [{"sku": "A-1"}, 2],
}


@pytest.fixture
def target(post_event: PostEvent) -> dict[str, Any]:
    created: dict[str, Any] = post_event(payload=PAYLOAD).json()
    return created


@pytest.fixture
def redact(client: httpx.Client, administrator: Headers) -> Callable[..., httpx.Response]:
    def run(
        event_id: str,
        paths: list[str] | None = None,
        reason: str = "Customer privacy request",
        headers: Headers | None = None,
        body: Any = None,
    ) -> httpx.Response:
        document = body if body is not None else {"paths": paths or ["/card"], "reason": reason}
        return client.post(
            f"/audit/events/{event_id}/redactions",
            json=document,
            headers=administrator if headers is None else headers,
        )

    return run


Redact = Callable[..., httpx.Response]


def _get(client: httpx.Client, auditor: Headers, event_id: str) -> dict[str, Any]:
    response = client.get(f"/audit/events/{event_id}", headers=auditor)
    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    return body


def _verify(client: httpx.Client, auditor: Headers) -> dict[str, Any]:
    body: dict[str, Any] = client.get("/audit/verify", headers=auditor).json()
    return body


def _assert_problem(response: httpx.Response, status: int) -> dict[str, Any]:
    assert response.status_code == status, response.text
    assert response.headers["content-type"] == "application/problem+json"
    body: dict[str, Any] = response.json()
    assert body["requestId"] == response.headers["x-request-id"]
    return body


def _record_count(engine: Engine) -> int:
    with engine.connect() as connection:
        count: int = connection.execute(text("SELECT count(*) FROM audit_records")).scalar_one()
    return count


# --- Successful redaction -----------------------------------------------------------------------


def test_redacting_one_value_records_a_system_event(
    client: httpx.Client, auditor: Headers, target: dict[str, Any], redact: Redact
) -> None:
    response = redact(target["id"], ["/card"], reason="  Request #42 ")

    assert response.status_code == 201
    event = response.json()
    assert response.headers["location"] == f"/audit/events/{event['id']}"
    assert event["eventType"] == "AUDIT_LOG_REDACTION"
    assert event["sequence"] == target["sequence"] + 1
    assert (event["actorId"], event["resourceType"], event["resourceId"]) == (
        target["actorId"],
        target["resourceType"],
        target["resourceId"],
    )
    assert event["recordedBy"] == "ops.admin"
    assert event["timestamp"] is None
    assert event["payload"] == {
        "targetId": target["id"],
        "paths": ["/card"],
        "reason": "  Request #42 ",
    }
    assert _get(client, auditor, event["id"]) == event


def test_redacted_value_renders_as_null_and_hashes_are_unchanged(
    client: httpx.Client, auditor: Headers, target: dict[str, Any], redact: Redact
) -> None:
    redact(target["id"], ["/card", "/nested/tags/1"])

    after = _get(client, auditor, target["id"])

    assert after["payload"] == {
        "card": None,
        "email": PAYLOAD["email"],
        "nested": {"phone": "555-0100", "tags": ["vip", None]},
        "items": [{"sku": "A-1"}, 2],
    }
    assert after["redactedPaths"] == ["/card", "/nested/tags/1"]
    for field in ("contentHash", "previousHash", "recordHash", "sequence", "recordedAt"):
        assert after[field] == target[field]


def test_container_pointer_covers_every_value_beneath_it(
    client: httpx.Client, auditor: Headers, target: dict[str, Any], redact: Redact
) -> None:
    event = redact(target["id"], ["/nested"]).json()

    assert event["payload"]["paths"] == ["/nested/phone", "/nested/tags/0", "/nested/tags/1"]
    assert _get(client, auditor, target["id"])["payload"]["nested"] == {
        "phone": None,
        "tags": [None, None],
    }


def test_root_pointer_covers_the_whole_payload(
    client: httpx.Client, auditor: Headers, target: dict[str, Any], redact: Redact
) -> None:
    event = redact(target["id"], [""]).json()

    after = _get(client, auditor, target["id"])
    assert event["payload"]["paths"] == after["redactedPaths"]
    assert len(after["redactedPaths"]) == 7
    assert after["payload"] == {
        "card": None,
        "email": None,
        "nested": {"phone": None, "tags": [None, None]},
        "items": [{"sku": None}, None],
    }


def test_partial_redaction_records_only_new_values(target: dict[str, Any], redact: Redact) -> None:
    redact(target["id"], ["/card"])
    second = redact(target["id"], ["/card", "/email"]).json()
    assert second["payload"]["paths"] == ["/email"]


def test_nothing_new_to_redact_is_409_and_records_nothing(
    target: dict[str, Any], redact: Redact, app_engine: Engine
) -> None:
    redact(target["id"], ["/card"])
    before = _record_count(app_engine)

    body = _assert_problem(redact(target["id"], ["/card"]), 409)

    assert body["detail"] == "No payload value remains to be redacted at these paths."
    assert _record_count(app_engine) == before


def test_pointer_to_an_empty_container_redacts_nothing(
    post_event: PostEvent, redact: Redact
) -> None:
    event_id = post_event(payload={"empty": {}, "list": []}).json()["id"]
    _assert_problem(redact(event_id, ["/empty", "/list"]), 409)


# --- Validation, lookup, and check order ---------------------------------------------------------


@pytest.mark.parametrize(
    ("paths", "detail"),
    [
        (["card"], "paths[0] is not a valid JSON Pointer"),
        (["/card", "/unknown"], "paths[1] does not identify a value in the payload"),
        (["/card/deeper"], "paths[0] does not identify a value in the payload"),
        (["/items/5"], "paths[0] does not identify a value in the payload"),
        (["/items/01"], "paths[0] does not identify a value in the payload"),
        (["/items/-"], "paths[0] does not identify a value in the payload"),
    ],
    ids=["syntax", "unknown-member", "below-a-value", "index-out-of-range", "leading-zero", "dash"],
)
def test_invalid_or_nonexistent_pointer_rejects_the_whole_request(
    client: httpx.Client,
    auditor: Headers,
    target: dict[str, Any],
    redact: Redact,
    paths: list[str],
    detail: str,
) -> None:
    body = _assert_problem(redact(target["id"], paths), 422)

    assert body["detail"] == detail
    assert _get(client, auditor, target["id"])["redactedPaths"] == []


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"paths": ["/card"], "reason": "   "}, 422),
        ({"paths": ["/card"], "reason": ""}, 422),
        ({"paths": ["/card"], "reason": "r", "extra": 1}, 422),
        ({"paths": [], "reason": "r"}, 422),
    ],
    ids=["whitespace-reason", "empty-reason", "unknown-field", "no-paths"],
)
def test_invalid_request_bodies_are_422(
    target: dict[str, Any], redact: Redact, body: dict[str, Any], status: int
) -> None:
    _assert_problem(redact(target["id"], body=body), status)


def test_body_reader_statuses_apply(
    client: httpx.Client, administrator: Headers, target: dict[str, Any]
) -> None:
    url = f"/audit/events/{target['id']}/redactions"
    json_headers = {**administrator, "Content-Type": "application/json"}

    _assert_problem(client.post(url, content=b"{not json", headers=json_headers), 400)
    _assert_problem(
        client.post(url, content=b'{"paths": ["/a"], "paths": []}', headers=json_headers), 422
    )
    _assert_problem(
        client.post(url, content=b"{}", headers={**administrator, "Content-Type": "text/plain"}),
        415,
    )
    oversized = json.dumps({"paths": ["/card"], "reason": "x" * (64 * 1024)}).encode()
    _assert_problem(client.post(url, content=oversized, headers=json_headers), 413)


@pytest.mark.parametrize("event_id", [str(uuid.uuid4()), "not-a-uuid"], ids=["unknown", "not-uuid"])
def test_missing_target_is_404(redact: Redact, event_id: str) -> None:
    assert _assert_problem(redact(event_id), 404)["detail"] == "No audit event has this identifier."


def test_body_validation_comes_before_target_lookup(redact: Redact) -> None:
    _assert_problem(redact(str(uuid.uuid4()), body={"paths": ["/a"], "reason": " "}), 422)


def test_system_events_cannot_be_redacted(target: dict[str, Any], redact: Redact) -> None:
    redaction_id = redact(target["id"], ["/card"]).json()["id"]

    # The system-event check comes before pointer resolution: /unknown would otherwise be a 422.
    body = _assert_problem(redact(redaction_id, ["/unknown"]), 409)
    assert body["detail"] == "System events cannot be redacted."


def test_errors_do_not_echo_pointers_or_reasons(target: dict[str, Any], redact: Redact) -> None:
    secret = "4111-1111-1111-1111"
    for response in (
        redact(target["id"], [f"/{secret}"]),
        redact(target["id"], [secret]),
        redact(target["id"], ["/card"], reason=secret + "\x00"),
        redact(target["id"], body={"paths": ["/card"], "reason": "r", secret: 1}),
    ):
        assert response.status_code == 422
        assert secret not in response.text


# --- Authorization ------------------------------------------------------------------------------


@pytest.mark.parametrize("principal", ["writer", "auditor", "regulator"])
def test_only_redact_capability_may_redact(
    target: dict[str, Any], redact: Redact, fake_keys: Any, principal: str
) -> None:
    headers = {"Authorization": f"Bearer {fake_keys[principal]}"}
    _assert_problem(redact(target["id"], headers=headers, body={"paths": "bad"}), 403)


def test_unauthenticated_redaction_is_401_before_validation(
    client: httpx.Client, target: dict[str, Any]
) -> None:
    response = client.post(f"/audit/events/{target['id']}/redactions", content=b"{bad")
    _assert_problem(response, 401)


# --- Atomicity, integrity, and verification ----------------------------------------------------


def test_failure_after_deleting_values_rolls_everything_back(
    client: httpx.Client,
    auditor: Headers,
    target: dict[str, Any],
    redact: Redact,
    app_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args: object) -> None:
        raise RuntimeError("append failed")

    monkeypatch.setattr(redactions_module, "append_event", fail)
    before = _record_count(app_engine)

    _assert_problem(redact(target["id"], ["/card"]), 500)

    assert _record_count(app_engine) == before
    assert _get(client, auditor, target["id"]) == target


def test_unreadable_redaction_event_is_a_500_and_rolls_back(
    target: dict[str, Any], redact: Redact, app_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_load = redactions_module.load_entry
    calls: list[int] = []

    def load_then_lose(connection: Any, record_id: uuid.UUID) -> Any:
        calls.append(1)
        return real_load(connection, record_id) if len(calls) == 1 else None

    monkeypatch.setattr(redactions_module, "load_entry", load_then_lose)
    before = _record_count(app_engine)

    _assert_problem(redact(target["id"], ["/card"]), 500)
    assert _record_count(app_engine) == before


def test_legitimate_redaction_keeps_the_chain_intact(
    client: httpx.Client, auditor: Headers, target: dict[str, Any], redact: Redact, load: Load
) -> None:
    redact(target["id"], ["/card"])
    redact(target["id"], ["/nested"])

    report = _verify(client, auditor)

    assert report["intact"] is True
    assert report["recordsChecked"] == 3
    entry = next(e for e in load() if e.record.content.id == target["id"])
    assert values_open_commitments(entry.record.content.payload, entry.payload_values)
    assert sorted(entry.payload_values) == ["/email", "/items/0/sku", "/items/1"]


def test_value_deleted_without_redaction_is_payload_value_missing(
    client: httpx.Client, auditor: Headers, target: dict[str, Any], owner_engine: Engine
) -> None:
    with owner_engine.begin() as connection:
        connection.execute(
            text("DELETE FROM audit_payload_values WHERE record_id = :id AND pointer = '/email'"),
            {"id": uuid.UUID(target["id"])},
        )

    report = _verify(client, auditor)

    assert report["firstViolation"] == {
        "type": "PAYLOAD_VALUE_MISSING",
        "sequence": target["sequence"],
        "recordId": target["id"],
        "message": VIOLATION_MESSAGES[ViolationType.PAYLOAD_VALUE_MISSING],
    }
    assert "/email" not in json.dumps(report)


def test_redaction_authorizes_only_the_values_it_removed(
    client: httpx.Client,
    auditor: Headers,
    target: dict[str, Any],
    redact: Redact,
    owner_engine: Engine,
) -> None:
    redact(target["id"], ["/card"])
    with owner_engine.begin() as connection:
        connection.execute(
            text("DELETE FROM audit_payload_values WHERE record_id = :id AND pointer = '/email'"),
            {"id": uuid.UUID(target["id"])},
        )

    report = _verify(client, auditor)
    assert (report["firstViolation"]["type"], report["violationCount"]) == (
        "PAYLOAD_VALUE_MISSING",
        1,
    )


def test_tampered_redaction_event_does_not_authorize(
    client: httpx.Client,
    auditor: Headers,
    target: dict[str, Any],
    redact: Redact,
    owner_engine: Engine,
) -> None:
    redaction = redact(target["id"], ["/card"]).json()
    with owner_engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE audit_payload_values SET canonical_value = '\"forged\"' "
                "WHERE record_id = :id AND pointer = '/reason'"
            ),
            {"id": uuid.UUID(redaction["id"])},
        )

    report = _verify(client, auditor)

    assert (report["firstViolation"]["type"], report["firstViolation"]["sequence"]) == (
        "PAYLOAD_VALUE_MISSING",
        target["sequence"],
    )
    assert report["violationCount"] == 2


# --- Representation across endpoints ------------------------------------------------------------


def test_representation_is_consistent_across_get_and_query(
    client: httpx.Client, auditor: Headers, target: dict[str, Any], redact: Redact
) -> None:
    redaction = redact(target["id"], ["/items/0"]).json()

    fetched = _get(client, auditor, target["id"])
    listed = client.get("/audit/events", headers=auditor).json()["items"]

    assert listed == [fetched, redaction]
    assert fetched["redactedPaths"] == ["/items/0/sku"]
    assert fetched["payload"]["items"] == [{"sku": None}, 2]
    assert redaction["redactedPaths"] == []


# --- Concurrency --------------------------------------------------------------------------------


def test_concurrent_redactions_of_the_same_value_serialize(
    target: dict[str, Any], redact: Redact, app_engine: Engine
) -> None:
    start = threading.Barrier(4)
    statuses: list[int] = []

    def worker() -> None:
        start.wait()
        statuses.append(redact(target["id"], ["/card"]).status_code)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(statuses) == [201, 409, 409, 409]
    assert _record_count(app_engine) == 2


def test_concurrent_redactions_of_different_values_all_apply(
    client: httpx.Client, auditor: Headers, target: dict[str, Any], redact: Redact
) -> None:
    pointers = ["/card", "/email", "/nested/phone", "/items/1"]
    start = threading.Barrier(len(pointers))
    statuses: list[int] = []

    def worker(pointer: str) -> None:
        start.wait()
        statuses.append(redact(target["id"], [pointer]).status_code)

    threads = [threading.Thread(target=worker, args=(p,)) for p in pointers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert statuses == [201] * 4
    assert _get(client, auditor, target["id"])["redactedPaths"] == sorted(pointers)
    assert _verify(client, auditor)["intact"] is True


# --- Property ---------------------------------------------------------------------------------

_LEAVES = [
    "/card",
    "/email",
    "/nested/phone",
    "/nested/tags/0",
    "/nested/tags/1",
    "/items/0/sku",
    "/items/1",
]


@settings(
    max_examples=15, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(batches=st.lists(st.lists(st.sampled_from(_LEAVES), min_size=1, max_size=3), max_size=4))
def test_any_sequence_of_redactions_keeps_the_chain_verifiable(
    client: httpx.Client,
    auditor: Headers,
    post_event: PostEvent,
    redact: Redact,
    owner_engine: Engine,
    batches: list[list[str]],
) -> None:
    with owner_engine.begin() as connection:
        connection.execute(text("TRUNCATE audit_payload_values, audit_records"))
    event_id = post_event(payload=PAYLOAD).json()["id"]
    redacted: set[str] = set()
    for batch in batches:
        response = redact(event_id, batch)
        new = set(batch) - redacted
        assert response.status_code == (201 if new else 409)
        redacted |= new

    assert _get(client, auditor, event_id)["redactedPaths"] == sorted(redacted)
    assert _verify(client, auditor)["intact"] is True
