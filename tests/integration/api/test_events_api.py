"""API tests for POST /audit/events and GET /audit/events/{id} against real PostgreSQL."""

import json
import re
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import Engine, text

from audit_log_service.integrity.canonical import canonicalize
from audit_log_service.integrity.hashing import GENESIS_PREVIOUS_HASH
from audit_log_service.integrity.timestamps import format_timestamp, parse_timestamp
from audit_log_service.integrity.verification import ChainEntry, verify_chain

Headers = dict[str, str]
PostEvent = Callable[..., httpx.Response]
Load = Callable[[], list[ChainEntry]]

UUID_TEXT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
HASH_TEXT = re.compile(r"[0-9a-f]{64}")
CANONICAL_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")
EVENT_FIELDS = {
    "id",
    "sequence",
    "eventType",
    "actorId",
    "resourceType",
    "resourceId",
    "timestamp",
    "recordedAt",
    "recordedBy",
    "payload",
    "redactedPaths",
    "archived",
    "contentHash",
    "previousHash",
    "recordHash",
}


def _assert_problem(response: httpx.Response, status: int) -> dict[str, Any]:
    assert response.status_code == status
    assert response.headers["content-type"] == "application/problem+json"
    body: dict[str, Any] = response.json()
    assert body["type"] == "about:blank"
    assert body["status"] == status
    assert body["requestId"] == response.headers["x-request-id"]
    return body


def _count_records(engine: Engine) -> int:
    with engine.connect() as connection:
        count: int = connection.execute(text("SELECT count(*) FROM audit_records")).scalar_one()
    return count


# --- Authentication (D4, Phase 1) --------------------------------------------------------------


@pytest.mark.parametrize(
    "authorization",
    [
        pytest.param([], id="missing"),
        pytest.param([("Authorization", "Basic dXNlcjpwYXNz")], id="non-bearer"),
        pytest.param([("Authorization", "Bearer")], id="no-token"),
        pytest.param([("Authorization", "Bearer  test-only-writer-key")], id="two-spaces"),
        pytest.param([("Authorization", "Bearer unknown-test-key")], id="unknown-key"),
        pytest.param(
            [
                ("Authorization", "Bearer test-only-writer-key"),
                ("Authorization", "Bearer test-only-writer-key"),
            ],
            id="multiple-headers",
        ),
    ],
)
@pytest.mark.parametrize("method", ["POST", "GET"])
def test_authentication_failures_are_a_uniform_401(
    client: httpx.Client, authorization: list[tuple[str, str]], method: str
) -> None:
    if method == "POST":
        # An invalid body too: authentication is checked before any validation.
        response = client.post("/audit/events", content=b"{not json", headers=authorization)
    else:
        response = client.get(f"/audit/events/{uuid.uuid4()}", headers=authorization)

    body = _assert_problem(response, 401)
    assert response.headers["www-authenticate"] == "Bearer"
    assert body["detail"] == "Valid Bearer credentials are required."
    assert "test-only-writer-key" not in response.text


def test_missing_write_capability_is_403_before_validation(
    client: httpx.Client, auditor: Headers
) -> None:
    response = client.post("/audit/events", content=b"{not json", headers=auditor)
    _assert_problem(response, 403)


def test_missing_read_capability_is_403_before_lookup(
    client: httpx.Client, writer: Headers, post_event: PostEvent
) -> None:
    event_id = post_event().json()["id"]
    response = client.get(f"/audit/events/{event_id}", headers=writer)
    _assert_problem(response, 403)


@pytest.mark.parametrize("reader", ["auditor", "administrator"])
def test_principals_with_read_capability_can_get(
    client: httpx.Client, post_event: PostEvent, reader: str, request: pytest.FixtureRequest
) -> None:
    event_id = post_event().json()["id"]
    headers: Headers = request.getfixturevalue(reader)
    assert client.get(f"/audit/events/{event_id}", headers=headers).status_code == 200


# --- POST: success ------------------------------------------------------------------------------


def test_append_returns_201_with_location_and_the_full_record(post_event: PostEvent) -> None:
    response = post_event()

    assert response.status_code == 201
    assert response.headers["content-type"] == "application/json"
    body = response.json()
    assert set(body) == EVENT_FIELDS
    assert response.headers["location"] == f"/audit/events/{body['id']}"
    assert UUID_TEXT.fullmatch(body["id"])
    assert body["sequence"] == 1
    assert body["previousHash"] == GENESIS_PREVIOUS_HASH
    assert CANONICAL_TIME.fullmatch(body["recordedAt"])
    assert body["recordedBy"] == "svc-writer"
    assert all(HASH_TEXT.fullmatch(body[name]) for name in ("contentHash", "recordHash"))
    assert body["payload"] == {"amount": 12.5, "items": ["sku-1", "sku-2"]}
    assert body["timestamp"] is None
    assert (body["redactedPaths"], body["archived"]) == ([], False)


def test_second_append_links_to_the_first(post_event: PostEvent) -> None:
    first = post_event().json()
    second = post_event().json()

    assert second["sequence"] == 2
    assert second["previousHash"] == first["recordHash"]


def test_recorded_at_comes_from_the_database(post_event: PostEvent, app_engine: Engine) -> None:
    with app_engine.connect() as connection:
        before = connection.execute(text("SELECT clock_timestamp()")).scalar_one()
    body = post_event().json()
    with app_engine.connect() as connection:
        after = connection.execute(text("SELECT clock_timestamp()")).scalar_one()

    assert before <= parse_timestamp(body["recordedAt"]) <= after


@pytest.mark.parametrize(
    ("submitted", "returned"),
    [
        ("2026-09-28T18:30:00.25+02:30", "2026-09-28T16:00:00.250000Z"),
        ("1970-01-01T00:00:00Z", "1970-01-01T00:00:00.000000Z"),
    ],
)
def test_supplied_timestamp_is_returned_in_canonical_utc(
    post_event: PostEvent, submitted: str, returned: str
) -> None:
    assert post_event(timestamp=submitted).json()["timestamp"] == returned


def test_timestamp_within_the_allowed_skew_is_accepted(post_event: PostEvent) -> None:
    soon = format_timestamp(datetime.now(UTC) + timedelta(minutes=1))
    assert post_event(timestamp=soon).status_code == 201


def test_timestamp_beyond_the_allowed_skew_is_rejected_without_a_gap(
    post_event: PostEvent, app_engine: Engine
) -> None:
    late = format_timestamp(datetime.now(UTC) + timedelta(minutes=10))

    body = _assert_problem(post_event(timestamp=late), 422)

    assert body["detail"] == "timestamp is too far in the future"
    assert _count_records(app_engine) == 0
    assert post_event().json()["sequence"] == 1


def test_json_content_type_parameters_are_accepted(client: httpx.Client, writer: Headers) -> None:
    response = client.post(
        "/audit/events",
        content=json.dumps(_body()).encode(),
        headers={**writer, "Content-Type": "application/json; charset=utf-8"},
    )
    assert response.status_code == 201


def _body(**changes: Any) -> dict[str, Any]:
    return {
        "eventType": "ORDER_PLACED",
        "actorId": "user-7",
        "resourceType": "ORDER",
        "resourceId": "order-1",
        "payload": {"amount": 1},
        **changes,
    }


# --- Scenario C (FR-8, C3) -------------------------------------------------------------------


def test_configured_client_account_event_is_accepted(post_event: PostEvent) -> None:
    response = post_event(
        eventType="CLIENT_ACCOUNT_VIEWED",
        resourceType="CLIENT_ACCOUNT",
        resourceId="acct-42",
        payload={"purpose": "kyc-review", "channel": "branch"},
    )
    assert response.status_code == 201


@pytest.mark.parametrize(
    ("changes", "detail"),
    [
        (
            {"eventType": "CLIENT_ACCOUNT_SOLD", "payload": {"purpose": "x", "channel": "y"}},
            "eventType is not in the configured vocabulary for this resourceType",
        ),
        (
            {"eventType": "CLIENT_ACCOUNT_VIEWED", "payload": {"purpose": "x"}},
            "payload is missing a key required for this eventType",
        ),
    ],
    ids=["unknown-event-type", "missing-required-key"],
)
def test_client_account_vocabulary_is_enforced(
    post_event: PostEvent, changes: dict[str, Any], detail: str
) -> None:
    response = post_event(resourceType="CLIENT_ACCOUNT", **changes)
    assert _assert_problem(response, 422)["detail"] == detail


def test_other_resource_types_ignore_the_vocabulary(post_event: PostEvent) -> None:
    assert post_event(eventType="SHIPMENT_DISPATCHED", resourceType="SHIPMENT").status_code == 201


def test_reserved_system_event_namespace_is_rejected(post_event: PostEvent) -> None:
    response = post_event(eventType="AUDIT_LOG_REDACTION")
    assert "reserved" in _assert_problem(response, 422)["detail"]


# --- POST: validation failures --------------------------------------------------------------


@pytest.mark.parametrize("field", ["eventType", "actorId", "resourceType", "resourceId", "payload"])
def test_required_fields(post_event: PostEvent, omit: object, field: str) -> None:
    response = post_event(**{field: omit})
    assert field in _assert_problem(response, 422)["detail"]


@pytest.mark.parametrize(
    "field",
    ["id", "sequence", "recordedAt", "recordedBy", "contentHash", "previousHash", "recordHash"],
)
def test_server_assigned_fields_are_rejected(post_event: PostEvent, field: str) -> None:
    body = _assert_problem(post_event(**{field: "client-value"}), 422)
    assert body["detail"] == f"{field}: field is not accepted"


def test_unknown_field_is_rejected(post_event: PostEvent, app_engine: Engine) -> None:
    _assert_problem(post_event(extra="value"), 422)
    assert _count_records(app_engine) == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"payload": ["not", "an", "object"]},
        {"payload": None},
        {"eventType": "order_placed"},
        {"resourceType": "A" * 65},
        {"actorId": ""},
        {"resourceId": "r" * 257},
        {"actorId": 7},
        {"timestamp": "2026-09-28T16:00:00"},
        {"timestamp": "2026-09-28T16:00:00.1234567Z"},
        {"timestamp": "not a time"},
        {"payload": {"n": 1e16}},
        {"payload": {"n": 9007199254740992}},
        {"payload": {"n": -1e300}},
        {"payload": {"text": "nul\x00"}},
    ],
    ids=[
        "payload-array",
        "payload-null",
        "event-type-pattern",
        "resource-type-length",
        "empty-actor",
        "resource-id-length",
        "actor-not-string",
        "timestamp-without-offset",
        "timestamp-seven-digits",
        "timestamp-garbage",
        "number-1e16",
        "number-2^53",
        "number-negative-huge",
        "nul-character",
    ],
)
def test_invalid_events_are_rejected_and_not_stored(
    post_event: PostEvent, app_engine: Engine, changes: dict[str, Any]
) -> None:
    _assert_problem(post_event(**changes), 422)
    assert _count_records(app_engine) == 0


def test_largest_safe_integer_is_accepted(post_event: PostEvent) -> None:
    response = post_event(payload={"n": 9007199254740991})
    assert response.json()["payload"] == {"n": 9007199254740991}


@pytest.mark.parametrize(
    ("raw", "status"),
    [
        (b"{not json", 400),
        (b"", 400),
        (b'{"n": NaN}', 400),
        (b"\xff\xfe{}", 400),
        (b'{"eventType": "A", "eventType": "B"}', 422),
        (b'{"payload": {"k": 1, "k": 2}}', 422),
        (b"[" * 20000 + b"]" * 20000, 422),
    ],
    ids=[
        "syntax",
        "empty",
        "nan-literal",
        "invalid-utf8",
        "duplicate-top-level-key",
        "duplicate-nested-key",
        "hostile-nesting",
    ],
)
def test_body_parsing_errors(
    client: httpx.Client, writer: Headers, raw: bytes, status: int
) -> None:
    response = client.post(
        "/audit/events", content=raw, headers={**writer, "Content-Type": "application/json"}
    )
    _assert_problem(response, status)


def test_escaped_lone_surrogate_is_rejected(client: httpx.Client, writer: Headers) -> None:
    raw = json.dumps(_body(payload={"k": "PLACEHOLDER"})).replace(
        "PLACEHOLDER", chr(0x5C) + "ud800"
    )
    response = client.post(
        "/audit/events",
        content=raw.encode(),
        headers={**writer, "Content-Type": "application/json"},
    )
    _assert_problem(response, 422)


@pytest.mark.parametrize(
    "content_type", [None, "text/plain", "application/xml", "application/json-seq"]
)
def test_non_json_content_type_is_415(
    client: httpx.Client, writer: Headers, content_type: str | None
) -> None:
    headers = dict(writer)
    if content_type is not None:
        headers["Content-Type"] = content_type
    response = client.post("/audit/events", content=json.dumps(_body()).encode(), headers=headers)
    _assert_problem(response, 415)


def test_body_over_64_kib_is_413(client: httpx.Client, writer: Headers, app_engine: Engine) -> None:
    oversized = json.dumps(_body(payload={"filler": "x" * (64 * 1024)})).encode()
    response = client.post(
        "/audit/events", content=oversized, headers={**writer, "Content-Type": "application/json"}
    )
    _assert_problem(response, 413)
    assert _count_records(app_engine) == 0


def test_body_just_under_64_kib_is_accepted(client: httpx.Client, writer: Headers) -> None:
    base = len(json.dumps(_body(payload={"filler": ""})).encode())
    body = json.dumps(_body(payload={"filler": "x" * (64 * 1024 - base)})).encode()
    assert len(body) == 64 * 1024
    response = client.post(
        "/audit/events", content=body, headers={**writer, "Content-Type": "application/json"}
    )
    assert response.status_code == 201


# --- Persistence and integrity ----------------------------------------------------------------


def test_response_matches_the_persisted_record(post_event: PostEvent, load: Load) -> None:
    body = post_event(timestamp="2026-09-28T16:00:00Z").json()

    [entry] = load()
    record = entry.record
    assert (body["id"], body["sequence"]) == (record.content.id, record.sequence)
    assert (body["contentHash"], body["previousHash"], body["recordHash"]) == (
        record.content_hash,
        record.previous_hash,
        record.record_hash,
    )
    assert (body["recordedAt"], body["timestamp"]) == (
        record.content.recorded_at,
        record.content.timestamp,
    )
    assert verify_chain([entry]).intact


def test_get_returns_exactly_what_post_returned(
    client: httpx.Client, post_event: PostEvent, auditor: Headers
) -> None:
    created = post_event(payload={"n": 1.0, "nested": {"list": [True, None, "x"]}, "empty": {}})

    fetched = client.get(created.headers["location"], headers=auditor)

    assert fetched.status_code == 200
    assert fetched.json() == created.json()
    assert fetched.json()["payload"] == {"n": 1, "nested": {"list": [True, None, "x"]}, "empty": {}}


def test_identical_posts_create_distinct_records(post_event: PostEvent) -> None:
    first, second = post_event().json(), post_event().json()

    assert first["id"] != second["id"]
    assert (first["sequence"], second["sequence"]) == (1, 2)
    assert first["contentHash"] != second["contentHash"]


def test_chain_verifies_after_many_posts(post_event: PostEvent, load: Load) -> None:
    for index in range(8):
        assert post_event(actorId=f"user-{index}", payload={"i": index}).status_code == 201

    result = verify_chain(load())
    assert result.intact
    assert result.records_checked == 8


def test_responses_never_expose_commitment_storage(
    client: httpx.Client, post_event: PostEvent, load: Load, auditor: Headers
) -> None:
    created = post_event(payload={"card": "4111-1111"})
    fetched = client.get(created.headers["location"], headers=auditor)

    salts = [value.salt for entry in load() for value in entry.payload_values.values()]
    for response in (created, fetched):
        assert not {"salt", "canonical_value", "pointer", "committed_payload"} & set(
            response.json()
        )
        assert all(salt not in response.text for salt in salts)


# --- GET ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "event_id",
    [str(uuid.uuid4()), "not-a-uuid", "1234", "%00"],
    ids=["unknown", "text", "number", "nul"],
)
def test_unknown_or_invalid_identifier_is_404(
    client: httpx.Client, auditor: Headers, event_id: str
) -> None:
    body = _assert_problem(client.get(f"/audit/events/{event_id}", headers=auditor), 404)
    assert body["detail"] == "No audit event has this identifier."


def test_uppercase_identifier_finds_the_event(
    client: httpx.Client, post_event: PostEvent, auditor: Headers
) -> None:
    event_id = post_event().json()["id"]
    assert client.get(f"/audit/events/{event_id.upper()}", headers=auditor).json()["id"] == event_id


# --- Request identifiers, routing, and disclosure -----------------------------------------------


def test_every_response_has_a_fresh_server_request_id(
    client: httpx.Client, post_event: PostEvent
) -> None:
    supplied = "caller-chosen-id"
    responses = [
        post_event(),
        client.get("/audit/events/x", headers={"X-Request-ID": supplied}),
        client.post("/audit/events", headers={"X-Request-ID": supplied}),
    ]
    request_ids = [response.headers["x-request-id"] for response in responses]

    assert all(UUID_TEXT.fullmatch(request_id) for request_id in request_ids)
    assert len(set(request_ids)) == 3
    assert supplied not in str(request_ids)


def test_unknown_route_and_method_are_problem_details(
    client: httpx.Client, auditor: Headers
) -> None:
    _assert_problem(client.get("/audit/unknown", headers=auditor), 404)
    response = client.delete(f"/audit/events/{uuid.uuid4()}", headers=auditor)
    _assert_problem(response, 405)
    assert response.headers["allow"] == "GET"


def test_validation_errors_do_not_echo_submitted_values(post_event: PostEvent) -> None:
    secret = "4111-1111-1111-1111"
    responses = [
        post_event(payload={"card": secret, "n": 1e16}),
        post_event(**{secret: "x"}),
        post_event(actorId=secret + "\x00"),
        post_event(timestamp=secret),
    ]
    for response in responses:
        assert response.status_code == 422
        assert secret not in response.text


def test_problem_responses_do_not_expose_credentials_or_hashes(
    client: httpx.Client, api_key_configuration: Any
) -> None:
    key_hash_hex = api_key_configuration.principals[0].key_digests[0].hex()
    for response in (
        client.post("/audit/events", headers={"Authorization": f"Bearer {key_hash_hex}"}),
        client.post("/audit/events", headers={"Authorization": "Bearer test-only-writer-key"}),
    ):
        assert key_hash_hex not in response.text
        assert "test-only-writer-key" not in response.text


# --- Property ---------------------------------------------------------------------------------

_KEYS = st.text(
    alphabet=st.characters(exclude_categories=("Cs",), exclude_characters="\x00"), max_size=8
)
_VALUES = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**53 - 1), max_value=2**53 - 1)
    | st.floats(min_value=-(2**53 - 1), max_value=2**53 - 1, allow_nan=False)
    | _KEYS,
    lambda children: st.lists(children, max_size=3) | st.dictionaries(_KEYS, children, max_size=3),
    max_leaves=10,
)


@settings(
    max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(payload=st.dictionaries(_KEYS, _VALUES, max_size=4))
def test_any_valid_payload_round_trips_through_the_api(
    client: httpx.Client, writer: Headers, auditor: Headers, payload: dict[str, Any]
) -> None:
    created = client.post("/audit/events", json=_body(payload=payload), headers=writer)
    assert created.status_code == 201
    fetched = client.get(created.headers["location"], headers=auditor)

    assert fetched.json() == created.json()
    # Numbers come back in their canonical JSON form (for example 1.0 as 1).
    assert canonicalize(created.json()["payload"]) == canonicalize(payload)


def test_streamed_body_over_64_kib_is_413(client: httpx.Client, writer: Headers) -> None:
    # A chunked upload carries no Content-Length, so the limit is enforced while reading.
    def chunks() -> Iterator[bytes]:
        for _ in range(17):
            yield b" " * 4096

    response = client.post(
        "/audit/events", content=chunks(), headers={**writer, "Content-Type": "application/json"}
    )
    assert "content-length" not in response.request.headers
    _assert_problem(response, 413)
