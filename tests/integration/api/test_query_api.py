"""API tests for GET /audit/events (FR-2) against real PostgreSQL."""

from collections.abc import Callable
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine

from audit_log_service.integrity.hashing import AuditRecord
from audit_log_service.integrity.timestamps import parse_timestamp
from audit_log_service.integrity.verification import ChainEntry, verify_chain
from audit_log_service.persistence.audit_log import NewEvent, append_event

Headers = dict[str, str]
Params = list[tuple[str, str]] | dict[str, str]
Seed = Callable[..., list[AuditRecord]]
Load = Callable[[], list[ChainEntry]]

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


@pytest.fixture
def seed(app_engine: Engine, new_event: Callable[..., NewEvent]) -> Seed:
    """Append `count` events in one transaction, as the application role."""

    def run(count: int = 1, **changes: Any) -> list[AuditRecord]:
        with app_engine.begin() as connection:
            return [append_event(connection, new_event(**changes)) for _ in range(count)]

    return run


@pytest.fixture
def query(client: httpx.Client, auditor: Headers) -> Callable[..., httpx.Response]:
    def run(params: Params | None = None) -> httpx.Response:
        pairs = list(params.items()) if isinstance(params, dict) else list(params or [])
        return client.get("/audit/events", params=tuple(pairs), headers=auditor)

    return run


Query = Callable[..., httpx.Response]


def _sequences(response: httpx.Response) -> list[int]:
    assert response.status_code == 200, response.text
    return [item["sequence"] for item in response.json()["items"]]


def _assert_problem(response: httpx.Response, status: int) -> dict[str, Any]:
    assert response.status_code == status
    assert response.headers["content-type"] == "application/problem+json"
    body: dict[str, Any] = response.json()
    assert body["requestId"] == response.headers["x-request-id"]
    return body


# --- Authentication and authorization ---------------------------------------------------------


def test_unauthenticated_query_is_401_before_validation(client: httpx.Client) -> None:
    response = client.get("/audit/events", params={"limit": "0", "unknown": "x"})
    assert _assert_problem(response, 401)["detail"] == "Valid Bearer credentials are required."
    assert response.headers["www-authenticate"] == "Bearer"


def test_writer_without_read_capability_is_403_before_validation(
    client: httpx.Client, writer: Headers
) -> None:
    _assert_problem(client.get("/audit/events", params={"limit": "0"}, headers=writer), 403)


@pytest.mark.parametrize("reader", ["auditor", "administrator"])
def test_readers_can_query(
    client: httpx.Client, request: pytest.FixtureRequest, reader: str
) -> None:
    headers: Headers = request.getfixturevalue(reader)
    assert client.get("/audit/events", headers=headers).status_code == 200


# --- Basic query and representation ----------------------------------------------------------


def test_empty_chain_returns_an_empty_page(query: Query) -> None:
    response = query()
    assert response.status_code == 200
    assert response.json() == {"items": [], "nextCursor": None}


def test_single_result_matches_the_single_event_representation(
    query: Query, post_event: Callable[..., httpx.Response]
) -> None:
    created = post_event(payload={"n": 1.0, "nested": {"x": [True, None]}}).json()

    body = query().json()

    assert set(body) == {"items", "nextCursor"}
    assert body["items"] == [created]
    assert set(body["items"][0]) == EVENT_FIELDS
    assert (body["items"][0]["redactedPaths"], body["items"][0]["archived"]) == ([], False)
    assert body["nextCursor"] is None


def test_results_are_in_ascending_sequence_order(query: Query, seed: Seed) -> None:
    seed(5)
    assert _sequences(query()) == [1, 2, 3, 4, 5]


def test_response_has_no_commitment_internals_or_total_count(
    query: Query, seed: Seed, load: Load
) -> None:
    seed(3, payload={"card": "4111-1111"})

    response = query()

    salts = [value.salt for entry in load() for value in entry.payload_values.values()]
    assert all(salt not in response.text for salt in salts)
    for forbidden in ("salt", "canonical_value", "pointer", "committed_payload", "total", "count"):
        assert f'"{forbidden}"' not in response.text


# --- Filters ------------------------------------------------------------------------------------


def test_actor_filter_is_an_exact_match(query: Query, seed: Seed) -> None:
    seed(2, actor_id="user-7")
    seed(1, actor_id="user-70")
    seed(1, actor_id="USER-7")

    assert _sequences(query({"actorId": "user-7"})) == [1, 2]


def test_event_type_filter(query: Query, seed: Seed) -> None:
    seed(1, event_type="ORDER_PLACED")
    seed(1, event_type="ORDER_SHIPPED")

    assert _sequences(query({"eventType": "ORDER_SHIPPED"})) == [2]


def test_resource_filters_are_independent(query: Query, seed: Seed) -> None:
    seed(1, resource_type="ORDER", resource_id="shared-id")
    seed(1, resource_type="INVOICE", resource_id="shared-id")
    seed(1, resource_type="ORDER", resource_id="other-id")

    assert _sequences(query({"resourceType": "ORDER"})) == [1, 3]
    assert _sequences(query({"resourceId": "shared-id"})) == [1, 2]
    assert _sequences(query({"resourceType": "ORDER", "resourceId": "shared-id"})) == [1]


def test_filters_combine_with_and(query: Query, seed: Seed) -> None:
    seed(1, actor_id="a", event_type="CLIENT_ACCOUNT_VIEWED", resource_type="CLIENT_ACCOUNT")
    seed(1, actor_id="a", event_type="CLIENT_ACCOUNT_UPDATED", resource_type="CLIENT_ACCOUNT")
    seed(1, actor_id="b", event_type="CLIENT_ACCOUNT_VIEWED", resource_type="CLIENT_ACCOUNT")

    params = {
        "actorId": "a",
        "eventType": "CLIENT_ACCOUNT_VIEWED",
        "resourceType": "CLIENT_ACCOUNT",
    }
    assert _sequences(query(params)) == [1]
    assert _sequences(query({"actorId": "nobody"})) == []


def test_query_filters_are_not_event_vocabulary_checks(query: Query, seed: Seed) -> None:
    # Querying an event type outside the Scenario C vocabulary is valid and simply matches nothing.
    seed(1, resource_type="CLIENT_ACCOUNT", event_type="CLIENT_ACCOUNT_VIEWED")
    assert _sequences(query({"resourceType": "CLIENT_ACCOUNT", "eventType": "UNLISTED"})) == []


# --- Time range ---------------------------------------------------------------------------------


def _expected(records: list[AuditRecord], lower: str | None, upper: str | None) -> list[int]:
    def included(record: AuditRecord) -> bool:
        moment = parse_timestamp(record.content.recorded_at)
        return (lower is None or moment >= parse_timestamp(lower)) and (
            upper is None or moment < parse_timestamp(upper)
        )

    return [record.sequence for record in records if included(record)]


def test_time_range_is_half_open_on_recorded_at(query: Query, seed: Seed) -> None:
    records = [seed(1)[0] for _ in range(5)]
    boundary = records[2].content.recorded_at

    at_or_after = _sequences(query({"from": boundary}))
    before = _sequences(query({"to": boundary}))

    assert 3 in at_or_after and 3 not in before
    assert at_or_after == _expected(records, boundary, None)
    assert before == _expected(records, None, boundary)
    assert sorted(at_or_after + before) == [1, 2, 3, 4, 5]


def test_from_and_to_together(query: Query, seed: Seed) -> None:
    records = [seed(1)[0] for _ in range(5)]
    lower, upper = records[1].content.recorded_at, records[3].content.recorded_at

    assert _sequences(query({"from": lower, "to": upper})) == _expected(records, lower, upper)


def test_time_range_accepts_offsets(query: Query, seed: Seed) -> None:
    record = seed(1)[0]
    moment = parse_timestamp(record.content.recorded_at)
    with_offset = moment.astimezone().isoformat()  # the same instant in the local offset

    assert _sequences(query({"from": with_offset})) == [1]


def test_equal_from_and_to_returns_an_empty_page(query: Query, seed: Seed) -> None:
    moment = seed(1)[0].content.recorded_at
    assert query({"from": moment, "to": moment}).json() == {"items": [], "nextCursor": None}


def test_from_after_to_is_rejected(query: Query) -> None:
    params = {"from": "2026-09-28T16:00:01Z", "to": "2026-09-28T16:00:00Z"}
    assert _assert_problem(query(params), 422)["detail"] == "from must not be later than to"


@pytest.mark.parametrize(
    "params",
    [
        {"from": "2026-09-28T16:00:00"},
        {"to": "2026-09-28"},
        {"from": "2026-09-28T16:00:00.1234567Z"},
        {"to": "not a time"},
    ],
)
def test_malformed_times_are_rejected(query: Query, params: dict[str, str]) -> None:
    _assert_problem(query(params), 422)


# --- includeArchived ----------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["true", "false"])
def test_include_archived_has_no_effect_before_retention(
    query: Query, seed: Seed, value: str
) -> None:
    seed(3)
    assert _sequences(query({"includeArchived": value})) == [1, 2, 3]


def test_include_archived_must_be_a_boolean(query: Query) -> None:
    _assert_problem(query({"includeArchived": "yes"}), 422)


# --- Pagination ---------------------------------------------------------------------------------


def test_default_page_is_50_with_a_cursor(query: Query, seed: Seed) -> None:
    seed(60)
    body = query().json()
    assert [item["sequence"] for item in body["items"]] == list(range(1, 51))
    assert isinstance(body["nextCursor"], str)


def test_maximum_page_is_200(query: Query, seed: Seed) -> None:
    seed(201)
    body = query({"limit": "200"}).json()
    assert len(body["items"]) == 200
    assert body["nextCursor"] is not None


@pytest.mark.parametrize("limit", ["0", "201", "-1", "abc", ""])
def test_out_of_range_limit_is_rejected(query: Query, limit: str) -> None:
    body = _assert_problem(query({"limit": limit}), 422)
    assert body["detail"] == "limit must be an integer from 1 to 200"


def test_paging_visits_every_record_once_in_order(query: Query, seed: Seed) -> None:
    seed(23)
    seen: list[int] = []
    cursor: str | None = None
    pages = 0
    while True:
        params = {"limit": "5"} if cursor is None else {"limit": "5", "cursor": cursor}
        body = query(params).json()
        seen += [item["sequence"] for item in body["items"]]
        pages += 1
        cursor = body["nextCursor"]
        if cursor is None:
            break

    assert seen == list(range(1, 24))
    assert pages == 5


def test_final_page_that_fills_the_limit_has_no_cursor(query: Query, seed: Seed) -> None:
    seed(4)
    first = query({"limit": "2"}).json()
    second = query({"limit": "2", "cursor": first["nextCursor"]}).json()

    assert [item["sequence"] for item in second["items"]] == [3, 4]
    assert second["nextCursor"] is None


def test_paging_with_filters_keeps_the_filters(query: Query, seed: Seed) -> None:
    for _ in range(4):
        seed(1, actor_id="a")
        seed(1, actor_id="b")

    first = query({"actorId": "b", "limit": "3"}).json()
    second = query({"actorId": "b", "limit": "3", "cursor": first["nextCursor"]}).json()

    assert [item["sequence"] for item in first["items"]] == [2, 4, 6]
    assert [item["sequence"] for item in second["items"]] == [8]
    assert second["nextCursor"] is None


def test_page_size_may_change_between_pages(query: Query, seed: Seed) -> None:
    seed(6)
    first = query({"limit": "2"}).json()
    assert _sequences(query({"limit": "4", "cursor": first["nextCursor"]})) == [3, 4, 5, 6]


def test_records_appended_between_pages_appear_later(query: Query, seed: Seed) -> None:
    seed(3)
    first = query({"limit": "2"}).json()
    seed(2)
    assert _sequences(query({"limit": "10", "cursor": first["nextCursor"]})) == [3, 4, 5]


@pytest.mark.parametrize(
    "other_filters",
    [
        {"actorId": "user-8"},
        {},
        {"eventType": "ORDER_PLACED", "actorId": "user-7"},
        {"includeArchived": "true", "actorId": "user-7"},
    ],
    ids=["other-actor", "no-filters", "added-filter", "include-archived"],
)
def test_cursor_cannot_be_reused_with_different_filters(
    query: Query, seed: Seed, other_filters: dict[str, str]
) -> None:
    seed(3, actor_id="user-7")
    cursor = query({"actorId": "user-7", "limit": "1"}).json()["nextCursor"]

    body = _assert_problem(query({**other_filters, "cursor": cursor}), 422)
    assert body["detail"] == "cursor was issued for a different set of filters"


@pytest.mark.parametrize("cursor", ["garbage!", "eyJ2IjoxfQ", "", "A" * 600])
def test_malformed_cursor_is_rejected(query: Query, cursor: str) -> None:
    assert _assert_problem(query({"cursor": cursor}), 422)["detail"] == "cursor is malformed"


# --- Unknown and repeated parameters, and disclosure --------------------------------------------


@pytest.mark.parametrize(
    "params",
    [[("sort", "desc")], [("offset", "5"), ("page", "2")], [("limit", "5"), ("limit", "6")]],
    ids=["unknown", "several-unknown", "repeated"],
)
def test_unknown_or_repeated_parameters_are_rejected(query: Query, params: Params) -> None:
    _assert_problem(query(params), 422)


def test_errors_do_not_echo_submitted_values(query: Query) -> None:
    secret = "4111-1111-1111-1111"
    for params in (
        {secret: "x"},
        {"actorId": secret + "\x00"},
        {"from": secret},
        {"cursor": secret},
        {"limit": secret},
    ):
        response = query(params)
        assert response.status_code == 422
        assert secret not in response.text


# --- Read-only behavior ---------------------------------------------------------------------------


def test_queries_do_not_change_records_or_the_chain(query: Query, seed: Seed, load: Load) -> None:
    seed(7)
    before = load()

    for params in ({}, {"limit": "3"}, {"actorId": "user-7"}, {"includeArchived": "true"}):
        assert query(params).status_code == 200

    after = load()
    assert after == before
    assert verify_chain(after).intact
