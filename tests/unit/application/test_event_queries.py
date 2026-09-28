"""Unit tests for query parameter validation and cursors (FR-2, Phase 6 decisions Q1 to Q3)."""

import base64
import json
from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from audit_log_service.application.queries import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    QueryError,
    encode_cursor,
    parse_query,
)

Params = list[tuple[str, str]]


def _error(parameters: Params) -> str:
    with pytest.raises(QueryError) as caught:
        parse_query(parameters)
    return str(caught.value)


def _raw_cursor(document: object) -> str:
    return base64.urlsafe_b64encode(json.dumps(document).encode()).rstrip(b"=").decode()


def test_no_parameters_means_no_filters_and_the_default_limit() -> None:
    query = parse_query([])

    assert query.limit == DEFAULT_LIMIT
    assert query.after_sequence == 0
    filters = query.filters
    assert (filters.actor_id, filters.event_type, filters.resource_type, filters.resource_id) == (
        None,
        None,
        None,
        None,
    )
    assert (filters.recorded_from, filters.recorded_to, filters.include_archived) == (
        None,
        None,
        False,
    )


def test_every_filter_is_parsed() -> None:
    query = parse_query(
        [
            ("from", "2026-09-28T18:00:00+02:00"),
            ("to", "2026-09-28T17:00:00.5Z"),
            ("actorId", "user-7"),
            ("eventType", "CLIENT_ACCOUNT_VIEWED"),
            ("resourceType", "CLIENT_ACCOUNT"),
            ("resourceId", "acct-42"),
            ("includeArchived", "true"),
            ("limit", "200"),
        ]
    )

    filters = query.filters
    assert filters.recorded_from == datetime(2026, 9, 28, 16, 0, tzinfo=UTC)
    assert filters.recorded_to == datetime(2026, 9, 28, 17, 0, 0, 500000, tzinfo=UTC)
    assert (filters.actor_id, filters.event_type) == ("user-7", "CLIENT_ACCOUNT_VIEWED")
    assert (filters.resource_type, filters.resource_id) == ("CLIENT_ACCOUNT", "acct-42")
    assert filters.include_archived is True
    assert query.limit == MAX_LIMIT


@pytest.mark.parametrize(
    "parameters",
    [[("resourceType", "ORDER")], [("resourceId", "order-1")]],
    ids=["type-only", "id-only"],
)
def test_resource_filters_are_independent(parameters: Params) -> None:
    parse_query(parameters)


def test_equal_from_and_to_is_valid() -> None:
    parse_query([("from", "2026-09-28T16:00:00Z"), ("to", "2026-09-28T18:00:00+02:00")])


def test_from_after_to_is_rejected() -> None:
    parameters = [("from", "2026-09-28T16:00:00.000001Z"), ("to", "2026-09-28T16:00:00Z")]
    assert _error(parameters) == "from must not be later than to"


@pytest.mark.parametrize(
    ("parameters", "field"),
    [
        ([("from", "2026-09-28T16:00:00")], "from"),
        ([("to", "yesterday")], "to"),
        ([("from", "2026-09-28T16:00:00.1234567Z")], "from"),
        ([("to", "2026-02-30T00:00:00Z")], "to"),
        ([("actorId", "")], "actorId"),
        ([("actorId", "a" * 257)], "actorId"),
        ([("actorId", "user\x00")], "actorId"),
        ([("resourceId", "")], "resourceId"),
        ([("resourceId", "r" * 257)], "resourceId"),
        ([("eventType", "lower_case")], "eventType"),
        ([("eventType", "")], "eventType"),
        ([("resourceType", "A" * 65)], "resourceType"),
        ([("includeArchived", "TRUE")], "includeArchived"),
        ([("includeArchived", "1")], "includeArchived"),
        ([("includeArchived", "")], "includeArchived"),
    ],
)
def test_invalid_filters_are_rejected(parameters: Params, field: str) -> None:
    assert _error(parameters).startswith(field)


def test_query_filters_do_not_apply_event_vocabulary_or_the_reserved_prefix() -> None:
    parse_query([("resourceType", "CLIENT_ACCOUNT"), ("eventType", "CLIENT_ACCOUNT_SOLD")])
    parse_query([("eventType", "AUDIT_LOG_RETENTION")])


@pytest.mark.parametrize("value", ["1", "50", "200"])
def test_limits_in_range(value: str) -> None:
    assert parse_query([("limit", value)]).limit == int(value)


@pytest.mark.parametrize("value", ["0", "201", "-1", "1.5", "", "abc", chr(0x665), "1e2", " 5"])
def test_limits_out_of_range_are_rejected(value: str) -> None:
    assert _error([("limit", value)]) == "limit must be an integer from 1 to 200"


@pytest.mark.parametrize(
    "parameters",
    [[("sort", "desc")], [("offset", "10"), ("page", "2")], [("ActorId", "x")], [("", "")]],
    ids=["one", "several", "wrong-case", "empty-name"],
)
def test_unknown_parameters_are_rejected_without_echo(parameters: Params) -> None:
    message = _error(parameters)
    assert message == "the query has an unsupported parameter"


def test_repeated_parameters_are_rejected() -> None:
    assert _error([("actorId", "a"), ("actorId", "b")]) == "actorId may be given only once"


def test_error_messages_do_not_echo_values() -> None:
    secret = "4111-1111-1111-1111"
    for parameters in (
        [("actorId", secret + "\x00")],
        [("from", secret)],
        [("limit", secret)],
        [("cursor", secret)],
        [("eventType", secret)],
    ):
        assert secret not in _error(parameters)


# --- Cursors ----------------------------------------------------------------------------------


def test_cursor_round_trip_resumes_after_its_sequence() -> None:
    first = parse_query([("actorId", "user-7")])
    cursor = encode_cursor(41, first.filter_digest)

    resumed = parse_query([("actorId", "user-7"), ("cursor", cursor)])

    assert resumed.after_sequence == 41
    assert set(cursor) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def test_cursor_allows_a_different_page_size() -> None:
    cursor = encode_cursor(5, parse_query([("limit", "10")]).filter_digest)
    assert parse_query([("limit", "20"), ("cursor", cursor)]).after_sequence == 5


def test_equivalent_filters_share_a_digest() -> None:
    # Parameter order and time-zone notation do not change the filter set.
    first = parse_query([("from", "2026-09-28T18:00:00+02:00"), ("actorId", "a")])
    second = parse_query([("actorId", "a"), ("from", "2026-09-28T16:00:00.000000Z")])
    default = parse_query([("includeArchived", "false")])
    assert first.filter_digest == second.filter_digest
    assert default.filter_digest == parse_query([]).filter_digest


@pytest.mark.parametrize(
    "other",
    [
        [("actorId", "someone-else")],
        [],
        [("actorId", "user-7"), ("eventType", "ORDER_PLACED")],
        [("actorId", "user-7"), ("includeArchived", "true")],
        [("actorId", "user-7"), ("to", "2030-01-01T00:00:00Z")],
        [("resourceId", "user-7")],
    ],
    ids=["other-actor", "no-filters", "extra-filter", "include-archived", "extra-range", "moved"],
)
def test_cursor_cannot_be_reused_with_different_filters(other: Params) -> None:
    cursor = encode_cursor(3, parse_query([("actorId", "user-7")]).filter_digest)
    assert (
        _error([*other, ("cursor", cursor)]) == "cursor was issued for a different set of filters"
    )


_DIGEST = parse_query([]).filter_digest


@pytest.mark.parametrize(
    "cursor",
    [
        "not a cursor!",
        "",
        "A" * 513,
        "%%%",
        "abc",
        _raw_cursor([1, 2]),
        _raw_cursor({"v": 1, "after": 3}),
        _raw_cursor({"v": 1, "after": 3, "filters": _DIGEST, "extra": 1}),
        _raw_cursor({"v": 2, "after": 3, "filters": _DIGEST}),
        _raw_cursor({"v": True, "after": 3, "filters": _DIGEST}),
        _raw_cursor({"v": 1.0, "after": 3, "filters": _DIGEST}),
        _raw_cursor({"v": 1, "after": 0, "filters": _DIGEST}),
        _raw_cursor({"v": 1, "after": -5, "filters": _DIGEST}),
        _raw_cursor({"v": 1, "after": True, "filters": _DIGEST}),
        _raw_cursor({"v": 1, "after": 3.0, "filters": _DIGEST}),
        _raw_cursor({"v": 1, "after": "3", "filters": _DIGEST}),
        _raw_cursor({"v": 1, "after": 2**53, "filters": _DIGEST}),
        base64.urlsafe_b64encode(b"\xff\xfe").decode().rstrip("="),
    ],
    ids=[
        "punctuation",
        "empty",
        "too-long",
        "percent",
        "truncated",
        "not-object",
        "missing-key",
        "extra-key",
        "version-2",
        "version-bool",
        "version-float",
        "after-zero",
        "after-negative",
        "after-bool",
        "after-float",
        "after-string",
        "after-too-large",
        "not-utf8",
    ],
)
def test_malformed_cursors_are_rejected(cursor: str) -> None:
    assert _error([("cursor", cursor)]) == "cursor is malformed"


_ACTOR_IDS = st.text(
    alphabet=st.characters(exclude_categories=("Cs",), exclude_characters="\x00"),
    min_size=1,
    max_size=20,
)


@given(sequence=st.integers(min_value=1, max_value=2**53 - 1), actor=_ACTOR_IDS)
def test_any_issued_cursor_is_accepted_with_its_filters(sequence: int, actor: str) -> None:
    parameters = [("actorId", actor)]
    cursor = encode_cursor(sequence, parse_query(parameters).filter_digest)
    assert parse_query([*parameters, ("cursor", cursor)]).after_sequence == sequence
