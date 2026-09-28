"""Unit tests for event submission validation (FR-1, FR-8, Phase 5 decisions C1, C3, D1)."""

from types import MappingProxyType
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from audit_log_service.application.events import (
    MAX_PAYLOAD_DEPTH,
    SERVER_ASSIGNED_FIELDS,
    SubmissionError,
    parse_submission,
    prepare_event,
)
from audit_log_service.config.vocabulary import ClientAccountVocabulary

VOCABULARY = ClientAccountVocabulary(
    resource_type="CLIENT_ACCOUNT",
    required_payload_keys=MappingProxyType(
        {"CLIENT_ACCOUNT_VIEWED": frozenset({"purpose", "channel"})}
    ),
)
VALID: dict[str, Any] = {
    "eventType": "ORDER_PLACED",
    "actorId": "user-7",
    "resourceType": "ORDER",
    "resourceId": "order-1",
    "payload": {"amount": 10},
}


def _prepare(**changes: Any) -> Any:
    document = {**VALID, **changes}
    return prepare_event(parse_submission(document), "svc-writer", VOCABULARY)


def _rejected(document: object) -> str:
    with pytest.raises(SubmissionError) as caught:
        prepare_event(parse_submission(document), "svc-writer", VOCABULARY)
    return str(caught.value)


def test_valid_submission_becomes_a_new_event() -> None:
    event = _prepare()

    assert (event.event_type, event.actor_id, event.resource_type, event.resource_id) == (
        "ORDER_PLACED",
        "user-7",
        "ORDER",
        "order-1",
    )
    assert event.recorded_by == "svc-writer"
    assert event.timestamp is None
    assert event.payload == {"amount": 10}


@pytest.mark.parametrize("field", ["eventType", "actorId", "resourceType", "resourceId", "payload"])
def test_every_field_except_timestamp_is_required(field: str) -> None:
    document = {key: value for key, value in VALID.items() if key != field}
    assert field in _rejected(document)


@pytest.mark.parametrize("field", sorted(SERVER_ASSIGNED_FIELDS))
def test_server_assigned_fields_are_rejected(field: str) -> None:
    assert f"{field}: field is not accepted" in _rejected({**VALID, field: "x"})


def test_unknown_field_is_rejected_without_echoing_its_name() -> None:
    message = _rejected({**VALID, "secret-looking-name": 1})
    assert "an unknown field: field is not accepted" in message
    assert "secret-looking-name" not in message


@pytest.mark.parametrize(
    "document", [[], "text", None, 7], ids=["array", "string", "null", "number"]
)
def test_body_must_be_an_object(document: object) -> None:
    _rejected(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("eventType", "order_placed"),
        ("eventType", "1ORDER"),
        ("eventType", "A" * 65),
        ("eventType", ""),
        ("resourceType", "Order"),
        ("resourceType", "ORDER-TYPE"),
        ("actorId", ""),
        ("actorId", "a" * 257),
        ("resourceId", ""),
        ("resourceId", "r" * 257),
        ("eventType", 7),
        ("actorId", ["user"]),
        ("timestamp", 1_700_000_000),
        ("payload", ["not", "an", "object"]),
        ("payload", "text"),
    ],
)
def test_field_constraints(field: str, value: object) -> None:
    assert field in _rejected({**VALID, field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [("eventType", "A" * 64), ("actorId", "a" * 256), ("resourceId", "r" * 256)],
)
def test_limits_are_inclusive(field: str, value: str) -> None:
    _prepare(**{field: value})


@pytest.mark.parametrize("event_type", ["AUDIT_LOG_RETENTION", "AUDIT_LOG_"])
def test_reserved_namespace_is_rejected(event_type: str) -> None:
    assert "reserved" in _rejected({**VALID, "eventType": event_type})


def test_reserved_namespace_is_rejected_for_client_accounts_too() -> None:
    document = {**VALID, "eventType": "AUDIT_LOG_REDACTION", "resourceType": "CLIENT_ACCOUNT"}
    assert "reserved" in _rejected(document)


# --- Scenario C (FR-8, C3) -------------------------------------------------------------------


def test_client_account_event_with_configured_type_and_keys_is_accepted() -> None:
    _prepare(
        eventType="CLIENT_ACCOUNT_VIEWED",
        resourceType="CLIENT_ACCOUNT",
        payload={"purpose": "kyc", "channel": "web", "extra": True},
    )


def test_client_account_event_type_must_be_in_the_vocabulary() -> None:
    document = {**VALID, "eventType": "CLIENT_ACCOUNT_SOLD", "resourceType": "CLIENT_ACCOUNT"}
    assert "vocabulary" in _rejected(document)


def test_client_account_event_must_have_the_required_keys() -> None:
    document = {
        **VALID,
        "eventType": "CLIENT_ACCOUNT_VIEWED",
        "resourceType": "CLIENT_ACCOUNT",
        "payload": {"purpose": "kyc"},
    }
    assert "required" in _rejected(document)


def test_other_resource_types_are_not_checked_against_the_vocabulary() -> None:
    _prepare(eventType="CLIENT_ACCOUNT_SOLD", resourceType="ORDER", payload={})


# --- Timestamps -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("submitted", "canonical"),
    [
        ("2026-09-28T16:00:00Z", "2026-09-28T16:00:00.000000Z"),
        ("2026-09-28T16:00:00.5Z", "2026-09-28T16:00:00.500000Z"),
        ("2026-09-28T18:30:00.123456+02:30", "2026-09-28T16:00:00.123456Z"),
        ("2026-09-28t16:00:00z", "2026-09-28T16:00:00.000000Z"),
        ("2026-09-28T16:00:00-00:00", "2026-09-28T16:00:00.000000Z"),
        ("1900-01-01T00:00:00Z", "1900-01-01T00:00:00.000000Z"),
    ],
)
def test_timestamps_are_normalized_to_canonical_utc(submitted: str, canonical: str) -> None:
    assert _prepare(timestamp=submitted).timestamp == canonical


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-09-28T16:00:00",
        "2026-09-28T16:00:00.1234567Z",
        "2026-09-28 16:00:00Z",
        "2026-02-30T16:00:00Z",
        "2026-09-28T24:00:00Z",
        "2026-09-28T16:00:60Z",
        "2026-09-28T16:00:00+24:00",
        "0001-01-01T00:00:00+01:00",
        "9999-12-31T23:59:59-01:00",
        "28/09/2026",
        "",
    ],
)
def test_invalid_timestamps_are_rejected(timestamp: str) -> None:
    message = _rejected({**VALID, "timestamp": timestamp})
    assert "timestamp" in message
    assert timestamp == "" or timestamp not in message


# --- Payload ----------------------------------------------------------------------------------


def _nested(depth: int) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for _ in range(depth - 1):
        payload = {"n": payload}
    return payload


def test_payload_depth_limit_is_inclusive() -> None:
    _prepare(payload=_nested(MAX_PAYLOAD_DEPTH))
    assert "nested" in _rejected({**VALID, "payload": _nested(MAX_PAYLOAD_DEPTH + 1)})


def test_arrays_count_toward_depth() -> None:
    # The payload object is level 1, so 31 nested lists reach the limit of 32.
    payload: Any = []
    for _ in range(MAX_PAYLOAD_DEPTH - 2):
        payload = [payload]
    _prepare(payload={"a": payload})
    assert "nested" in _rejected({**VALID, "payload": {"a": [payload]}})


@pytest.mark.parametrize(
    "value",
    [9007199254740992, -9007199254740992, 1e16, 9007199254740991.5, -1e300],
    ids=["int-above", "int-below", "1e16", "rounds-to-2^53", "-1e300"],
)
def test_numbers_outside_the_domain_are_rejected(value: float) -> None:
    message = _rejected({**VALID, "payload": {"n": [value]}})
    assert "numeric domain" in message
    assert str(value) not in message


def test_numbers_at_the_domain_bounds_are_accepted() -> None:
    _prepare(payload={"n": [9007199254740991, -9007199254740991, 9007199254740991.4, 0.5]})


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"actorId": "user\x00"}, "actorId"),
        ({"resourceId": "\x00"}, "resourceId"),
        ({"actorId": "user" + chr(0xD800)}, "actorId"),
        ({"payload": {"k": "value\x00"}}, "payload"),
        ({"payload": {"k\x00": 1}}, "payload"),
        ({"payload": {"k": ["ok", chr(0xDC00)]}}, "payload"),
        ({"payload": {chr(0xD83D): 1}}, "payload"),
    ],
    ids=[
        "nul-actor",
        "nul-resource",
        "surrogate-actor",
        "nul-value",
        "nul-key",
        "surrogate-value",
        "surrogate-key",
    ],
)
def test_unstorable_text_is_rejected(changes: dict[str, Any], message: str) -> None:
    assert message in _rejected({**VALID, **changes})


def test_error_messages_never_include_submitted_values() -> None:
    secret = "4111-1111-secret"
    for document in (
        {**VALID, "payload": {"card": secret, "n": 1e16}},
        {**VALID, "actorId": secret + "\x00"},
        {**VALID, "eventType": secret},
        {**VALID, "timestamp": secret},
    ):
        assert secret not in _rejected(document)


_json = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**53 - 1), max_value=2**53 - 1)
    | st.text(alphabet=st.characters(exclude_categories=("Cs",), exclude_characters="\x00")),
    lambda children: (
        st.lists(children, max_size=3)
        | st.dictionaries(
            st.text(max_size=5).filter(lambda k: "\x00" not in k), children, max_size=3
        )
    ),
    max_leaves=10,
)


@given(payload=st.dictionaries(st.text(max_size=5).filter(lambda k: "\x00" not in k), _json))
def test_any_valid_payload_is_accepted_unchanged(payload: dict[str, Any]) -> None:
    assert _prepare(payload=payload).payload == payload
