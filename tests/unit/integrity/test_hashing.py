"""Tests for contentHash, recordHash, genesis, and record sealing."""

import dataclasses
import hashlib
from typing import Any

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from audit_log_service.integrity.canonical import MAX_SAFE_INTEGER
from audit_log_service.integrity.commitments import commit_payload
from audit_log_service.integrity.errors import IntegrityInputError
from audit_log_service.integrity.hashing import (
    GENESIS_PREVIOUS_HASH,
    EventContent,
    compute_content_hash,
    compute_record_hash,
    seal_record,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
COMMITMENT = "c" * 64

CONTENT = EventContent(
    id="0f8fad5b-d9cb-469f-a165-70867728950e",
    event_type="CLIENT_ACCOUNT_VIEWED",
    actor_id="user-7",
    resource_type="CLIENT_ACCOUNT",
    resource_id="acct-42",
    timestamp="2026-09-28T16:00:00.000000Z",
    recorded_at="2026-09-28T16:17:06.919000Z",
    recorded_by="svc-writer",
    payload={"channel": COMMITMENT},
)

# Alternative values for every covered field, each valid on its own.
FIELD_CHANGES: dict[str, Any] = {
    "id": "0f8fad5b-d9cb-469f-a165-70867728950f",
    "event_type": "CLIENT_ACCOUNT_UPDATED",
    "actor_id": "user-8",
    "resource_type": "CLIENT_PROFILE",
    "resource_id": "acct-43",
    "timestamp": None,
    "recorded_at": "2026-09-28T16:17:06.919001Z",
    "recorded_by": "svc-other",
    "payload": {"channel": "d" * 64},
}

_hashes = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
_sequences = st.integers(min_value=1, max_value=MAX_SAFE_INTEGER)


def test_every_covered_field_has_a_change_case() -> None:
    assert set(FIELD_CHANGES) == {f.name for f in dataclasses.fields(EventContent)}


def test_content_hash_formula() -> None:
    expected_input = (
        b"audit-log/v1/content\x00"
        b'{"actorId":"user-7","eventType":"CLIENT_ACCOUNT_VIEWED",'
        b'"id":"0f8fad5b-d9cb-469f-a165-70867728950e",'
        b'"payload":{"channel":"' + COMMITMENT.encode() + b'"},'
        b'"recordedAt":"2026-09-28T16:17:06.919000Z","recordedBy":"svc-writer",'
        b'"resourceId":"acct-42","resourceType":"CLIENT_ACCOUNT",'
        b'"timestamp":"2026-09-28T16:00:00.000000Z"}'
    )

    assert compute_content_hash(CONTENT) == hashlib.sha256(expected_input).hexdigest()


def test_absent_timestamp_is_hashed_as_null() -> None:
    content = dataclasses.replace(CONTENT, timestamp=None, payload={})
    expected_input = (
        b"audit-log/v1/content\x00"
        b'{"actorId":"user-7","eventType":"CLIENT_ACCOUNT_VIEWED",'
        b'"id":"0f8fad5b-d9cb-469f-a165-70867728950e","payload":{},'
        b'"recordedAt":"2026-09-28T16:17:06.919000Z","recordedBy":"svc-writer",'
        b'"resourceId":"acct-42","resourceType":"CLIENT_ACCOUNT","timestamp":null}'
    )

    assert compute_content_hash(content) == hashlib.sha256(expected_input).hexdigest()


@pytest.mark.parametrize(("field_name", "new_value"), FIELD_CHANGES.items())
def test_changing_any_covered_field_changes_the_content_hash(
    field_name: str, new_value: Any
) -> None:
    changed = dataclasses.replace(CONTENT, **{field_name: new_value})
    assert compute_content_hash(changed) != compute_content_hash(CONTENT)


@given(
    payload=st.dictionaries(
        st.text(max_size=5),
        st.one_of(st.none(), st.booleans(), st.integers(-100, 100), st.text(max_size=5)),
        max_size=3,
    )
)
def test_content_hash_is_deterministic_for_the_same_committed_payload(
    payload: dict[str, Any],
) -> None:
    content = dataclasses.replace(CONTENT, payload=commit_payload(payload).structure)
    assert compute_content_hash(content) == compute_content_hash(dataclasses.replace(content))


def test_same_payload_committed_twice_gives_different_content_hashes() -> None:
    # Fresh salts make the committed structures, and so the content hashes, differ.
    first = dataclasses.replace(CONTENT, payload=commit_payload({"a": 1}).structure)
    second = dataclasses.replace(CONTENT, payload=commit_payload({"a": 1}).structure)
    assert compute_content_hash(first) != compute_content_hash(second)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"id": "0F8FAD5B-D9CB-469F-A165-70867728950E"}, "UUID"),
        ({"id": "0f8fad5bd9cb469fa16570867728950e"}, "UUID"),
        ({"id": "{0f8fad5b-d9cb-469f-a165-70867728950e}"}, "UUID"),
        ({"timestamp": "2026-09-28T16:00:00Z"}, "timestamp"),
        ({"timestamp": "2026-09-28T16:00:00.000000+00:00"}, "timestamp"),
        ({"recorded_at": "2026-09-28T16:17:06.919Z"}, "recordedAt"),
        ({"event_type": 7}, "strings"),
        ({"payload": {"channel": "raw value"}}, "committed structure"),
        ({"payload": {"channel": COMMITMENT.upper()}}, "committed structure"),
        ({"payload": {"n": 5}}, "committed structure"),
        ({"payload": ["c" * 64]}, "committed structure"),
    ],
    ids=[
        "uppercase-uuid",
        "unhyphenated-uuid",
        "braced-uuid",
        "timestamp-without-fraction",
        "timestamp-with-offset",
        "recorded-at-milliseconds",
        "non-string-field",
        "raw-payload-value",
        "uppercase-commitment",
        "number-leaf",
        "array-payload",
    ],
)
def test_non_canonical_content_is_rejected(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(IntegrityInputError, match=message):
        compute_content_hash(dataclasses.replace(CONTENT, **changes))


def test_content_errors_do_not_echo_values() -> None:
    content = dataclasses.replace(CONTENT, payload={"channel": "4111-secret"})
    with pytest.raises(IntegrityInputError) as caught:
        compute_content_hash(content)
    assert "4111-secret" not in str(caught.value)


def test_record_hash_formula() -> None:
    expected_input = (
        b"audit-log/v1/record\x00"
        b'{"contentHash":"' + HASH_B.encode() + b'",'
        b'"previousHash":"' + GENESIS_PREVIOUS_HASH.encode() + b'","sequence":1}'
    )

    assert (
        compute_record_hash(1, GENESIS_PREVIOUS_HASH, HASH_B)
        == hashlib.sha256(expected_input).hexdigest()
    )


@given(sequence=_sequences, previous_hash=_hashes, content_hash=_hashes)
def test_record_hash_is_deterministic(sequence: int, previous_hash: str, content_hash: str) -> None:
    first = compute_record_hash(sequence, previous_hash, content_hash)
    assert compute_record_hash(sequence, previous_hash, content_hash) == first


@given(sequence=_sequences, other_sequence=_sequences, previous_hash=_hashes, content_hash=_hashes)
def test_different_sequence_gives_different_record_hash(
    sequence: int, other_sequence: int, previous_hash: str, content_hash: str
) -> None:
    assume(sequence != other_sequence)
    assert compute_record_hash(sequence, previous_hash, content_hash) != compute_record_hash(
        other_sequence, previous_hash, content_hash
    )


@given(sequence=_sequences, previous_hash=_hashes, other_hash=_hashes, content_hash=_hashes)
def test_different_previous_or_content_hash_gives_different_record_hash(
    sequence: int, previous_hash: str, other_hash: str, content_hash: str
) -> None:
    assume(other_hash not in (previous_hash, content_hash))
    original = compute_record_hash(sequence, previous_hash, content_hash)

    assert compute_record_hash(sequence, other_hash, content_hash) != original
    assert compute_record_hash(sequence, previous_hash, other_hash) != original


def test_previous_and_content_hash_are_not_interchangeable() -> None:
    assert compute_record_hash(2, HASH_A, HASH_B) != compute_record_hash(2, HASH_B, HASH_A)


@pytest.mark.parametrize(
    ("sequence", "previous_hash", "content_hash"),
    [
        (0, HASH_A, HASH_B),
        (-1, HASH_A, HASH_B),
        (MAX_SAFE_INTEGER + 1, HASH_A, HASH_B),
        (True, HASH_A, HASH_B),
        (1.0, HASH_A, HASH_B),
        (1, HASH_A.upper(), HASH_B),
        (1, HASH_A[:-1], HASH_B),
        (1, HASH_A, HASH_B + "b"),
        (1, HASH_A, "z" * 64),
    ],
    ids=[
        "zero",
        "negative",
        "above-domain",
        "bool",
        "float",
        "uppercase-previous",
        "short-previous",
        "long-content",
        "non-hex-content",
    ],
)
def test_invalid_record_hash_inputs_are_rejected(
    sequence: Any, previous_hash: str, content_hash: str
) -> None:
    with pytest.raises(IntegrityInputError):
        compute_record_hash(sequence, previous_hash, content_hash)


def test_genesis_is_64_zeros() -> None:
    assert GENESIS_PREVIOUS_HASH == "0" * 64


def test_seal_record_links_the_hashes() -> None:
    record = seal_record(CONTENT, 1, GENESIS_PREVIOUS_HASH)

    assert record.content_hash == compute_content_hash(CONTENT)
    assert record.record_hash == compute_record_hash(1, GENESIS_PREVIOUS_HASH, record.content_hash)
    assert record.previous_hash == GENESIS_PREVIOUS_HASH


def test_record_repr_does_not_expose_protected_fields() -> None:
    text = repr(seal_record(CONTENT, 1, GENESIS_PREVIOUS_HASH))

    for protected in ("user-7", "acct-42", "svc-writer", "channel", COMMITMENT):
        assert protected not in text
