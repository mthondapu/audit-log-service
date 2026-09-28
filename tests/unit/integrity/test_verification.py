"""Tests for pure chain verification."""

import dataclasses
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from audit_log_service.integrity.canonical import MAX_SAFE_INTEGER, JsonValue
from audit_log_service.integrity.commitments import PayloadValue, commit_payload
from audit_log_service.integrity.hashing import (
    GENESIS_PREVIOUS_HASH,
    AuditRecord,
    EventContent,
    compute_content_hash,
    seal_record,
)
from audit_log_service.integrity.timestamps import format_timestamp
from audit_log_service.integrity.verification import (
    ChainEntry,
    ChainHead,
    VerificationResult,
    Violation,
    ViolationType,
    verify_chain,
)

V = ViolationType
BASE_TIME = datetime(2026, 9, 28, 16, 0, tzinfo=UTC)
OTHER_HASH = "e" * 64

_payloads = st.dictionaries(
    st.text(max_size=6),
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(-1000, 1000),
        st.text(max_size=8),
        st.lists(st.integers(-5, 5), max_size=3),
    ),
    max_size=3,
)


def _content(index: int, payload: dict[str, JsonValue], recorded_at: str) -> EventContent:
    return EventContent(
        id=str(uuid.UUID(int=index)),
        event_type="CLIENT_ACCOUNT_VIEWED",
        actor_id=f"sensitive-actor-{index}",
        resource_type="CLIENT_ACCOUNT",
        resource_id=f"sensitive-resource-{index}",
        timestamp=None,
        recorded_at=recorded_at,
        recorded_by="sensitive-principal",
        payload=payload,
    )


def build_chain(
    payloads: list[dict[str, Any]], recorded_ats: list[str] | None = None
) -> list[ChainEntry]:
    entries: list[ChainEntry] = []
    previous_hash = GENESIS_PREVIOUS_HASH
    for index, payload in enumerate(payloads, start=1):
        committed = commit_payload(payload)
        recorded_at = (
            recorded_ats[index - 1]
            if recorded_ats
            else format_timestamp(BASE_TIME + timedelta(seconds=index))
        )
        record = seal_record(
            _content(index, committed.structure, recorded_at), index, previous_hash
        )
        entries.append(ChainEntry(record=record, payload_values=committed.values))
        previous_hash = record.record_hash
    return entries


def replace_record(entries: list[ChainEntry], position: int, **changes: Any) -> list[ChainEntry]:
    """Change stored record fields without recomputing any hash."""
    tampered = list(entries)
    entry = tampered[position]
    tampered[position] = dataclasses.replace(
        entry, record=dataclasses.replace(entry.record, **changes)
    )
    return tampered


def replace_content(entries: list[ChainEntry], position: int, **changes: Any) -> list[ChainEntry]:
    record = entries[position].record
    return replace_record(entries, position, content=dataclasses.replace(record.content, **changes))


def reseal(entries: list[ChainEntry], position: int, **content_changes: Any) -> list[ChainEntry]:
    """Change content and recompute this record's hashes, as an attacker with write access could."""
    tampered = list(entries)
    record = tampered[position].record
    content = dataclasses.replace(record.content, **content_changes)
    resealed = seal_record(content, record.sequence, record.previous_hash)
    tampered[position] = dataclasses.replace(tampered[position], record=resealed)
    return tampered


def first(result: VerificationResult) -> tuple[ViolationType, int] | None:
    violation = result.first_violation
    return None if violation is None else (violation.type, violation.sequence)


def test_violation_types_are_the_approved_phase_3_set_in_precedence_order() -> None:
    assert list(ViolationType) == [
        "SEQUENCE_DUPLICATE",
        "SEQUENCE_GAP",
        "GENESIS_MISMATCH",
        "PREVIOUS_HASH_MISMATCH",
        "CONTENT_HASH_MISMATCH",
        "PAYLOAD_VALUE_MISMATCH",
        "RECORD_HASH_MISMATCH",
        "RECORDED_AT_REGRESSION",
    ]


def test_empty_chain_is_intact() -> None:
    assert verify_chain([]) == VerificationResult(
        intact=True, records_checked=0, head=None, violation_count=0, first_violation=None
    )


@given(payloads=st.lists(_payloads, min_size=1, max_size=6))
def test_valid_chain_verifies(payloads: list[dict[str, Any]]) -> None:
    entries = build_chain(payloads)

    result = verify_chain(entries)

    assert result.intact
    assert result.violation_count == 0
    assert result.records_checked == len(entries)
    last = entries[-1].record
    assert result.head == ChainHead(sequence=last.sequence, record_hash=last.record_hash)


# --- One violation type at a time -------------------------------------------------------------


def test_genesis_mismatch() -> None:
    entries = reseal(build_chain([{}]), 0)
    entries = replace_record(entries, 0, previous_hash=OTHER_HASH)

    assert first(verify_chain(entries)) == (V.GENESIS_MISMATCH, 1)


def test_first_record_other_than_sequence_1_is_a_gap() -> None:
    entries = build_chain([{}, {}, {}])[1:]

    result = verify_chain(entries)

    assert first(result) == (V.SEQUENCE_GAP, 2)
    assert result.violation_count == 1


def test_middle_deletion_is_a_gap() -> None:
    entries = build_chain([{}, {}, {}, {}])
    del entries[1]

    result = verify_chain(entries)

    assert first(result) == (V.SEQUENCE_GAP, 3)
    assert result.violation_count == 1


def test_duplicate_sequence() -> None:
    entries = build_chain([{}, {}, {}])
    entries.insert(2, entries[1])

    result = verify_chain(entries)

    assert first(result) == (V.SEQUENCE_DUPLICATE, 2)
    assert result.violation_count == 1


def test_reordering_is_detected() -> None:
    entries = build_chain([{}, {}, {}, {}])
    entries[1], entries[2] = entries[2], entries[1]

    result = verify_chain(entries)

    assert first(result) == (V.SEQUENCE_GAP, 3)
    assert result.violation_count == 3


def test_forged_insertion_is_detected() -> None:
    entries = build_chain([{}, {}, {}])
    # A well-formed forgery linked to record 1 passes on its own; the displaced original record 2
    # then duplicates its sequence.
    recorded_at = format_timestamp(BASE_TIME + timedelta(seconds=1, microseconds=1))
    forged = seal_record(_content(99, {}, recorded_at), 2, entries[0].record.record_hash)
    entries.insert(1, ChainEntry(record=forged))

    result = verify_chain(entries)

    assert first(result) == (V.SEQUENCE_DUPLICATE, 2)
    assert result.violation_count == 1


def test_previous_hash_mismatch() -> None:
    entries = build_chain([{}, {}])
    entries = replace_record(entries, 1, previous_hash=OTHER_HASH)

    assert first(verify_chain(entries)) == (V.PREVIOUS_HASH_MISMATCH, 2)


# Tamper values for each covered field; each keeps the content otherwise valid.
COVERED_FIELD_TAMPERS: dict[str, Any] = {
    "id": str(uuid.UUID(int=999)),
    "event_type": "CLIENT_ACCOUNT_DELETED",
    "actor_id": "someone-else",
    "resource_type": "OTHER",
    "resource_id": "other-resource",
    "timestamp": "2020-01-01T00:00:00.000000Z",
    "recorded_at": "2026-09-28T16:00:01.000001Z",
    "recorded_by": "svc-other",
    "payload": {"field": OTHER_HASH},
}


def test_every_covered_field_has_a_tamper_case() -> None:
    assert set(COVERED_FIELD_TAMPERS) == {f.name for f in dataclasses.fields(EventContent)}


@pytest.mark.parametrize(("field_name", "value"), COVERED_FIELD_TAMPERS.items())
def test_tampering_one_covered_field_is_a_content_hash_mismatch(
    field_name: str, value: Any
) -> None:
    entries = build_chain([{"field": "a"}, {"field": "b"}, {"field": "c"}])
    entries = replace_content(entries, 1, **{field_name: value})

    result = verify_chain(entries)

    assert first(result) == (V.CONTENT_HASH_MISMATCH, 2)
    assert result.violation_count == 1


def test_changed_payload_value_is_a_payload_value_mismatch() -> None:
    entries = build_chain([{"amount": 10}, {"amount": 20}])
    stored = entries[1].payload_values["/amount"]
    tampered_values = {"/amount": PayloadValue(canonical_text="99", salt=stored.salt)}
    entries[1] = dataclasses.replace(entries[1], payload_values=tampered_values)

    result = verify_chain(entries)

    assert first(result) == (V.PAYLOAD_VALUE_MISMATCH, 2)
    assert result.violation_count == 1


def test_record_hash_mismatch() -> None:
    entries = build_chain([{}, {}])
    entries = replace_record(entries, 1, record_hash=OTHER_HASH)

    assert first(verify_chain(entries)) == (V.RECORD_HASH_MISMATCH, 2)


def test_recorded_at_regression() -> None:
    times = ["2026-09-28T16:00:02.000000Z", "2026-09-28T16:00:01.999999Z"]
    entries = build_chain([{}, {}], recorded_ats=times)

    assert first(verify_chain(entries)) == (V.RECORDED_AT_REGRESSION, 2)


def test_equal_recorded_at_is_valid() -> None:
    times = ["2026-09-28T16:00:02.000000Z"] * 3
    assert verify_chain(build_chain([{}, {}, {}], recorded_ats=times)).intact


@pytest.mark.parametrize(
    ("field_name", "expected"),
    [
        ("previous_hash", V.PREVIOUS_HASH_MISMATCH),
        ("content_hash", V.CONTENT_HASH_MISMATCH),
        ("record_hash", V.RECORD_HASH_MISMATCH),
    ],
)
def test_uppercase_stored_hash_is_a_mismatch(field_name: str, expected: ViolationType) -> None:
    entries = build_chain([{}, {}])
    stored = getattr(entries[1].record, field_name)
    entries = replace_record(entries, 1, **{field_name: stored.upper()})

    assert first(verify_chain(entries)) == (expected, 2)


def test_malformed_genesis_previous_hash_is_a_genesis_mismatch() -> None:
    entries = replace_record(build_chain([{}]), 0, previous_hash="0" * 63)
    assert first(verify_chain(entries)) == (V.GENESIS_MISMATCH, 1)


def test_sequence_beyond_the_numeric_domain_is_a_record_hash_mismatch() -> None:
    content = _content(1, {}, format_timestamp(BASE_TIME))
    head = seal_record(content, MAX_SAFE_INTEGER, GENESIS_PREVIOUS_HASH)
    beyond = AuditRecord(
        sequence=MAX_SAFE_INTEGER + 1,
        previous_hash=head.record_hash,
        content_hash=compute_content_hash(content),
        record_hash=OTHER_HASH,
        content=content,
    )

    result = verify_chain([ChainEntry(head), ChainEntry(beyond)])

    assert first(result) == (V.SEQUENCE_GAP, MAX_SAFE_INTEGER)
    assert result.violation_count == 2


def test_malformed_predecessor_recorded_at_is_reported_once() -> None:
    entries = replace_content(build_chain([{}, {}]), 0, recorded_at="not a timestamp")

    result = verify_chain(entries)

    assert first(result) == (V.CONTENT_HASH_MISMATCH, 1)
    assert result.violation_count == 1


# --- Precedence, continuation, and chain-level tampering --------------------------------------


def test_one_violation_per_record_follows_precedence() -> None:
    entries = build_chain([{}, {}, {}])
    # Record 2: previous-hash, content-hash, and record-hash problems at once.
    entries = replace_record(entries, 1, previous_hash=OTHER_HASH, record_hash=OTHER_HASH)
    entries = replace_content(entries, 1, actor_id="someone-else")

    result = verify_chain(entries)

    assert first(result) == (V.PREVIOUS_HASH_MISMATCH, 2)
    # Record 3 links to the stored (altered) record hash of record 2, which it does not match.
    assert result.violation_count == 2


def test_content_mismatch_takes_precedence_over_payload_and_record_hash() -> None:
    entries = build_chain([{"a": 1}])
    stored = entries[0].payload_values["/a"]
    entries[0] = dataclasses.replace(
        entries[0], payload_values={"/a": PayloadValue(canonical_text="2", salt=stored.salt)}
    )
    entries = replace_record(entries, 0, record_hash=OTHER_HASH)
    entries = replace_content(entries, 0, event_type="CHANGED")

    assert first(verify_chain(entries)) == (V.CONTENT_HASH_MISMATCH, 1)


def test_verification_continues_after_the_first_violation() -> None:
    entries = build_chain([{}, {}, {}, {}, {}])
    entries = replace_content(entries, 1, actor_id="changed")
    entries = replace_content(entries, 3, resource_id="changed")

    result = verify_chain(entries)

    assert first(result) == (V.CONTENT_HASH_MISMATCH, 2)
    assert result.violation_count == 2
    assert result.records_checked == 5


def test_resealed_earlier_record_breaks_the_next_link() -> None:
    entries = reseal(build_chain([{}, {}, {}]), 0, actor_id="rewritten")

    result = verify_chain(entries)

    assert first(result) == (V.PREVIOUS_HASH_MISMATCH, 2)
    assert result.violation_count == 1


def _nested(depth: int, leaf: Any) -> dict[str, Any]:
    node: dict[str, Any] = {"leaf": leaf}
    for _ in range(depth - 1):
        node = {"n": node}
    return node


def test_payload_too_deep_to_walk_is_a_content_hash_mismatch_and_verification_continues() -> None:
    # Only tampering can store this: appends are limited to depth 32.
    entries = build_chain([{}, {}, {}, {}])
    entries = replace_content(entries, 1, payload=_nested(5000, OTHER_HASH))
    entries = replace_content(entries, 3, actor_id="changed")

    result = verify_chain(entries)

    assert first(result) == (V.CONTENT_HASH_MISMATCH, 2)
    assert result.violation_count == 2
    assert result.records_checked == 4


def test_undecoded_payload_text_is_a_content_hash_mismatch() -> None:
    # The loader keeps a payload it cannot decode as its text, which is never a committed structure.
    entries = replace_content(build_chain([{}, {}]), 0, payload='{"n": {"n": {}}}')

    result = verify_chain(entries)

    assert first(result) == (V.CONTENT_HASH_MISMATCH, 1)
    assert result.violation_count == 1


def test_deepest_payload_an_append_allows_still_verifies() -> None:
    assert verify_chain(build_chain([_nested(31, "value"), {}])).intact


def test_tail_truncation_is_not_detectable_without_a_checkpoint() -> None:
    # Documents a known limitation: CHAIN_TRUNCATED needs the deferred checkpoint anchor (FR-4).
    entries = build_chain([{}, {}, {}])[:2]
    assert verify_chain(entries).intact


@given(
    payloads=st.lists(_payloads, min_size=1, max_size=5),
    data=st.data(),
    field_name=st.sampled_from(sorted(COVERED_FIELD_TAMPERS)),
)
def test_any_single_field_tamper_is_detected_at_its_record(
    payloads: list[dict[str, Any]], data: st.DataObject, field_name: str
) -> None:
    entries = build_chain(payloads)
    position = data.draw(st.integers(0, len(entries) - 1))
    original = getattr(entries[position].record.content, field_name)
    replacement = COVERED_FIELD_TAMPERS[field_name]
    if replacement == original:
        replacement = None if field_name == "timestamp" else OTHER_HASH
    tampered = replace_content(entries, position, **{field_name: replacement})

    result = verify_chain(tampered)

    assert not result.intact
    assert first(result) == (V.CONTENT_HASH_MISMATCH, position + 1)
    assert result.violation_count == 1


@given(payloads=st.lists(_payloads, min_size=2, max_size=5), data=st.data())
def test_any_resealed_record_is_detected_by_its_successor(
    payloads: list[dict[str, Any]], data: st.DataObject
) -> None:
    entries = build_chain(payloads)
    position = data.draw(st.integers(0, len(entries) - 2))

    result = verify_chain(reseal(entries, position, recorded_by="attacker"))

    assert first(result) == (V.PREVIOUS_HASH_MISMATCH, position + 2)


# --- Disclosure ------------------------------------------------------------------------------


def test_result_discloses_only_type_sequence_and_record_id() -> None:
    entries = build_chain([{"card": "4111-secret"}, {"card": "5500-secret"}])
    salt = entries[1].payload_values["/card"].salt
    entries = replace_content(entries, 1, actor_id="changed")

    result = verify_chain(entries)
    text = repr(result) + repr(entries)

    assert result.first_violation == Violation(
        type=V.CONTENT_HASH_MISMATCH, sequence=2, record_id=str(uuid.UUID(int=2))
    )
    assert {f.name for f in dataclasses.fields(Violation)} == {"type", "sequence", "record_id"}
    for protected in ("4111-secret", "5500-secret", salt, "card", "sensitive-", "changed"):
        assert protected not in text
