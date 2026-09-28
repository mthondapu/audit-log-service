"""Chain verification against a trusted checkpoint anchor (FR-4, Phase 10 decisions CP9, CP10)."""

import dataclasses
import uuid
from datetime import UTC, datetime, timedelta

from hypothesis import given
from hypothesis import strategies as st

from audit_log_service.integrity.commitments import commit_payload
from audit_log_service.integrity.hashing import GENESIS_PREVIOUS_HASH, EventContent, seal_record
from audit_log_service.integrity.timestamps import format_timestamp
from audit_log_service.integrity.verification import (
    AnchorStatus,
    ChainEntry,
    ChainHead,
    VerificationResult,
    ViolationType,
    verify_chain,
)

V = ViolationType
A = AnchorStatus
BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)
Chain = list[ChainEntry]


def build(count: int, actor: str = "actor", start: int = 1, previous: str | None = None) -> Chain:
    chain: Chain = []
    for sequence in range(start, start + count):
        committed = commit_payload({"n": sequence})
        content = EventContent(
            id=str(uuid.UUID(int=sequence if actor == "actor" else 10_000 + sequence)),
            event_type="ORDER_PLACED",
            actor_id=actor,
            resource_type="ORDER",
            resource_id="order-1",
            timestamp=None,
            recorded_at=format_timestamp(BASE_TIME + timedelta(seconds=sequence)),
            recorded_by="svc",
            payload=committed.structure,
        )
        link = (
            chain[-1].record.record_hash
            if chain
            else (previous if previous is not None else GENESIS_PREVIOUS_HASH)
        )
        chain.append(ChainEntry(seal_record(content, sequence, link), committed.values))
    return chain


def anchor_at(chain: Chain, sequence: int) -> ChainHead:
    record = chain[sequence - 1].record
    return ChainHead(sequence=record.sequence, record_hash=record.record_hash)


def first(result: VerificationResult) -> tuple[ViolationType, int, str | None] | None:
    violation = result.first_violation
    return None if violation is None else (violation.type, violation.sequence, violation.record_id)


def test_without_an_anchor_the_status_is_none() -> None:
    result = verify_chain(build(3))
    assert (result.anchor_status, result.anchor_sequence) == (A.NONE, None)
    assert result.intact


def test_matching_anchor_is_verified() -> None:
    chain = build(5)
    result = verify_chain(chain, anchor_at(chain, 3))

    assert result.intact
    assert (result.anchor_status, result.anchor_sequence) == (A.VERIFIED, 3)


def test_anchor_at_the_head_is_verified() -> None:
    chain = build(3)
    assert verify_chain(chain, anchor_at(chain, 3)).anchor_status is A.VERIFIED


def test_tail_truncation_below_the_checkpoint_is_detected() -> None:
    chain = build(5)
    anchor = anchor_at(chain, 5)

    result = verify_chain(chain[:3], anchor)

    assert not result.intact
    assert (result.anchor_status, result.anchor_sequence) == (A.TRUNCATED, 5)
    assert first(result) == (V.CHAIN_TRUNCATED, 4, None)
    assert result.violation_count == 1
    assert result.head == anchor_at(chain, 3)


def test_truncation_to_an_empty_chain_is_detected() -> None:
    chain = build(2)
    result = verify_chain([], anchor_at(chain, 2))

    assert (result.anchor_status, first(result)) == (A.TRUNCATED, (V.CHAIN_TRUNCATED, 1, None))
    assert result.records_checked == 0


def test_truncation_above_the_checkpoint_is_not_detected() -> None:
    # The documented limitation: records after the latest checkpoint are unanchored (FR-4).
    chain = build(5)
    result = verify_chain(chain[:4], anchor_at(chain, 3))
    assert result.intact
    assert result.anchor_status is A.VERIFIED


def test_full_rewrite_with_recomputed_hashes_is_an_anchor_mismatch() -> None:
    original = build(5)
    rewritten = build(5, actor="forger")
    assert verify_chain(rewritten).intact  # consistent on its own

    result = verify_chain(rewritten, anchor_at(original, 4))

    assert not result.intact
    assert (result.anchor_status, result.anchor_sequence) == (A.MISMATCH, 4)
    assert first(result) == (V.ANCHOR_MISMATCH, 4, rewritten[3].record.content.id)
    assert result.violation_count == 1


def test_truncation_and_forged_reappend_past_the_checkpoint_is_an_anchor_mismatch() -> None:
    original = build(10)
    forged = original[:5] + build(
        7, actor="forger", start=6, previous=original[4].record.record_hash
    )

    result = verify_chain(forged, anchor_at(original, 10))

    assert verify_chain(forged).intact
    assert first(result) == (V.ANCHOR_MISMATCH, 10, forged[9].record.content.id)
    assert result.anchor_status is A.MISMATCH


def test_deleting_the_checkpointed_record_is_a_mismatch_reported_as_the_gap() -> None:
    chain = build(5)
    anchor = anchor_at(chain, 3)

    result = verify_chain(chain[:2] + chain[3:], anchor)

    assert result.anchor_status is A.MISMATCH
    assert first(result) == (V.SEQUENCE_GAP, 4, chain[3].record.content.id)
    assert result.violation_count == 1  # the gap only; no further anchor violation


def test_higher_precedence_violation_suppresses_the_anchor_mismatch_on_that_record() -> None:
    chain = build(3)
    anchor = ChainHead(sequence=2, record_hash="f" * 64)
    record = chain[1].record
    chain[1] = dataclasses.replace(
        chain[1],
        record=dataclasses.replace(
            record, content=dataclasses.replace(record.content, actor_id="x")
        ),
    )

    result = verify_chain(chain, anchor)

    assert result.anchor_status is A.MISMATCH
    assert first(result) == (V.CONTENT_HASH_MISMATCH, 2, record.content.id)
    assert result.violation_count == 1  # one violation per record


def test_anchor_mismatch_is_counted_with_other_record_violations() -> None:
    original = build(4)
    rewritten = build(4, actor="forger")
    record = rewritten[0].record
    rewritten[0] = dataclasses.replace(
        rewritten[0],
        record=dataclasses.replace(
            record, content=dataclasses.replace(record.content, recorded_by="y")
        ),
    )

    result = verify_chain(rewritten, anchor_at(original, 3))

    assert first(result) == (V.CONTENT_HASH_MISMATCH, 1, record.content.id)
    assert result.violation_count == 2  # the modified record and the anchor mismatch


def test_truncation_is_reported_after_earlier_record_violations() -> None:
    chain = build(5)
    anchor = anchor_at(chain, 5)
    truncated = chain[:3]
    truncated[0] = dataclasses.replace(truncated[0], payload_values={})

    result = verify_chain(truncated, anchor)

    assert first(result) == (V.PAYLOAD_VALUE_MISSING, 1, chain[0].record.content.id)
    assert result.violation_count == 2
    assert result.anchor_status is A.TRUNCATED


def test_duplicate_at_the_anchor_sequence_compares_the_first_occurrence() -> None:
    chain = build(3)
    anchor = anchor_at(chain, 2)
    result = verify_chain([*chain[:2], chain[1], chain[2]], anchor)

    assert result.anchor_status is A.VERIFIED
    assert first(result) == (V.SEQUENCE_DUPLICATE, 2, chain[1].record.content.id)


def test_stored_record_hash_changed_at_the_anchor_is_reported_once() -> None:
    chain = build(3)
    anchor = anchor_at(chain, 3)
    record = chain[2].record
    chain[2] = dataclasses.replace(
        chain[2], record=dataclasses.replace(record, record_hash="e" * 64)
    )

    result = verify_chain(chain, anchor)

    assert result.anchor_status is A.MISMATCH
    assert first(result) == (V.RECORD_HASH_MISMATCH, 3, record.content.id)
    assert result.violation_count == 1


@given(length=st.integers(min_value=1, max_value=12), data=st.data())
def test_any_intact_chain_verifies_against_a_checkpoint_of_any_prefix(
    length: int, data: st.DataObject
) -> None:
    chain = build(length)
    sequence = data.draw(st.integers(min_value=1, max_value=length))

    result = verify_chain(chain, anchor_at(chain, sequence))

    assert result.intact
    assert (result.anchor_status, result.anchor_sequence) == (A.VERIFIED, sequence)


@given(length=st.integers(min_value=2, max_value=12), data=st.data())
def test_any_truncation_below_a_checkpoint_is_detected(length: int, data: st.DataObject) -> None:
    chain = build(length)
    sequence = data.draw(st.integers(min_value=1, max_value=length))
    kept = data.draw(st.integers(min_value=0, max_value=sequence - 1))

    result = verify_chain(chain[:kept], anchor_at(chain, sequence))

    assert result.anchor_status is A.TRUNCATED
    assert first(result) == (V.CHAIN_TRUNCATED, kept + 1, None)
