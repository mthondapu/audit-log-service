"""Verification of missing payload values and their authorization by redaction (FR-3, FR-6)."""

import dataclasses
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from audit_log_service.integrity.commitments import PayloadValue, commit_payload
from audit_log_service.integrity.hashing import GENESIS_PREVIOUS_HASH, EventContent, seal_record
from audit_log_service.integrity.timestamps import format_timestamp
from audit_log_service.integrity.verification import (
    REDACTION_EVENT_TYPE,
    ChainEntry,
    VerificationResult,
    ViolationType,
    verify_chain,
)

V = ViolationType
BASE_TIME = datetime(2026, 9, 28, 20, 0, tzinfo=UTC)
Chain = list[ChainEntry]


def append(
    chain: Chain, payload: dict[str, Any], event_type: str = "ORDER_PLACED", record_id: str = ""
) -> Chain:
    index = len(chain) + 1
    committed = commit_payload(payload)
    content = EventContent(
        id=record_id or str(uuid.UUID(int=index)),
        event_type=event_type,
        actor_id="actor",
        resource_type="ORDER",
        resource_id="order-1",
        timestamp=None,
        recorded_at=format_timestamp(BASE_TIME + timedelta(seconds=index)),
        recorded_by="svc",
        payload=committed.structure,
    )
    previous = chain[-1].record.record_hash if chain else GENESIS_PREVIOUS_HASH
    record = seal_record(content, index, previous)
    return [*chain, ChainEntry(record=record, payload_values=committed.values)]


def remove_values(chain: Chain, position: int, pointers: list[str]) -> Chain:
    target = chain[position]
    kept = {p: v for p, v in target.payload_values.items() if p not in pointers}
    changed = list(chain)
    changed[position] = dataclasses.replace(target, payload_values=kept)
    return changed


def redact(
    chain: Chain,
    position: int,
    pointers: list[str],
    event_type: str = REDACTION_EVENT_TYPE,
    target_id: str = "",
) -> Chain:
    """Delete values from a record and append the redaction event, as the service does."""
    changed = remove_values(chain, position, pointers)
    payload = {
        "targetId": target_id or chain[position].record.content.id,
        "paths": sorted(pointers),
        "reason": "privacy request",
    }
    return append(changed, payload, event_type)


def first(result: VerificationResult) -> tuple[ViolationType, int] | None:
    violation = result.first_violation
    return None if violation is None else (violation.type, violation.sequence)


PAYLOAD = {"card": "4111", "email": "a@example.test", "nested": {"phone": "555", "tags": ["x"]}}


def test_missing_value_without_redaction_is_reported() -> None:
    chain = remove_values(append(append([], PAYLOAD), {}), 0, ["/card"])

    result = verify_chain(chain)

    assert first(result) == (V.PAYLOAD_VALUE_MISSING, 1)
    assert result.violation_count == 1


def test_later_redaction_authorizes_the_missing_values() -> None:
    chain = redact(append(append([], PAYLOAD), {}), 0, ["/card", "/nested/tags/0"])
    assert verify_chain(chain).intact


def test_redaction_authorizes_only_the_pointers_it_lists() -> None:
    chain = redact(append([], PAYLOAD), 0, ["/card"])
    chain = remove_values(chain, 0, ["/email"])

    assert first(verify_chain(chain)) == (V.PAYLOAD_VALUE_MISSING, 1)


def test_several_redactions_accumulate() -> None:
    chain = redact(append([], PAYLOAD), 0, ["/card"])
    chain = redact(chain, 0, ["/email", "/nested/phone"])
    assert verify_chain(chain).intact


def test_redaction_earlier_than_its_target_does_not_authorize() -> None:
    target_id = str(uuid.UUID(int=99))
    chain = append(
        [], {"targetId": target_id, "paths": ["/card"], "reason": "r"}, REDACTION_EVENT_TYPE
    )
    chain = append(chain, PAYLOAD, record_id=target_id)
    chain = remove_values(chain, 1, ["/card"])

    assert first(verify_chain(chain)) == (V.PAYLOAD_VALUE_MISSING, 2)


def test_redaction_of_another_record_does_not_authorize() -> None:
    chain = append(append([], PAYLOAD), PAYLOAD)
    chain = redact(chain, 1, ["/card"], target_id=chain[1].record.content.id)
    chain = remove_values(chain, 0, ["/card"])

    assert first(verify_chain(chain)) == (V.PAYLOAD_VALUE_MISSING, 1)


def test_event_outside_the_reserved_type_does_not_authorize() -> None:
    chain = redact(append([], PAYLOAD), 0, ["/card"], event_type="REDACTION")
    assert first(verify_chain(chain)) == (V.PAYLOAD_VALUE_MISSING, 1)


def test_tampered_redaction_event_does_not_authorize() -> None:
    chain = redact(append([], PAYLOAD), 0, ["/card"])
    redaction = chain[1]
    tampered_values = dict(redaction.payload_values)
    tampered_values["/reason"] = PayloadValue(
        canonical_text='"forged"', salt=tampered_values["/reason"].salt
    )
    chain[1] = dataclasses.replace(redaction, payload_values=tampered_values)

    result = verify_chain(chain)

    assert first(result) == (V.PAYLOAD_VALUE_MISSING, 1)
    assert result.violation_count == 2  # the redaction event is a PAYLOAD_VALUE_MISMATCH


def test_redaction_event_with_a_missing_value_does_not_authorize() -> None:
    chain = redact(append([], PAYLOAD), 0, ["/card"])
    chain = remove_values(chain, 1, ["/reason"])

    result = verify_chain(chain)

    assert first(result) == (V.PAYLOAD_VALUE_MISSING, 1)
    assert result.violation_count == 2  # its own missing value is unauthorized too


@pytest.mark.parametrize(
    "payload",
    [
        {"targetId": "X", "paths": ["/card"], "reason": "r", "extra": 1},
        {"targetId": 7, "paths": ["/card"], "reason": "r"},
        {"targetId": "X", "paths": "/card", "reason": "r"},
        {"targetId": "X", "paths": [1], "reason": "r"},
        {"targetId": "X", "paths": ["/card"]},
    ],
    ids=["extra-key", "non-string-target", "paths-not-list", "non-string-path", "no-reason"],
)
def test_malformed_redaction_payload_does_not_authorize(payload: dict[str, Any]) -> None:
    chain = remove_values(append([], PAYLOAD), 0, ["/card"])
    target_id = chain[0].record.content.id
    fixed = {k: (target_id if v == "X" else v) for k, v in payload.items()}
    chain = append(chain, fixed, REDACTION_EVENT_TYPE)

    assert first(verify_chain(chain)) == (V.PAYLOAD_VALUE_MISSING, 1)


def test_content_hash_mismatch_outranks_a_missing_value() -> None:
    chain = remove_values(append([], PAYLOAD), 0, ["/card"])
    record = chain[0].record
    chain[0] = dataclasses.replace(
        chain[0],
        record=dataclasses.replace(
            record, content=dataclasses.replace(record.content, actor_id="changed")
        ),
    )
    assert first(verify_chain(chain)) == (V.CONTENT_HASH_MISMATCH, 1)


def test_missing_value_outranks_a_record_hash_mismatch() -> None:
    chain = remove_values(append([], PAYLOAD), 0, ["/card"])
    chain[0] = dataclasses.replace(
        chain[0], record=dataclasses.replace(chain[0].record, record_hash="e" * 64)
    )
    assert first(verify_chain(chain)) == (V.PAYLOAD_VALUE_MISSING, 1)


_SCALARS = st.one_of(st.none(), st.booleans(), st.integers(-1000, 1000), st.text(max_size=6))
_PAYLOADS = st.dictionaries(
    st.text(min_size=1, max_size=4),
    st.one_of(_SCALARS, st.lists(_SCALARS, max_size=3)),
    min_size=1,
    max_size=5,
)


@given(payload=_PAYLOADS, data=st.data())
def test_any_sequence_of_valid_redactions_keeps_the_chain_intact(
    payload: dict[str, Any], data: st.DataObject
) -> None:
    chain = append([], payload)
    remaining: list[str] = sorted(chain[0].payload_values)
    while remaining:
        batch: list[str] = data.draw(st.lists(st.sampled_from(remaining), min_size=1, unique=True))
        chain = redact(chain, 0, batch)
        remaining = [pointer for pointer in remaining if pointer not in batch]
        if data.draw(st.booleans()):
            break
    chain = append(chain, {"after": 1})

    assert verify_chain(chain).intact
