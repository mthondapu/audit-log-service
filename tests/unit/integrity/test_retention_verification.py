"""Verification of missing values authorized by retention events (FR-3 rule 1, FR-5)."""

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
    RETENTION_EVENT_TYPE,
    ChainEntry,
    VerificationResult,
    ViolationType,
    verify_chain,
)

V = ViolationType
BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)
CUTOFF = "2026-06-01T00:00:00.000000Z"
Chain = list[ChainEntry]
PAYLOAD = {"card": "4111", "email": "a@example.test"}


def append(chain: Chain, payload: dict[str, Any], event_type: str = "ORDER_PLACED") -> Chain:
    index = len(chain) + 1
    committed = commit_payload(payload)
    content = EventContent(
        id=str(uuid.UUID(int=index)),
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
    return [*chain, ChainEntry(seal_record(content, index, previous), committed.values)]


def purge(chain: Chain, up_to: int) -> Chain:
    """Delete every stored value of records at or below `up_to`, as a retention purge does."""
    return [
        dataclasses.replace(entry, payload_values={}) if entry.record.sequence <= up_to else entry
        for entry in chain
    ]


def retain(chain: Chain, up_to: Any, event_type: str = RETENTION_EVENT_TYPE) -> Chain:
    return append(chain, {"cutoff": CUTOFF, "upToSequence": up_to}, event_type)


def first(result: VerificationResult) -> tuple[ViolationType, int] | None:
    violation = result.first_violation
    return None if violation is None else (violation.type, violation.sequence)


def test_retention_event_authorizes_purged_values_it_covers() -> None:
    chain = retain(append(append([], PAYLOAD), PAYLOAD), 2)
    assert verify_chain(purge(chain, 2)).intact


def test_mid_purge_chain_is_intact() -> None:
    chain = retain(append(append([], PAYLOAD), PAYLOAD), 2)
    assert verify_chain(purge(chain, 1)).intact


def test_values_above_the_boundary_are_not_authorized() -> None:
    chain = retain(append(append([], PAYLOAD), PAYLOAD), 1)
    assert first(verify_chain(purge(chain, 2))) == (V.PAYLOAD_VALUE_MISSING, 2)


def test_retention_event_does_not_authorize_a_later_record() -> None:
    chain = append(retain(append([], PAYLOAD), 1), PAYLOAD)
    chain[2] = dataclasses.replace(chain[2], payload_values={})
    assert first(verify_chain(chain)) == (V.PAYLOAD_VALUE_MISSING, 3)


@pytest.mark.parametrize(
    "up_to",
    [3, 4, 0, -1, 2.5, "2", True, None],
    ids=["own-sequence", "above-own", "zero", "negative", "fraction", "string", "bool", "null"],
)
def test_invalid_up_to_sequence_does_not_authorize(up_to: Any) -> None:
    chain = retain(append(append([], PAYLOAD), PAYLOAD), up_to)
    assert first(verify_chain(purge(chain, 1))) == (V.PAYLOAD_VALUE_MISSING, 1)


def test_event_outside_the_reserved_type_does_not_authorize() -> None:
    chain = retain(append([], PAYLOAD), 1, event_type="RETENTION")
    assert first(verify_chain(purge(chain, 1))) == (V.PAYLOAD_VALUE_MISSING, 1)


def test_redaction_event_type_does_not_grant_retention_coverage() -> None:
    chain = retain(append([], PAYLOAD), 1, event_type=REDACTION_EVENT_TYPE)
    assert first(verify_chain(purge(chain, 1))) == (V.PAYLOAD_VALUE_MISSING, 1)


def test_tampered_retention_event_does_not_authorize() -> None:
    chain = purge(retain(append(append([], PAYLOAD), PAYLOAD), 1), 2)
    event = chain[2]
    values = dict(event.payload_values)
    values["/upToSequence"] = PayloadValue(canonical_text="2", salt=values["/upToSequence"].salt)
    chain[2] = dataclasses.replace(event, payload_values=values)

    result = verify_chain(chain)

    assert first(result) == (V.PAYLOAD_VALUE_MISSING, 1)
    assert result.violation_count == 3  # both records and the tampered event


def test_retention_event_without_a_readable_boundary_does_not_authorize() -> None:
    chain = purge(retain(append([], PAYLOAD), 1), 1)
    event = chain[1]
    chain[1] = dataclasses.replace(
        event,
        payload_values={p: v for p, v in event.payload_values.items() if p != "/upToSequence"},
    )

    result = verify_chain(chain)

    assert first(result) == (V.PAYLOAD_VALUE_MISSING, 1)
    assert result.violation_count == 2


def test_older_retention_event_can_itself_be_archived() -> None:
    chain = retain(append([], PAYLOAD), 1)
    chain = append(chain, PAYLOAD)
    chain = retain(chain, 3)

    assert verify_chain(purge(chain, 3)).intact


def test_retention_covers_redaction_events_and_their_targets() -> None:
    chain = append([], PAYLOAD)
    chain = append(
        chain,
        {"targetId": chain[0].record.content.id, "paths": ["/card"], "reason": "r"},
        REDACTION_EVENT_TYPE,
    )
    chain = retain(chain, 2)

    assert verify_chain(purge(chain, 2)).intact


def test_kept_redaction_evidence_with_a_purged_reason_verifies() -> None:
    # The retention purge keeps a redaction event's targetId and paths and purges its reason.
    chain = append([], PAYLOAD)
    chain[0] = dataclasses.replace(
        chain[0],
        payload_values={p: v for p, v in chain[0].payload_values.items() if p != "/card"},
    )
    chain = append(
        chain,
        {"targetId": chain[0].record.content.id, "paths": ["/card"], "reason": "r"},
        REDACTION_EVENT_TYPE,
    )
    chain = retain(chain, 2)
    chain = purge(chain, 1)
    redaction = chain[1]
    chain[1] = dataclasses.replace(
        redaction,
        payload_values={p: v for p, v in redaction.payload_values.items() if p != "/reason"},
    )

    assert verify_chain(chain).intact


_OPERATIONS = st.lists(st.sampled_from(["append", "redact", "retain"]), min_size=1, max_size=8)


@given(operations=_OPERATIONS)
def test_any_interleaving_of_appends_redactions_and_retention_verifies(
    operations: list[str],
) -> None:
    chain: Chain = []
    boundary = 0
    for operation in operations:
        if operation == "append" or not chain:
            chain = append(chain, PAYLOAD)
        elif operation == "redact":
            target = next(
                (
                    entry
                    for entry in chain
                    if entry.record.sequence > boundary
                    and not entry.record.content.event_type.startswith("AUDIT_LOG_")
                    and entry.payload_values
                ),
                None,
            )
            if target is None:
                continue
            pointer = sorted(target.payload_values)[0]
            position = target.record.sequence - 1
            chain[position] = dataclasses.replace(
                target,
                payload_values={p: v for p, v in target.payload_values.items() if p != pointer},
            )
            chain = append(
                chain,
                {"targetId": target.record.content.id, "paths": [pointer], "reason": "r"},
                REDACTION_EVENT_TYPE,
            )
        else:
            boundary = len(chain)
            chain = purge(retain(chain, boundary), boundary)

    assert verify_chain(chain).intact
