"""Pure chain verification (requirements FR-3, ADR-0002).

Records are verified in the order given, from genesis. Each record is checked against the record
actually preceding it in the input. Verification continues past violations, counts at most one
violation per record, and reports the first violation and the total count.

When several violations apply to one record, the first in `ViolationType` order is reported.
Malformed stored hashes count as a mismatch of that hash. Results never contain payload values,
salts, payload keys, `actorId`, `resourceId`, or `recordedBy`.

Not implemented here, and deferred: `PAYLOAD_VALUE_MISSING` (with retention and redaction), and
`ANCHOR_MISMATCH` and `CHAIN_TRUNCATED` (with checkpoints). Missing payload values are therefore
not reported, and tail truncation is not detectable by this verifier alone.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from audit_log_service.integrity.canonical import is_sha256_hex
from audit_log_service.integrity.commitments import PayloadValue, values_open_commitments
from audit_log_service.integrity.errors import IntegrityInputError
from audit_log_service.integrity.hashing import (
    GENESIS_PREVIOUS_HASH,
    AuditRecord,
    compute_content_hash,
    compute_record_hash,
)
from audit_log_service.integrity.timestamps import parse_timestamp


class ViolationType(StrEnum):
    """Violation types implemented in this phase, in per-record precedence order."""

    SEQUENCE_DUPLICATE = "SEQUENCE_DUPLICATE"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    GENESIS_MISMATCH = "GENESIS_MISMATCH"
    PREVIOUS_HASH_MISMATCH = "PREVIOUS_HASH_MISMATCH"
    CONTENT_HASH_MISMATCH = "CONTENT_HASH_MISMATCH"
    PAYLOAD_VALUE_MISMATCH = "PAYLOAD_VALUE_MISMATCH"
    RECORD_HASH_MISMATCH = "RECORD_HASH_MISMATCH"
    RECORDED_AT_REGRESSION = "RECORDED_AT_REGRESSION"


@dataclass(frozen=True, slots=True)
class ChainEntry:
    """A stored record and its recoverable payload values, keyed by JSON Pointer."""

    record: AuditRecord
    payload_values: Mapping[str, PayloadValue] = field(
        default_factory=lambda: MappingProxyType({}), repr=False
    )


@dataclass(frozen=True, slots=True)
class Violation:
    type: ViolationType
    sequence: int
    record_id: str


@dataclass(frozen=True, slots=True)
class ChainHead:
    sequence: int
    record_hash: str


@dataclass(frozen=True, slots=True)
class VerificationResult:
    intact: bool
    records_checked: int
    head: ChainHead | None
    violation_count: int
    first_violation: Violation | None


def verify_chain(entries: Iterable[ChainEntry]) -> VerificationResult:
    """Verify an ordered sequence of records from genesis."""
    seen_sequences: set[int] = set()
    predecessor: AuditRecord | None = None
    records_checked = 0
    violation_count = 0
    first_violation: Violation | None = None

    for entry in entries:
        record = entry.record
        violation_type = _first_violation(entry, predecessor, seen_sequences)
        if violation_type is not None:
            violation_count += 1
            if first_violation is None:
                first_violation = Violation(
                    type=violation_type, sequence=record.sequence, record_id=record.content.id
                )
        seen_sequences.add(record.sequence)
        predecessor = record
        records_checked += 1

    head = (
        None
        if predecessor is None
        else ChainHead(sequence=predecessor.sequence, record_hash=predecessor.record_hash)
    )
    return VerificationResult(
        intact=violation_count == 0,
        records_checked=records_checked,
        head=head,
        violation_count=violation_count,
        first_violation=first_violation,
    )


def _first_violation(
    entry: ChainEntry, predecessor: AuditRecord | None, seen_sequences: set[int]
) -> ViolationType | None:
    record = entry.record

    if record.sequence in seen_sequences:
        return ViolationType.SEQUENCE_DUPLICATE
    expected_sequence = 1 if predecessor is None else predecessor.sequence + 1
    if record.sequence != expected_sequence:
        return ViolationType.SEQUENCE_GAP
    if predecessor is None:
        if record.previous_hash != GENESIS_PREVIOUS_HASH:
            return ViolationType.GENESIS_MISMATCH
    elif not is_sha256_hex(record.previous_hash) or record.previous_hash != predecessor.record_hash:
        return ViolationType.PREVIOUS_HASH_MISMATCH
    if not _content_hash_matches(record):
        return ViolationType.CONTENT_HASH_MISMATCH
    if not values_open_commitments(record.content.payload, entry.payload_values):
        return ViolationType.PAYLOAD_VALUE_MISMATCH
    if not _record_hash_matches(record):
        return ViolationType.RECORD_HASH_MISMATCH
    if predecessor is not None and _recorded_at_regressed(record, predecessor):
        return ViolationType.RECORDED_AT_REGRESSION
    return None


def _content_hash_matches(record: AuditRecord) -> bool:
    if not is_sha256_hex(record.content_hash):
        return False
    try:
        return compute_content_hash(record.content) == record.content_hash
    except IntegrityInputError:
        return False


def _record_hash_matches(record: AuditRecord) -> bool:
    if not is_sha256_hex(record.record_hash):
        return False
    try:
        expected = compute_record_hash(record.sequence, record.previous_hash, record.content_hash)
    except IntegrityInputError:
        return False
    return expected == record.record_hash


def _recorded_at_regressed(record: AuditRecord, predecessor: AuditRecord) -> bool:
    try:
        current = parse_timestamp(record.content.recorded_at)
        previous = parse_timestamp(predecessor.content.recorded_at)
    except IntegrityInputError:
        # A malformed recordedAt on this record already fails its contentHash check; one on the
        # predecessor was reported against the predecessor. Neither can be ordered.
        return False
    return current < previous
