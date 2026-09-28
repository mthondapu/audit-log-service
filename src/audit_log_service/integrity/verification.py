"""Pure chain verification (requirements FR-3, ADR-0002).

Records are verified in the order given, from genesis. Each record is checked against the record
actually preceding it in the input. Verification continues past violations, counts at most one
violation per record, and reports the first violation and the total count.

When several violations apply to one record, the first in `ViolationType` order is reported.
Malformed stored hashes count as a mismatch of that hash. Results never contain payload values,
salts, payload keys, `actorId`, `resourceId`, or `recordedBy`.

A missing payload value is `PAYLOAD_VALUE_MISSING` unless it is authorized (requirements FR-3):
by a later, valid `AUDIT_LOG_REDACTION` event that names the record and lists the value's pointer
(FR-6), or by a valid `AUDIT_LOG_RETENTION` event whose `upToSequence` covers the record (FR-5).
`ANCHOR_MISMATCH` and `CHAIN_TRUNCATED` (with checkpoints) are not implemented yet; tail truncation
is not detectable by this verifier alone.
"""

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import cast

from audit_log_service.integrity.canonical import is_sha256_hex
from audit_log_service.integrity.commitments import (
    PayloadValue,
    committed_pointers,
    reveal_payload,
    values_open_commitments,
)
from audit_log_service.integrity.errors import IntegrityInputError
from audit_log_service.integrity.hashing import (
    GENESIS_PREVIOUS_HASH,
    AuditRecord,
    compute_content_hash,
    compute_record_hash,
)
from audit_log_service.integrity.timestamps import parse_timestamp

REDACTION_EVENT_TYPE = "AUDIT_LOG_REDACTION"
RETENTION_EVENT_TYPE = "AUDIT_LOG_RETENTION"


class ViolationType(StrEnum):
    """Violation types implemented in this phase, in per-record precedence order."""

    SEQUENCE_DUPLICATE = "SEQUENCE_DUPLICATE"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    GENESIS_MISMATCH = "GENESIS_MISMATCH"
    PREVIOUS_HASH_MISMATCH = "PREVIOUS_HASH_MISMATCH"
    CONTENT_HASH_MISMATCH = "CONTENT_HASH_MISMATCH"
    PAYLOAD_VALUE_MISMATCH = "PAYLOAD_VALUE_MISMATCH"
    PAYLOAD_VALUE_MISSING = "PAYLOAD_VALUE_MISSING"
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
    """Verify an ordered sequence of records from genesis.

    Pass 1 applies every per-record check except missing payload values. A missing value can be
    authorized only by a later, valid redaction event, so pass 2 checks missing values once every
    redaction event is known, keeping the `ViolationType` precedence.
    """
    ordered = list(entries)
    seen_sequences: set[int] = set()
    predecessor: AuditRecord | None = None
    checked: list[ViolationType | None] = []
    for entry in ordered:
        checked.append(_first_violation(entry, predecessor, seen_sequences))
        seen_sequences.add(entry.record.sequence)
        predecessor = entry.record

    authorized = _redaction_authorizations(ordered, checked)
    retained_up_to = _retention_coverage(ordered, checked)
    violation_count = 0
    first_violation: Violation | None = None
    for entry, violation_type in zip(ordered, checked, strict=True):
        record = entry.record
        # Missing values rank after the pass-1 checks up to PAYLOAD_VALUE_MISMATCH.
        outranks_missing = violation_type is not None and (
            _PRECEDENCE.index(violation_type) < _MISSING_RANK
        )
        if (
            not outranks_missing
            and record.sequence > retained_up_to
            and _has_unauthorized_missing_value(entry, authorized)
        ):
            violation_type = ViolationType.PAYLOAD_VALUE_MISSING
        if violation_type is not None:
            violation_count += 1
            if first_violation is None:
                first_violation = Violation(
                    type=violation_type, sequence=record.sequence, record_id=record.content.id
                )

    head = (
        None
        if predecessor is None
        else ChainHead(sequence=predecessor.sequence, record_hash=predecessor.record_hash)
    )
    return VerificationResult(
        intact=violation_count == 0,
        records_checked=len(ordered),
        head=head,
        violation_count=violation_count,
        first_violation=first_violation,
    )


_PRECEDENCE = list(ViolationType)
_MISSING_RANK = _PRECEDENCE.index(ViolationType.PAYLOAD_VALUE_MISSING)


def _redaction_authorizations(
    entries: list[ChainEntry], checked: list[ViolationType | None]
) -> dict[tuple[str, str], int]:
    """Map (target record id, pointer) to the latest valid redaction event's sequence.

    A redaction event authorizes only if it passed every check in pass 1 and none of its own
    values is missing (a redaction event cannot itself be redacted).
    """
    authorized: dict[tuple[str, str], int] = {}
    for entry, violation_type in zip(entries, checked, strict=True):
        record = entry.record
        if violation_type is not None or record.content.event_type != REDACTION_EVENT_TYPE:
            continue
        redaction = _redaction_payload(entry)
        if redaction is None:
            continue
        target_id, paths = redaction
        for pointer in paths:
            key = (target_id, pointer)
            authorized[key] = max(authorized.get(key, 0), record.sequence)
    return authorized


def _retention_coverage(entries: list[ChainEntry], checked: list[ViolationType | None]) -> int:
    """The highest `upToSequence` of a valid retention event, or 0.

    A retention event authorizes the missing values of every record at or below its readable
    `upToSequence`, which must be an integer from 1 to just below its own sequence. It needs no
    other value of its own: a later retention event may have archived it.
    """
    covered = 0
    for entry, violation_type in zip(entries, checked, strict=True):
        record = entry.record
        if violation_type is not None or record.content.event_type != RETENTION_EVENT_TYPE:
            continue
        stored = entry.payload_values.get("/upToSequence")
        if stored is None:
            continue
        up_to: object = json.loads(stored.canonical_text)
        if type(up_to) is int and 1 <= up_to < record.sequence:
            covered = max(covered, up_to)
    return covered


def _redaction_payload(entry: ChainEntry) -> tuple[str, list[str]] | None:
    revealed = reveal_payload(entry.record.content.payload, entry.payload_values)
    payload = revealed.payload
    if revealed.missing or set(payload) != {"targetId", "paths", "reason"}:
        return None
    target_id, paths = payload["targetId"], payload["paths"]
    if not isinstance(target_id, str) or not isinstance(paths, list):
        return None
    if not all(isinstance(path, str) for path in paths):
        return None
    return target_id, cast(list[str], paths)


def _has_unauthorized_missing_value(
    entry: ChainEntry, authorized: dict[tuple[str, str], int]
) -> bool:
    record = entry.record
    return any(
        authorized.get((record.content.id, pointer), 0) <= record.sequence
        for pointer in committed_pointers(record.content.payload)
        if pointer not in entry.payload_values
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
    except (IntegrityInputError, RecursionError):
        # A structure nested too deeply to walk can only come from tampering: it is this record's
        # content mismatch, and verification continues with the next record.
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
