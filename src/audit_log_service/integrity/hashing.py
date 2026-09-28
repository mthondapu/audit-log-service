"""`contentHash`, `recordHash`, and genesis (requirements NFR-1, ADR-0002).

- `contentHash` = labeled hash under ``audit-log/v1/content`` of the object ``{id, eventType,
  actorId, resourceType, resourceId, timestamp, recordedAt, recordedBy, payload}``, where
  `timestamp` is null when absent and `payload` is the committed payload structure.
- `recordHash` = labeled hash under ``audit-log/v1/record`` of ``{sequence, previousHash,
  contentHash}``.
- `previousHash` is the predecessor's `recordHash`, or `GENESIS_PREVIOUS_HASH` for sequence 1.
"""

import re
from dataclasses import dataclass, field

from audit_log_service.integrity.canonical import (
    CONTENT_LABEL,
    MAX_SAFE_INTEGER,
    RECORD_LABEL,
    JsonValue,
    is_sha256_hex,
    labeled_sha256,
)
from audit_log_service.integrity.commitments import is_committed_structure
from audit_log_service.integrity.errors import IntegrityInputError
from audit_log_service.integrity.timestamps import is_canonical_timestamp

GENESIS_PREVIOUS_HASH = "0" * 64
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


@dataclass(frozen=True, slots=True)
class EventContent:
    """The fields covered by `contentHash`, in their canonical text forms.

    `payload` is the committed structure, never raw values. Fields that verification output must
    not expose are excluded from repr.
    """

    id: str
    event_type: str
    actor_id: str = field(repr=False)
    resource_type: str
    resource_id: str = field(repr=False)
    timestamp: str | None
    recorded_at: str
    recorded_by: str = field(repr=False)
    payload: dict[str, JsonValue] = field(repr=False)


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """An immutable audit record as stored: content plus its chain position and hashes."""

    sequence: int
    previous_hash: str
    content_hash: str
    record_hash: str
    content: EventContent


def compute_content_hash(content: EventContent) -> str:
    """Compute `contentHash`, rejecting content that is not in canonical form."""
    _check_content(content)
    return labeled_sha256(
        CONTENT_LABEL,
        {
            "id": content.id,
            "eventType": content.event_type,
            "actorId": content.actor_id,
            "resourceType": content.resource_type,
            "resourceId": content.resource_id,
            "timestamp": content.timestamp,
            "recordedAt": content.recorded_at,
            "recordedBy": content.recorded_by,
            "payload": content.payload,
        },
    )


def compute_record_hash(sequence: int, previous_hash: str, content_hash: str) -> str:
    """Compute `recordHash` from the chain position and the two hashes it links."""
    if not _is_sequence(sequence):
        raise IntegrityInputError("sequence must be an integer from 1 to 2^53 - 1")
    if not is_sha256_hex(previous_hash) or not is_sha256_hex(content_hash):
        raise IntegrityInputError("hashes must be 64 lowercase hexadecimal characters")
    return labeled_sha256(
        RECORD_LABEL,
        {"sequence": sequence, "previousHash": previous_hash, "contentHash": content_hash},
    )


def seal_record(content: EventContent, sequence: int, previous_hash: str) -> AuditRecord:
    """Compute both hashes and return the record for this chain position."""
    content_hash = compute_content_hash(content)
    return AuditRecord(
        sequence=sequence,
        previous_hash=previous_hash,
        content_hash=content_hash,
        record_hash=compute_record_hash(sequence, previous_hash, content_hash),
        content=content,
    )


def _is_sequence(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_SAFE_INTEGER


def _check_content(content: EventContent) -> None:
    if not isinstance(content.id, str) or _UUID.fullmatch(content.id) is None:  # pyright: ignore[reportUnnecessaryIsInstance]
        raise IntegrityInputError("id must be a lowercase hyphenated UUID")
    if content.timestamp is not None and not is_canonical_timestamp(content.timestamp):
        raise IntegrityInputError("timestamp is not in canonical form")
    if not is_canonical_timestamp(content.recorded_at):
        raise IntegrityInputError("recordedAt is not in canonical form")
    text_fields = (
        content.event_type,
        content.actor_id,
        content.resource_type,
        content.resource_id,
        content.recorded_by,
    )
    if not all(isinstance(text, str) for text in text_fields):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise IntegrityInputError("event fields must be strings")
    if not is_committed_structure(content.payload):
        raise IntegrityInputError("payload must be a committed structure")
