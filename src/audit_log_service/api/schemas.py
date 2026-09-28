"""Response schemas and the public audit event representation (requirements FR-2, NFR-7)."""

import json
from typing import Any, cast

from pydantic import BaseModel, ConfigDict

from audit_log_service.application.verification import VIOLATION_MESSAGES
from audit_log_service.application.verification import (
    ChainVerification as ApplicationChainVerification,
)
from audit_log_service.integrity.canonical import SCHEME
from audit_log_service.integrity.verification import ChainEntry


class AuditEvent(BaseModel):
    """The public representation of a stored audit event, returned by POST and GET alike."""

    model_config = ConfigDict(extra="forbid")

    id: str
    sequence: int
    eventType: str
    actorId: str
    resourceType: str
    resourceId: str
    timestamp: str | None
    recordedAt: str
    recordedBy: str
    payload: dict[str, Any]
    redactedPaths: list[str]
    archived: bool
    contentHash: str
    previousHash: str
    recordHash: str


class AuditEventPage(BaseModel):
    """One page of query results, in ascending `sequence` order. There is no total count."""

    model_config = ConfigDict(extra="forbid")

    items: list[AuditEvent]
    nextCursor: str | None


class ProblemDetails(BaseModel):
    """RFC 9457 Problem Details, served as application/problem+json."""

    model_config = ConfigDict(extra="forbid")

    type: str
    title: str
    status: int
    detail: str
    requestId: str | None = None


def represent(entry: ChainEntry) -> dict[str, Any]:
    """Build the public representation. Salts, pointers, and commitments are never included.

    Until redaction and retention exist, `redactedPaths` is always empty and `archived` is always
    false (Phase 5 decision C2).
    """
    record = entry.record
    content = record.content
    return AuditEvent(
        id=content.id,
        sequence=record.sequence,
        eventType=content.event_type,
        actorId=content.actor_id,
        resourceType=content.resource_type,
        resourceId=content.resource_id,
        timestamp=content.timestamp,
        recordedAt=content.recorded_at,
        recordedBy=content.recorded_by,
        payload=_payload(content.payload, entry),
        redactedPaths=[],
        archived=False,
        contentHash=record.content_hash,
        previousHash=record.previous_hash,
        recordHash=record.record_hash,
    ).model_dump()


def _payload(structure: dict[str, Any], entry: ChainEntry) -> dict[str, Any]:
    """Rebuild the payload from the committed structure and the stored canonical values."""

    def rebuild(node: object, pointer: str) -> Any:
        if isinstance(node, dict):
            items = cast(dict[str, object], node).items()
            return {key: rebuild(item, f"{pointer}/{_pointer_token(key)}") for key, item in items}
        if isinstance(node, list):
            elements = cast(list[object], node)
            return [rebuild(item, f"{pointer}/{index}") for index, item in enumerate(elements)]
        stored = entry.payload_values.get(pointer)
        return None if stored is None else json.loads(stored.canonical_text)

    return {key: rebuild(item, f"/{_pointer_token(key)}") for key, item in structure.items()}


def _pointer_token(key: str) -> str:
    # RFC 6901 escaping, matching the keys under which values are stored.
    return key.replace("~", "~0").replace("/", "~1")


class ChainHead(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sequence: int
    recordHash: str


class Anchor(BaseModel):
    """Checkpoint anchor. Until checkpoints exist, always status NONE with a null sequence."""

    model_config = ConfigDict(extra="forbid")

    status: str
    sequence: int | None


class Violation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    sequence: int
    recordId: str
    message: str


class ChainVerification(BaseModel):
    """The v1 verification result (FR-3). Returned with 200 whether or not the chain is intact."""

    model_config = ConfigDict(extra="forbid")

    intact: bool
    scheme: str
    verifiedAt: str
    recordsChecked: int
    head: ChainHead | None
    anchor: Anchor
    violationCount: int
    firstViolation: Violation | None


def represent_verification(verification: ApplicationChainVerification) -> dict[str, Any]:
    """Map a verification to the response. Only sequences, record ids, and hashes are exposed."""
    result = verification.result
    head = result.head
    violation = result.first_violation
    return ChainVerification(
        intact=result.intact,
        scheme=SCHEME,
        verifiedAt=verification.verified_at,
        recordsChecked=result.records_checked,
        head=None
        if head is None
        else ChainHead(sequence=head.sequence, recordHash=head.record_hash),
        anchor=Anchor(status="NONE", sequence=None),
        violationCount=result.violation_count,
        firstViolation=None
        if violation is None
        else Violation(
            type=violation.type.value,
            sequence=violation.sequence,
            recordId=violation.record_id,
            message=VIOLATION_MESSAGES[violation.type],
        ),
    ).model_dump()
