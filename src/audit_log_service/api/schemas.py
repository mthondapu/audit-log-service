"""Response schemas and the public audit event representation (requirements FR-2, NFR-7)."""

from typing import Any

from pydantic import BaseModel, ConfigDict

from audit_log_service.application.verification import VIOLATION_MESSAGES
from audit_log_service.application.verification import (
    ChainVerification as ApplicationChainVerification,
)
from audit_log_service.integrity.canonical import SCHEME
from audit_log_service.integrity.commitments import reveal_payload
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
    """Build the public representation. Salts and commitments are never included.

    Values that are no longer stored (redacted) render as `null`, and their JSON Pointers are
    listed in `redactedPaths` (FR-2). Until retention exists, `archived` is always false.
    """
    record = entry.record
    content = record.content
    revealed = reveal_payload(content.payload, entry.payload_values)
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
        payload=revealed.payload,
        redactedPaths=revealed.missing,
        archived=False,
        contentHash=record.content_hash,
        previousHash=record.previous_hash,
        recordHash=record.record_hash,
    ).model_dump()


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
