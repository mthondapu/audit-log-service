"""Response schemas and the public audit event representation (requirements FR-2, NFR-7)."""

from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from audit_log_service.application.retention import RetentionResult
from audit_log_service.application.verification import VIOLATION_MESSAGES
from audit_log_service.application.verification import (
    ChainVerification as ApplicationChainVerification,
)
from audit_log_service.application.views import EventView
from audit_log_service.integrity.canonical import SCHEME
from audit_log_service.integrity.commitments import PayloadValue, reveal_payload


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


def represent(view: EventView) -> dict[str, Any]:
    """Build the public representation. Salts and commitments are never included (FR-2).

    Values no longer available render as `null`. An archived record renders every value as `null`,
    even while its purge is in progress. `redactedPaths` lists only redaction-authorized pointers.
    """
    record = view.entry.record
    content = record.content
    stored: Mapping[str, PayloadValue] = {} if view.archived else view.entry.payload_values
    revealed = reveal_payload(content.payload, stored)
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
        redactedPaths=view.redacted_paths,
        archived=view.archived,
        contentHash=record.content_hash,
        previousHash=record.previous_hash,
        recordHash=record.record_hash,
    ).model_dump()


class ChainHead(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sequence: int
    recordHash: str


class Anchor(BaseModel):
    """The comparison with the latest checkpoint (FR-4, Phase 10 decision CP10).

    `NONE` (no checkpoint, null sequence), `VERIFIED`, `MISMATCH`, or `TRUNCATED`; otherwise
    `sequence` is the checkpoint's sequence.
    """

    model_config = ConfigDict(extra="forbid")

    status: Literal["NONE", "VERIFIED", "MISMATCH", "TRUNCATED"]
    sequence: int | None


class Violation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    sequence: int
    recordId: str | None
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
        anchor=Anchor(status=result.anchor_status.value, sequence=result.anchor_sequence),
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


class RetentionRun(BaseModel):
    """The result of a successful retention run (FR-5)."""

    model_config = ConfigDict(extra="forbid")

    outcome: Literal["RETENTION_RECORDED", "PURGE_RESUMED", "NOTHING_ELIGIBLE"]
    upToSequence: int | None
    retentionEvent: AuditEvent | None
    purgedValues: int


def represent_retention(result: RetentionResult) -> dict[str, Any]:
    event = result.retention_event
    return {
        "outcome": result.outcome.value,
        "upToSequence": result.up_to_sequence,
        "retentionEvent": None if event is None else represent(event),
        "purgedValues": result.purged_values,
    }


class ExportBundle(BaseModel):
    """A signed export bundle (FR-7). Documentation only: the response is the exact signed bytes.

    `manifest` is the signed manifest, `signature` its Ed25519 signature in lowercase hex, and
    `records` the exported records with their hash inputs, in ascending `sequence` order.
    """

    model_config = ConfigDict(extra="forbid")

    manifest: dict[str, Any]
    signature: str
    records: list[dict[str, Any]]
