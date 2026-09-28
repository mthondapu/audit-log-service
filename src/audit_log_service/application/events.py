"""Audit event submission and retrieval (requirements FR-1, FR-2, FR-8).

Validation follows the API definition (Phase 5 decision D1): field patterns and lengths, payload
depth, U+0000 and unpaired surrogates, RFC 3339 timestamps normalized to the canonical form, the
reserved `AUDIT_LOG_` namespace, the numeric domain (through the integrity core's canonicalization),
and Scenario C vocabulary rules for `CLIENT_ACCOUNT` events. Every error message is fixed text and
never includes submitted values.

The integrity core computes all canonical forms, commitments, and hashes; the persistence layer
serializes the append. Nothing here repeats that work.
"""

import re
import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import Connection

from audit_log_service.config.vocabulary import ClientAccountVocabulary
from audit_log_service.integrity.canonical import JsonValue, canonicalize
from audit_log_service.integrity.errors import IntegrityInputError
from audit_log_service.integrity.timestamps import format_timestamp, parse_timestamp
from audit_log_service.integrity.verification import ChainEntry
from audit_log_service.persistence.audit_log import NewEvent, append_event, load_entry

TYPE_PATTERN = r"^[A-Z][A-Z0-9_]{0,63}$"
RESERVED_EVENT_TYPE_PREFIX = "AUDIT_LOG_"
MAX_IDENTIFIER_LENGTH = 256
MAX_PAYLOAD_DEPTH = 32
SERVER_ASSIGNED_FIELDS = frozenset(
    {"id", "sequence", "recordedAt", "recordedBy", "contentHash", "previousHash", "recordHash"}
)

_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:[Zz]|[+-]\d{2}:\d{2})"
)

TypeName = Annotated[str, Field(pattern=TYPE_PATTERN)]
Identifier = Annotated[str, Field(min_length=1, max_length=MAX_IDENTIFIER_LENGTH)]


class SubmissionError(ValueError):
    """A submission failed validation. The message is fixed text, safe to return to the caller."""


class EventSubmission(BaseModel):
    """The body of `POST /audit/events`. Unknown fields, including server-assigned ones, fail."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    eventType: TypeName
    actorId: Identifier
    resourceType: TypeName
    resourceId: Identifier
    timestamp: str | None = None
    payload: dict[str, Any]


def parse_submission(document: object) -> EventSubmission:
    """Validate a decoded JSON document against the request schema."""
    try:
        return EventSubmission.model_validate(document)
    except ValidationError as error:
        raise SubmissionError(_describe(error)) from None


def prepare_event(
    submission: EventSubmission, recorded_by: str, vocabulary: ClientAccountVocabulary
) -> NewEvent:
    """Apply the remaining FR-1 and FR-8 rules and build the event to append."""
    if submission.eventType.startswith(RESERVED_EVENT_TYPE_PREFIX):
        raise SubmissionError("eventType is in the reserved system-event namespace")
    for name, text in (("actorId", submission.actorId), ("resourceId", submission.resourceId)):
        if not _is_storable_text(text):
            raise SubmissionError(f"{name} contains a character that is not allowed")
    _check_payload(submission.payload)
    if submission.resourceType == vocabulary.resource_type:
        _check_vocabulary(submission, vocabulary)
    return NewEvent(
        event_type=submission.eventType,
        actor_id=submission.actorId,
        resource_type=submission.resourceType,
        resource_id=submission.resourceId,
        timestamp=None if submission.timestamp is None else _canonical_time(submission.timestamp),
        recorded_by=recorded_by,
        payload=submission.payload,
    )


def record_event(connection: Connection, event: NewEvent, skew: timedelta) -> ChainEntry:
    """Append the event in the caller's transaction and return it as stored.

    A caller `timestamp` more than `skew` ahead of the database-assigned `recordedAt` is rejected
    after the append, inside the same transaction, so the caller's rollback removes it without a
    sequence gap.
    """
    record = append_event(connection, event)
    if event.timestamp is not None:
        recorded_at = parse_timestamp(record.content.recorded_at)
        if parse_timestamp(event.timestamp) - recorded_at > skew:
            raise SubmissionError("timestamp is too far in the future")
    entry = load_entry(connection, uuid.UUID(record.content.id))
    if entry is None:
        raise RuntimeError("appended record is not readable in its own transaction")
    return entry


def find_event(connection: Connection, event_id: str) -> ChainEntry | None:
    """Return the stored event, or None when the identifier is not a UUID or no event has it."""
    try:
        record_id = uuid.UUID(event_id)
    except ValueError:
        return None
    return load_entry(connection, record_id)


def _canonical_time(text: str) -> str:
    if _RFC3339.fullmatch(text) is None:
        raise SubmissionError(
            "timestamp must be an RFC 3339 date-time with a UTC offset and at most six "
            "fractional-second digits"
        )
    try:
        return format_timestamp(datetime.fromisoformat(text.upper()))
    except (ValueError, OverflowError, IntegrityInputError):
        raise SubmissionError("timestamp is not a valid date and time") from None


def _check_payload(payload: dict[str, JsonValue]) -> None:
    if _depth(payload) > MAX_PAYLOAD_DEPTH:
        raise SubmissionError(f"payload is nested more than {MAX_PAYLOAD_DEPTH} levels deep")
    if not _all_text_storable(payload):
        raise SubmissionError("payload contains a character that is not allowed")
    try:
        canonicalize(payload)
    except IntegrityInputError as error:
        # Integrity-core messages are fixed text that never includes the value.
        raise SubmissionError(f"payload {error}") from None


def _check_vocabulary(submission: EventSubmission, vocabulary: ClientAccountVocabulary) -> None:
    required = vocabulary.required_payload_keys.get(submission.eventType)
    if required is None:
        raise SubmissionError("eventType is not in the configured vocabulary for this resourceType")
    if not required <= submission.payload.keys():
        raise SubmissionError("payload is missing a key required for this eventType")


def _depth(value: object) -> int:
    # Iterative, so hostile nesting cannot exhaust the interpreter stack.
    deepest = 0
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        node, level = stack.pop()
        children = _children(node)
        if children is not None:
            deepest = max(deepest, level)
            stack.extend((child, level + 1) for child in children)
    return deepest


def _all_text_storable(value: object) -> bool:
    stack: list[object] = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, str) and not _is_storable_text(node):
            return False
        if isinstance(node, dict) and not all(
            _is_storable_text(key) for key in cast(dict[str, object], node)
        ):
            return False
        children = _children(cast(object, node))
        if children is not None:
            stack.extend(children)
    return True


def _children(node: object) -> list[object] | None:
    if isinstance(node, dict):
        return list(cast(dict[str, object], node).values())
    if isinstance(node, list):
        return list(cast(list[object], node))
    return None


def _is_storable_text(text: str) -> bool:
    """No U+0000 (PostgreSQL) and no unpaired surrogates (UTF-8 and canonical hashing)."""
    if "\x00" in text:
        return False
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _describe(error: ValidationError) -> str:
    """Describe schema errors by known field name and message only, never by input value."""
    known = set(EventSubmission.model_fields) | SERVER_ASSIGNED_FIELDS
    problems: list[str] = []
    for detail in error.errors(include_url=False, include_input=False, include_context=False):
        location = [str(part) for part in detail["loc"]]
        field = location[0] if location else ""
        if detail["type"] == "extra_forbidden":
            name = field if field in known else "an unknown field"
            problems.append(f"{name}: field is not accepted")
        elif field in known:
            problems.append(f"{field}: {detail['msg']}")
        else:
            problems.append(detail["msg"])
    return "; ".join(problems)
