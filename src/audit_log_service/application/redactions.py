"""Redaction of payload values (requirements FR-6, Phase 8 decisions).

A redaction deletes the stored values (and their salts) covered by RFC 6901 JSON Pointers and
appends an `AUDIT_LOG_REDACTION` system event, atomically, under the append lock. Commitments,
`contentHash`, and `recordHash` are never changed.

Checks run in the approved order: request validation (422), target lookup (404), system-event
or archived target (409), pointer resolution (422), and nothing new to redact (409). Error
messages identify a pointer by its position and never echo submitted pointers or reasons.
"""

import re
import uuid
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import Connection

from audit_log_service.application.events import (
    RESERVED_EVENT_TYPE_PREFIX,
    SubmissionError,
    describe_schema_errors,
    is_storable_text,
)
from audit_log_service.application.views import EventView, event_views
from audit_log_service.integrity.canonical import JsonValue
from audit_log_service.integrity.commitments import committed_pointers
from audit_log_service.integrity.verification import REDACTION_EVENT_TYPE
from audit_log_service.persistence.audit_log import (
    NewEvent,
    acquire_append_lock,
    append_event,
    delete_payload_values,
    load_entry,
)
from audit_log_service.persistence.retention import current_retention_boundary

MAX_PATHS = 100
MAX_REASON_LENGTH = 1000
# RFC 6901: "" (the whole document) or "/"-prefixed tokens, in which "~" appears only as ~0 or ~1.
_POINTER = re.compile(r"(?:/(?:[^~/]|~[01])*)*", re.DOTALL)
_ARRAY_INDEX = re.compile(r"0|[1-9][0-9]*")


class RedactionNotFoundError(LookupError):
    """No audit event has the target identifier."""


class RedactionConflictError(Exception):
    """The redaction cannot be applied (409). The message is fixed text."""


class RedactionRequest(BaseModel):
    """The body of `POST /audit/events/{id}/redactions`. Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    paths: Annotated[list[str], Field(min_length=1, max_length=MAX_PATHS)]
    reason: Annotated[str, Field(min_length=1, max_length=MAX_REASON_LENGTH)]


def parse_redaction_request(document: object) -> RedactionRequest:
    """Validate the request body, including pointer syntax and the reason rules."""
    try:
        request = RedactionRequest.model_validate(document)
    except ValidationError as error:
        raise SubmissionError(
            describe_schema_errors(error, set(RedactionRequest.model_fields))
        ) from None
    if not request.reason.strip():
        raise SubmissionError("reason must not be empty or whitespace only")
    if not is_storable_text(request.reason):
        raise SubmissionError("reason contains a character that is not allowed")
    for position, pointer in enumerate(request.paths):
        if not is_storable_text(pointer) or _POINTER.fullmatch(pointer) is None:
            raise SubmissionError(f"paths[{position}] is not a valid JSON Pointer")
    return request


def redact(
    connection: Connection, event_id: str, request: RedactionRequest, operator: str
) -> EventView:
    """Redact in the caller's transaction and return the appended redaction event."""
    acquire_append_lock(connection)
    try:
        target_id = uuid.UUID(event_id)
    except ValueError:
        raise RedactionNotFoundError from None
    target = load_entry(connection, target_id)
    if target is None:
        raise RedactionNotFoundError
    content = target.record.content
    if content.event_type.startswith(RESERVED_EVENT_TYPE_PREFIX):
        raise RedactionConflictError("System events cannot be redacted.")
    # Archived as soon as the covering retention event commits, even mid-purge (FR-6). The append
    # lock is held, so no retention event can commit between this check and the deletion.
    if target.record.sequence <= current_retention_boundary(connection):
        raise RedactionConflictError("Archived records cannot be redacted.")

    leaves = committed_pointers(content.payload)
    covered: set[str] = set()
    for position, pointer in enumerate(request.paths):
        if not _resolves(content.payload, pointer):
            raise SubmissionError(f"paths[{position}] does not identify a value in the payload")
        covered.update(leaf for leaf in leaves if _covers(pointer, leaf))
    to_redact = sorted(covered & target.payload_values.keys())
    if not to_redact:
        raise RedactionConflictError("No payload value remains to be redacted at these paths.")

    delete_payload_values(connection, target_id, to_redact)
    redacted_paths: list[JsonValue] = [*to_redact]
    redaction_payload: dict[str, JsonValue] = {
        "targetId": content.id,
        "paths": redacted_paths,
        "reason": request.reason,
    }
    record = append_event(
        connection,
        NewEvent(
            event_type=REDACTION_EVENT_TYPE,
            actor_id=content.actor_id,
            resource_type=content.resource_type,
            resource_id=content.resource_id,
            timestamp=None,
            recorded_by=operator,
            payload=redaction_payload,
        ),
    )
    entry = load_entry(connection, uuid.UUID(record.content.id))
    if entry is None:
        raise RuntimeError("appended redaction event is not readable in its own transaction")
    return event_views(connection, [entry])[0]


def _covers(pointer: str, leaf: str) -> bool:
    """A pointer covers a value at itself or anywhere beneath it; "" covers every value."""
    return leaf == pointer or leaf.startswith(pointer + "/")


def _resolves(structure: dict[str, Any], pointer: str) -> bool:
    """Whether the pointer identifies an existing object member, array element, or the root."""
    node: object = structure
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            members: dict[str, object] = node  # pyright: ignore[reportUnknownVariableType]
            if token not in members:
                return False
            node = members[token]
        elif isinstance(node, list):
            elements: list[object] = node  # pyright: ignore[reportUnknownVariableType]
            if _ARRAY_INDEX.fullmatch(token) is None or int(token) >= len(elements):
                return False
            node = elements[int(token)]
        else:
            return False
    return True
