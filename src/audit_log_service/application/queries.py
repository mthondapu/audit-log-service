"""Audit event queries: parameter validation and opaque cursors (FR-2, Phase 6 decisions Q1 to Q3).

Accepted parameters are `from`, `to`, `actorId`, `eventType`, `resourceType`, `resourceId`,
`includeArchived`, `limit`, and `cursor`. Anything else, or a repeated parameter, is rejected.
Error messages are fixed text and never include submitted values.

The cursor is opaque to clients: base64url-encoded canonical JSON holding a format version, the
last returned `sequence`, and a digest of the filter set (every parameter except `limit` and
`cursor`). Reusing it with different filters is rejected. It is not signed: a forged cursor can
only select another position among records the caller may already read.
"""

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import cast

from sqlalchemy import Connection

from audit_log_service.application.events import (
    MAX_IDENTIFIER_LENGTH,
    TYPE_PATTERN,
    SubmissionError,
    canonical_time,
    is_storable_text,
)
from audit_log_service.application.views import EventView, event_views
from audit_log_service.integrity.canonical import MAX_SAFE_INTEGER, JsonValue, canonicalize
from audit_log_service.integrity.timestamps import parse_timestamp
from audit_log_service.persistence.audit_log import EventFilters, query_entries
from audit_log_service.persistence.retention import current_retention_boundary

QUERY_PARAMETERS = (
    "from",
    "to",
    "actorId",
    "eventType",
    "resourceType",
    "resourceId",
    "includeArchived",
    "limit",
    "cursor",
)
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
_CURSOR_VERSION = 1
_MAX_CURSOR_LENGTH = 512
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+")
_TYPE = re.compile(TYPE_PATTERN)


class QueryError(ValueError):
    """The query is invalid. The message is fixed text, safe to return to the caller."""


@dataclass(frozen=True, slots=True)
class EventQuery:
    filters: EventFilters
    limit: int
    after_sequence: int
    filter_digest: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class EventPage:
    events: list[EventView]
    next_cursor: str | None


def parse_query(parameters: Sequence[tuple[str, str]]) -> EventQuery:
    """Validate query parameters, given as (name, value) pairs in request order."""
    names = [name for name, _ in parameters]
    if any(name not in QUERY_PARAMETERS for name in names):
        raise QueryError("the query has an unsupported parameter")
    for name in QUERY_PARAMETERS:
        if names.count(name) > 1:
            raise QueryError(f"{name} may be given only once")
    values = dict(parameters)

    recorded_from = _time(values.get("from"), "from")
    recorded_to = _time(values.get("to"), "to")
    if (
        recorded_from is not None
        and recorded_to is not None
        and parse_timestamp(recorded_from) > parse_timestamp(recorded_to)
    ):
        raise QueryError("from must not be later than to")

    context: dict[str, JsonValue] = {
        "from": recorded_from,
        "to": recorded_to,
        "actorId": _identifier(values.get("actorId"), "actorId"),
        "eventType": _type_name(values.get("eventType"), "eventType"),
        "resourceType": _type_name(values.get("resourceType"), "resourceType"),
        "resourceId": _identifier(values.get("resourceId"), "resourceId"),
        "includeArchived": _boolean(values.get("includeArchived"), "includeArchived"),
    }
    digest = hashlib.sha256(canonicalize(context)).hexdigest()
    cursor = values.get("cursor")
    return EventQuery(
        filters=EventFilters(
            actor_id=_optional_text(context["actorId"]),
            event_type=_optional_text(context["eventType"]),
            resource_type=_optional_text(context["resourceType"]),
            resource_id=_optional_text(context["resourceId"]),
            recorded_from=None if recorded_from is None else parse_timestamp(recorded_from),
            recorded_to=None if recorded_to is None else parse_timestamp(recorded_to),
            include_archived=context["includeArchived"] is True,
        ),
        limit=_limit(values.get("limit")),
        after_sequence=0 if cursor is None else _decode_cursor(cursor, digest),
        filter_digest=digest,
    )


def run_query(connection: Connection, query: EventQuery) -> EventPage:
    """Fetch one page. One extra record is read to tell whether another page exists."""
    boundary = current_retention_boundary(connection)
    entries = query_entries(
        connection, query.filters, query.after_sequence, query.limit + 1, archived_boundary=boundary
    )
    page = entries[: query.limit]
    next_cursor = (
        encode_cursor(page[-1].record.sequence, query.filter_digest)
        if len(entries) > query.limit
        else None
    )
    return EventPage(events=event_views(connection, page, boundary), next_cursor=next_cursor)


def encode_cursor(after_sequence: int, filter_digest: str) -> str:
    document: dict[str, JsonValue] = {
        "v": _CURSOR_VERSION,
        "after": after_sequence,
        "filters": filter_digest,
    }
    return base64.urlsafe_b64encode(canonicalize(document)).rstrip(b"=").decode("ascii")


def _decode_cursor(cursor: str, filter_digest: str) -> int:
    if len(cursor) > _MAX_CURSOR_LENGTH or _BASE64URL.fullmatch(cursor) is None:
        raise QueryError("cursor is malformed")
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        document: object = json.loads(raw.decode("utf-8"))
    except (binascii.Error, ValueError):
        raise QueryError("cursor is malformed") from None
    if not isinstance(document, dict):
        raise QueryError("cursor is malformed")
    fields = cast(dict[str, object], document)
    version, after = fields.get("v"), fields.get("after")
    if set(fields) != {"v", "after", "filters"} or type(version) is not int:
        raise QueryError("cursor is malformed")
    # `type(...) is int` rejects booleans and floats, which compare equal to integers.
    if version != _CURSOR_VERSION or type(after) is not int or not 1 <= after <= MAX_SAFE_INTEGER:
        raise QueryError("cursor is malformed")
    if fields["filters"] != filter_digest:
        raise QueryError("cursor was issued for a different set of filters")
    return after


def _time(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    try:
        return canonical_time(value, name)
    except SubmissionError as error:
        raise QueryError(str(error)) from None


def _identifier(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    if not 1 <= len(value) <= MAX_IDENTIFIER_LENGTH:
        raise QueryError(f"{name} must be 1 to {MAX_IDENTIFIER_LENGTH} characters")
    if not is_storable_text(value):
        raise QueryError(f"{name} contains a character that is not allowed")
    return value


def _type_name(value: str | None, name: str) -> str | None:
    if value is not None and _TYPE.fullmatch(value) is None:
        raise QueryError(f"{name} must match {TYPE_PATTERN}")
    return value


def _boolean(value: str | None, name: str) -> bool:
    if value is None or value == "false":
        return False
    if value == "true":
        return True
    raise QueryError(f"{name} must be true or false")


def _limit(value: str | None) -> int:
    if value is None:
        return DEFAULT_LIMIT
    if not (value.isascii() and value.isdigit()) or not 1 <= int(value) <= MAX_LIMIT:
        raise QueryError(f"limit must be an integer from 1 to {MAX_LIMIT}")
    return int(value)


def _optional_text(value: JsonValue) -> str | None:
    return value if isinstance(value, str) else None
