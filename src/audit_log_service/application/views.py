"""Event views: a stored record with the state derived from system events (FR-2, FR-5, FR-6).

- `archived` is true when the record is at or below the archived boundary, from the moment the
  covering retention event commits, even while its purge is still in progress.
- `redacted_paths` lists the pointers named by redaction events for the record. Values missing
  only because retention purged them are not redactions and are not listed.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field

from sqlalchemy import Connection

from audit_log_service.integrity.verification import ChainEntry
from audit_log_service.persistence.retention import (
    current_retention_boundary,
    redacted_paths_by_target,
)


@dataclass(frozen=True, slots=True)
class EventView:
    entry: ChainEntry = field(repr=False)
    archived: bool
    redacted_paths: list[str]


def event_views(
    connection: Connection, entries: Sequence[ChainEntry], boundary: int | None = None
) -> list[EventView]:
    """Attach archived state and redacted paths, read in the caller's transaction."""
    if boundary is None:
        boundary = current_retention_boundary(connection)
    paths = redacted_paths_by_target(connection, [entry.record.content.id for entry in entries])
    return [
        EventView(
            entry=entry,
            archived=entry.record.sequence <= boundary,
            redacted_paths=paths.get(entry.record.content.id, []),
        )
        for entry in entries
    ]
