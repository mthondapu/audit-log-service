"""Synchronous, bounded retention runs (requirements FR-5, ADR-0005, Phase 9 decisions).

A run:

1. under the append lock, reads the database clock, computes `cutoff = now - window`, finds the
   highest eligible sequence (`recordedAt < cutoff`), and appends an `AUDIT_LOG_RETENTION` event
   only when that sequence is above the current boundary, which therefore never moves back; then
2. purges the payload values of records at or below the boundary in batches, each its own
   transaction under the append lock, up to the configured number of batches.

Each step commits, so a run stopped by its execution bound leaves resumable work, and a later
run resumes the purge without another retention event. Audit records are never changed.
"""

import uuid
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum

from sqlalchemy import Engine, func, select

from audit_log_service.application.views import EventView, event_views
from audit_log_service.integrity.canonical import JsonValue
from audit_log_service.integrity.timestamps import format_timestamp
from audit_log_service.integrity.verification import RETENTION_EVENT_TYPE
from audit_log_service.persistence.audit_log import (
    NewEvent,
    acquire_append_lock,
    append_event,
    load_entry,
)
from audit_log_service.persistence.retention import (
    current_retention_boundary,
    has_unpurged_values,
    highest_eligible_sequence,
    purge_batch,
)

# Fixed, server-defined identity of retention events (Phase 9 decision 1).
RETENTION_ACTOR_ID = "audit-log-service"
RETENTION_RESOURCE_TYPE = "AUDIT_LOG"
RETENTION_RESOURCE_ID = "audit-log"


class RetentionDisabledError(Exception):
    """No retention window is configured."""


class RetentionIncompleteError(Exception):
    """The execution bound was reached before the purge finished; committed work remains."""


class RetentionOutcome(StrEnum):
    RETENTION_RECORDED = "RETENTION_RECORDED"
    PURGE_RESUMED = "PURGE_RESUMED"
    NOTHING_ELIGIBLE = "NOTHING_ELIGIBLE"


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    window: timedelta | None
    batch_size: int
    max_batches: int


@dataclass(frozen=True, slots=True)
class RetentionResult:
    outcome: RetentionOutcome
    up_to_sequence: int | None
    retention_event: EventView | None
    purged_values: int


def run_retention(engine: Engine, policy: RetentionPolicy, operator: str) -> RetentionResult:
    """Run retention once. Raises `RetentionDisabledError` or `RetentionIncompleteError`."""
    if policy.window is None:
        raise RetentionDisabledError
    boundary, retention_event = _establish_boundary(engine, policy.window, operator)
    purged = _purge(engine, boundary, policy)
    if retention_event is not None:
        outcome = RetentionOutcome.RETENTION_RECORDED
    elif purged > 0:
        outcome = RetentionOutcome.PURGE_RESUMED
    else:
        outcome = RetentionOutcome.NOTHING_ELIGIBLE
    return RetentionResult(
        outcome=outcome,
        up_to_sequence=boundary or None,
        retention_event=retention_event,
        purged_values=purged,
    )


def _establish_boundary(
    engine: Engine, window: timedelta, operator: str
) -> tuple[int, EventView | None]:
    with engine.begin() as connection:
        acquire_append_lock(connection)
        cutoff = connection.execute(select(func.clock_timestamp())).scalar_one() - window
        boundary = current_retention_boundary(connection)
        eligible = highest_eligible_sequence(connection, cutoff)
        if eligible <= boundary:
            return boundary, None
        payload: dict[str, JsonValue] = {
            "cutoff": format_timestamp(cutoff),
            "upToSequence": eligible,
        }
        record = append_event(
            connection,
            NewEvent(
                event_type=RETENTION_EVENT_TYPE,
                actor_id=RETENTION_ACTOR_ID,
                resource_type=RETENTION_RESOURCE_TYPE,
                resource_id=RETENTION_RESOURCE_ID,
                timestamp=None,
                recorded_by=operator,
                payload=payload,
            ),
        )
        entry = load_entry(connection, uuid.UUID(record.content.id))
        if entry is None:
            raise RuntimeError("appended retention event is not readable in its own transaction")
        return eligible, event_views(connection, [entry], eligible)[0]


def _purge(engine: Engine, boundary: int, policy: RetentionPolicy) -> int:
    """Purge within the execution bound; return the number of values deleted."""
    if boundary == 0:
        return 0
    purged = 0
    for _ in range(policy.max_batches):
        with engine.begin() as connection:
            acquire_append_lock(connection)
            deleted = purge_batch(connection, boundary, policy.batch_size)
        purged += deleted
        if deleted < policy.batch_size:
            return purged
    with engine.connect() as connection:
        if has_unpurged_values(connection, boundary):
            raise RetentionIncompleteError
    return purged
