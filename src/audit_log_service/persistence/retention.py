"""State derived from system events, and the retention purge (requirements FR-2, FR-5, FR-6).

There is no retention-runs table. The archived boundary is the `upToSequence` of the latest
applicable retention event, and a record's redacted paths are the paths listed by the redaction
events that name it. Both are read from the chain itself.

The purge deletes only recoverable payload values and their salts; audit records are never
changed (ADR-0005, ADR-0009). It keeps the `/targetId` and `/paths/*` values of redaction events,
the evidence behind `redactedPaths`, and purges every other value, including a redaction reason.
"""

import json
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import Connection, and_, delete, func, not_, or_, select, tuple_

from audit_log_service.integrity.verification import REDACTION_EVENT_TYPE, RETENTION_EVENT_TYPE
from audit_log_service.persistence.schema import audit_payload_values, audit_records


def current_retention_boundary(connection: Connection) -> int:
    """The archived boundary: `upToSequence` of the latest applicable retention event, or 0.

    A retention event applies when its `upToSequence` is readable as an integer from 1 to just
    below its own sequence. The latest retention event keeps its own values, because only a later
    retention event can archive it.
    """
    rows = connection.execute(
        select(audit_records.c.sequence, audit_payload_values.c.canonical_value)
        .select_from(
            audit_records.join(
                audit_payload_values, audit_payload_values.c.record_id == audit_records.c.id
            )
        )
        .where(
            audit_records.c.event_type == RETENTION_EVENT_TYPE,
            audit_payload_values.c.pointer == "/upToSequence",
        )
        .order_by(audit_records.c.sequence.desc())
    ).all()
    for sequence, text in rows:
        up_to = retention_up_to_sequence(text, sequence)
        if up_to is not None:
            return up_to
    return 0


def retention_up_to_sequence(canonical_text: str, event_sequence: int) -> int | None:
    """Parse a retention event's `upToSequence`, or None if it is not a valid boundary."""
    try:
        value: object = json.loads(canonical_text)
    except ValueError:
        return None
    if type(value) is not int or not 1 <= value < event_sequence:
        return None
    return value


def highest_eligible_sequence(connection: Connection, cutoff: datetime) -> int:
    """The end of the oldest contiguous block of records with `recordedAt < cutoff`, or 0.

    The block ends just before the first record at or after the cutoff, so archived records
    always form a contiguous prefix of the chain.
    """
    first_ineligible = connection.execute(
        select(func.min(audit_records.c.sequence)).where(audit_records.c.recorded_at >= cutoff)
    ).scalar_one()
    if first_ineligible is not None:
        return int(first_ineligible) - 1
    last = connection.execute(select(func.max(audit_records.c.sequence))).scalar_one()
    return 0 if last is None else int(last)


# Redaction evidence kept through retention (Phase 9 follow-up): a redaction event's target and
# paths. The values stay commitment-protected and verified; the reason is purged as usual.
_KEPT_REDACTION_EVIDENCE = and_(
    audit_records.c.event_type == REDACTION_EVENT_TYPE,
    or_(
        audit_payload_values.c.pointer == "/targetId",
        audit_payload_values.c.pointer.like("/paths/%"),
    ),
)


def purge_batch(connection: Connection, up_to_sequence: int, batch_size: int) -> int:
    """Delete up to `batch_size` purgeable payload values of records at or below the boundary."""
    batch = (
        select(audit_payload_values.c.record_id, audit_payload_values.c.pointer)
        .join(audit_records, audit_records.c.id == audit_payload_values.c.record_id)
        .where(audit_records.c.sequence <= up_to_sequence, not_(_KEPT_REDACTION_EVIDENCE))
        .limit(batch_size)
    )
    result = connection.execute(
        delete(audit_payload_values).where(
            tuple_(audit_payload_values.c.record_id, audit_payload_values.c.pointer).in_(batch)
        )
    )
    return result.rowcount


def has_unpurged_values(connection: Connection, up_to_sequence: int) -> bool:
    """Whether a purgeable payload value of a record at or below the boundary is still stored.

    Kept redaction evidence does not count, so it never leaves a run unfinished.
    """
    remaining = connection.execute(
        select(audit_payload_values.c.record_id)
        .join(audit_records, audit_records.c.id == audit_payload_values.c.record_id)
        .where(audit_records.c.sequence <= up_to_sequence, not_(_KEPT_REDACTION_EVIDENCE))
        .limit(1)
    ).first()
    return remaining is not None


def redacted_paths_by_target(
    connection: Connection, target_ids: Sequence[str]
) -> dict[str, list[str]]:
    """The sorted JSON Pointers listed by the redaction events naming each target.

    Only readable redaction events count: once retention purges a redaction event's own values,
    its paths can no longer be read.
    """
    if not target_ids:
        return {}
    target_value = audit_payload_values.alias("target_value")
    path_value = audit_payload_values.alias("path_value")
    rows = connection.execute(
        select(target_value.c.canonical_value, path_value.c.canonical_value)
        .select_from(audit_records)
        .join(target_value, target_value.c.record_id == audit_records.c.id)
        .join(path_value, path_value.c.record_id == audit_records.c.id)
        .where(
            audit_records.c.event_type == REDACTION_EVENT_TYPE,
            target_value.c.pointer == "/targetId",
            target_value.c.canonical_value.in_([json.dumps(i) for i in target_ids]),
            path_value.c.pointer.like("/paths/%"),
        )
    ).all()
    paths: dict[str, set[str]] = {}
    for target_text, path_text in rows:
        try:
            target: object = json.loads(target_text)
            path: object = json.loads(path_text)
        except ValueError:
            # Unreadable stored text can only come from tampering; verification reports it.
            continue
        if isinstance(target, str) and isinstance(path, str):
            paths.setdefault(target, set()).add(path)
    return {target: sorted(found) for target, found in paths.items()}
