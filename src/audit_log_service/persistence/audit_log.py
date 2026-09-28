"""Serialized append and chain loading (ADR-0003).

Callers own the transaction: they pass a connection inside an explicit transaction at READ
COMMITTED, and commit or roll back. `append_event` can therefore also run inside the larger
transactions of later operations.

Append order, all inside the caller's transaction:

1. bound lock waiting (`SET LOCAL lock_timeout`);
2. take the transaction-scoped advisory lock that serializes every append;
3. read the chain head: `sequence` is head + 1 (or 1), `previousHash` is the head's `recordHash`
   (or the genesis value);
4. read `recordedAt` from the database clock (`clock_timestamp()`, which is taken now, unlike
   `now()`, the transaction start), clamped so it never precedes the head's `recordedAt`;
5. seal the record with the integrity core and insert it with its payload values.

The advisory lock is released when the transaction ends. PostgreSQL, not the application process,
serializes writers. The integrity core computes every hash, commitment, and canonical form.
"""

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from sqlalchemy import Connection, Select, func, insert, select, text

from audit_log_service.integrity.canonical import JsonValue
from audit_log_service.integrity.commitments import PayloadValue, commit_payload
from audit_log_service.integrity.hashing import (
    GENESIS_PREVIOUS_HASH,
    AuditRecord,
    EventContent,
    seal_record,
)
from audit_log_service.integrity.timestamps import format_timestamp, parse_timestamp
from audit_log_service.integrity.verification import ChainEntry
from audit_log_service.persistence.schema import audit_payload_values, audit_records

# Fixed key for the append lock; any other use of this key would serialize with appends.
APPEND_LOCK_KEY = 0x6175_6469_745F_6C6F
_SET_LOCK_TIMEOUT = text("SET LOCAL lock_timeout = '5s'")
_REQUIRED_ISOLATION = "READ COMMITTED"


class PersistenceUsageError(RuntimeError):
    """Raised when a persistence function is called without the transaction it requires."""


@dataclass(frozen=True, slots=True)
class NewEvent:
    """A validated event to append. Server-assigned fields are added during the append.

    `timestamp` is canonical timestamp text or None. Fields that must not reach logs are excluded
    from repr.
    """

    event_type: str
    actor_id: str = field(repr=False)
    resource_type: str
    resource_id: str = field(repr=False)
    timestamp: str | None
    recorded_by: str = field(repr=False)
    payload: dict[str, JsonValue] = field(repr=False)


def append_event(connection: Connection, event: NewEvent) -> AuditRecord:
    """Append one event at the chain head, inside the caller's READ COMMITTED transaction."""
    _require_transaction(connection)
    event_time = None if event.timestamp is None else parse_timestamp(event.timestamp)
    # Salts, commitments, and the id need no lock, so they are prepared before taking it.
    committed = commit_payload(event.payload)
    record_id = uuid.uuid4()

    connection.execute(_SET_LOCK_TIMEOUT)
    connection.execute(select(func.pg_advisory_xact_lock(APPEND_LOCK_KEY)))

    head = connection.execute(
        select(audit_records.c.sequence, audit_records.c.record_hash, audit_records.c.recorded_at)
        .order_by(audit_records.c.sequence.desc())
        .limit(1)
    ).one_or_none()
    database_now = connection.execute(select(func.clock_timestamp())).scalar_one()
    if head is None:
        sequence, previous_hash, recorded_at = 1, GENESIS_PREVIOUS_HASH, database_now
    else:
        sequence = head.sequence + 1
        previous_hash = head.record_hash
        recorded_at = max(database_now, head.recorded_at)

    record = seal_record(
        EventContent(
            id=str(record_id),
            event_type=event.event_type,
            actor_id=event.actor_id,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            timestamp=event.timestamp,
            recorded_at=format_timestamp(recorded_at),
            recorded_by=event.recorded_by,
            payload=committed.structure,
        ),
        sequence,
        previous_hash,
    )

    connection.execute(
        insert(audit_records).values(
            id=record_id,
            sequence=record.sequence,
            previous_hash=record.previous_hash,
            content_hash=record.content_hash,
            record_hash=record.record_hash,
            event_type=event.event_type,
            actor_id=event.actor_id,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            timestamp=event_time,
            recorded_at=recorded_at,
            recorded_by=event.recorded_by,
            committed_payload=committed.structure,
        )
    )
    _insert_payload_values(connection, record_id, committed.values)
    return record


def load_chain_entries(connection: Connection) -> list[ChainEntry]:
    """Load every record with its payload values, in `sequence` order, for verification.

    A single statement reads records and values, so the result reflects one snapshot even at
    READ COMMITTED.
    """
    return _entries_from_rows(connection.execute(_records_with_values()).all())


def load_entry(connection: Connection, record_id: uuid.UUID) -> ChainEntry | None:
    """Load one record with its payload values, or None if no record has this id."""
    rows = connection.execute(_records_with_values().where(audit_records.c.id == record_id)).all()
    entries = _entries_from_rows(rows)
    return entries[0] if entries else None


def _records_with_values() -> Select[Any]:
    return (
        select(
            audit_records,
            audit_payload_values.c.pointer,
            audit_payload_values.c.canonical_value,
            audit_payload_values.c.salt,
        )
        .select_from(
            audit_records.outerjoin(
                audit_payload_values, audit_payload_values.c.record_id == audit_records.c.id
            )
        )
        # `id` keeps each record's rows together even if tampering created duplicate sequences.
        .order_by(audit_records.c.sequence, audit_records.c.id, audit_payload_values.c.pointer)
    )


def _entries_from_rows(rows: Sequence[Any]) -> list[ChainEntry]:
    entries: list[ChainEntry] = []
    current: AuditRecord | None = None
    values: dict[str, PayloadValue] = {}
    for row in rows:
        if current is None or current.content.id != str(row.id):
            if current is not None:
                entries.append(ChainEntry(record=current, payload_values=MappingProxyType(values)))
            current = _record_from_row(row)
            values = {}
        if row.pointer is not None:
            values[row.pointer] = PayloadValue(canonical_text=row.canonical_value, salt=row.salt)
    if current is not None:
        entries.append(ChainEntry(record=current, payload_values=MappingProxyType(values)))
    return entries


def _record_from_row(row: Any) -> AuditRecord:
    return AuditRecord(
        sequence=row.sequence,
        previous_hash=row.previous_hash,
        content_hash=row.content_hash,
        record_hash=row.record_hash,
        content=EventContent(
            id=str(row.id),
            event_type=row.event_type,
            actor_id=row.actor_id,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            timestamp=None if row.timestamp is None else format_timestamp(row.timestamp),
            recorded_at=format_timestamp(row.recorded_at),
            recorded_by=row.recorded_by,
            payload=row.committed_payload,
        ),
    )


def _insert_payload_values(
    connection: Connection, record_id: uuid.UUID, values: Mapping[str, PayloadValue]
) -> None:
    if not values:
        return
    connection.execute(
        insert(audit_payload_values),
        [
            {
                "record_id": record_id,
                "pointer": pointer,
                "canonical_value": value.canonical_text,
                "salt": value.salt,
            }
            for pointer, value in values.items()
        ],
    )


def _require_transaction(connection: Connection) -> None:
    if not connection.in_transaction():
        raise PersistenceUsageError("append_event requires an explicit transaction")
    if connection.get_isolation_level() != _REQUIRED_ISOLATION:
        raise PersistenceUsageError("append_event requires READ COMMITTED isolation")
