"""SQLAlchemy Core table definitions for the audit log.

These mirror the schema created by the Alembic migrations, which remain the source of the database
schema; a test checks that the two agree.

- `audit_records` holds the immutable record: its chain position, hashes, event fields, and the
  committed payload structure (commitments only, never raw values).
- `audit_payload_values` holds each recoverable payload value as its RFC 8785 canonical JSON text,
  with its salt, keyed by record and JSON Pointer.

There is no foreign key from `previous_hash` to `record_hash` (ADR-0003).
"""

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    ForeignKeyConstraint,
    MetaData,
    PrimaryKeyConstraint,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP, UUID

APPLICATION_ROLE = "audit_log_app"
# The checkpoint CLI's read-only group role (migration 0002, ADR-0009 D4).
CHECKPOINT_ROLE = "audit_log_checkpoint"

metadata = MetaData()

audit_records = Table(
    "audit_records",
    metadata,
    Column("id", UUID(as_uuid=True), nullable=False),
    Column("sequence", BigInteger, nullable=False),
    Column("previous_hash", Text, nullable=False),
    Column("content_hash", Text, nullable=False),
    Column("record_hash", Text, nullable=False),
    Column("event_type", Text, nullable=False),
    Column("actor_id", Text, nullable=False),
    Column("resource_type", Text, nullable=False),
    Column("resource_id", Text, nullable=False),
    Column("timestamp", TIMESTAMP(timezone=True), nullable=True),
    Column("recorded_at", TIMESTAMP(timezone=True), nullable=False),
    Column("recorded_by", Text, nullable=False),
    Column("committed_payload", JSONB, nullable=False),
    PrimaryKeyConstraint("id", name="pk_audit_records"),
    UniqueConstraint("sequence", name="uq_audit_records_sequence"),
    UniqueConstraint("previous_hash", name="uq_audit_records_previous_hash"),
    CheckConstraint("sequence >= 1", name="ck_audit_records_sequence_positive"),
)

audit_payload_values = Table(
    "audit_payload_values",
    metadata,
    Column("record_id", UUID(as_uuid=True), nullable=False),
    Column("pointer", Text, nullable=False),
    Column("canonical_value", Text, nullable=False),
    Column("salt", Text, nullable=False),
    PrimaryKeyConstraint("record_id", "pointer", name="pk_audit_payload_values"),
    ForeignKeyConstraint(
        ["record_id"], ["audit_records.id"], name="fk_audit_payload_values_record_id"
    ),
)
