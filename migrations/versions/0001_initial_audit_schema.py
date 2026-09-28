"""Initial audit log schema: immutable records, payload values, and application-role grants.

Revision ID: 0001
Revises:
Create Date: 2026-09-28

Runs as the schema owner. The `audit_log_app` group role must already exist; it is created by the
owner-run provisioning script (scripts/provision_database_roles.sql), never by a migration.

`audit_log_app` receives SELECT and INSERT on `audit_records`, and SELECT, INSERT, and DELETE on
`audit_payload_values`. It receives no UPDATE, DELETE, or TRUNCATE on `audit_records` (ADR-0009).

This migration is irreversible: downgrading would drop audit evidence.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_log_app') THEN
                RAISE EXCEPTION 'role audit_log_app must be provisioned before migrating';
            END IF;
        END
        $$
        """
    )

    op.create_table(
        "audit_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("previous_hash", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.Text(), nullable=False),
        sa.Column("record_hash", sa.Text(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("actor_id", sa.Text(), nullable=False),
        sa.Column("resource_type", sa.Text(), nullable=False),
        sa.Column("resource_id", sa.Text(), nullable=False),
        sa.Column("timestamp", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("recorded_at", postgresql.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("recorded_by", sa.Text(), nullable=False),
        sa.Column("committed_payload", postgresql.JSONB(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_audit_records"),
        sa.UniqueConstraint("sequence", name="uq_audit_records_sequence"),
        sa.UniqueConstraint("previous_hash", name="uq_audit_records_previous_hash"),
        sa.CheckConstraint("sequence >= 1", name="ck_audit_records_sequence_positive"),
    )
    op.create_table(
        "audit_payload_values",
        sa.Column("record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("pointer", sa.Text(), nullable=False),
        sa.Column("canonical_value", sa.Text(), nullable=False),
        sa.Column("salt", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("record_id", "pointer", name="pk_audit_payload_values"),
        sa.ForeignKeyConstraint(
            ["record_id"], ["audit_records.id"], name="fk_audit_payload_values_record_id"
        ),
    )

    op.execute("REVOKE ALL ON audit_records, audit_payload_values FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA public TO audit_log_app")
    op.execute("GRANT SELECT, INSERT ON audit_records TO audit_log_app")
    op.execute("GRANT SELECT, INSERT, DELETE ON audit_payload_values TO audit_log_app")


def downgrade() -> None:
    raise RuntimeError(
        "Migration 0001 is irreversible: downgrading would drop the audit tables and evidence."
    )
