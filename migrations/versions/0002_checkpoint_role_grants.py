"""Read-only grants for the checkpoint CLI's database role.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-28

Runs as the schema owner. The `audit_log_checkpoint` group role must already exist; it is created by
the owner-run provisioning script (scripts/provision_database_roles.sql), never by a migration.

`audit_log_checkpoint` receives SELECT on `audit_records` and `audit_payload_values` and nothing
else: the checkpoint CLI only reads the chain to verify it before signing (requirements FR-4,
ADR-0009 D4, Phase 10 decision CP4). No table is created or changed. Like 0001, it is irreversible.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_log_checkpoint') THEN
                RAISE EXCEPTION 'role audit_log_checkpoint must be provisioned before migrating';
            END IF;
        END
        $$
        """
    )
    op.execute("GRANT USAGE ON SCHEMA public TO audit_log_checkpoint")
    op.execute("GRANT SELECT ON audit_records, audit_payload_values TO audit_log_checkpoint")


def downgrade() -> None:
    # Like 0001, the schema history is forward-only; a partial downgrade is not supported.
    raise RuntimeError("Migration 0002 is irreversible: the schema history is forward-only.")
