"""Tests for the Alembic migrations."""

import secrets
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import URL, Engine, create_engine, inspect, pool, text

from audit_log_service.persistence.schema import APPLICATION_ROLE, CHECKPOINT_ROLE, metadata

MIGRATION_URL_VARIABLE = "AUDIT_LOG_MIGRATION_DATABASE_URL"


def _snapshot(engine: Engine) -> dict[str, Any]:
    """Describe the audit tables: columns, constraints, and application-role grants."""
    inspector = inspect(engine)
    snapshot: dict[str, Any] = {}
    for table in ("audit_records", "audit_payload_values"):
        snapshot[table] = {
            "columns": [
                (column["name"], column["type"].compile(dialect=engine.dialect), column["nullable"])
                for column in inspector.get_columns(table)
            ],
            "primary_key": inspector.get_pk_constraint(table),
            "unique": sorted(
                (unique["name"], tuple(unique["column_names"]))
                for unique in inspector.get_unique_constraints(table)
            ),
            "checks": sorted(
                (check["name"], check["sqltext"])
                for check in inspector.get_check_constraints(table)
            ),
            "foreign_keys": sorted(
                (fk["name"], tuple(fk["constrained_columns"]), fk["referred_table"])
                for fk in inspector.get_foreign_keys(table)
            ),
        }
    with engine.connect() as connection:
        snapshot["grants"] = connection.execute(
            text(
                "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
                "WHERE grantee = :role ORDER BY table_name, privilege_type"
            ),
            {"role": APPLICATION_ROLE},
        ).all()
    return snapshot


@pytest.fixture
def fresh_database(create_database: Callable[[], URL]) -> Iterator[Engine]:
    engine = create_engine(create_database(), poolclass=pool.NullPool)
    yield engine
    engine.dispose()


def test_migrated_schema_matches_the_core_table_definitions(owner_engine: Engine) -> None:
    snapshot = _snapshot(owner_engine)

    for table in metadata.sorted_tables:
        expected = [
            (column.name, column.type.compile(dialect=owner_engine.dialect), column.nullable)
            for column in table.columns
        ]
        assert snapshot[table.name]["columns"] == expected
        assert snapshot[table.name]["primary_key"]["name"] == table.primary_key.name


def test_approved_constraints_exist(owner_engine: Engine) -> None:
    records = _snapshot(owner_engine)["audit_records"]

    assert records["unique"] == [
        ("uq_audit_records_previous_hash", ("previous_hash",)),
        ("uq_audit_records_sequence", ("sequence",)),
    ]
    assert [name for name, _ in records["checks"]] == ["ck_audit_records_sequence_positive"]


def test_no_foreign_key_links_previous_hash(owner_engine: Engine) -> None:
    snapshot = _snapshot(owner_engine)

    assert snapshot["audit_records"]["foreign_keys"] == []
    assert snapshot["audit_payload_values"]["foreign_keys"] == [
        ("fk_audit_payload_values_record_id", ("record_id",), "audit_records")
    ]


def test_migration_is_deterministic(
    owner_engine: Engine, fresh_database: Engine, run_migrations: Callable[[Engine], None]
) -> None:
    run_migrations(fresh_database)
    assert _snapshot(fresh_database) == _snapshot(owner_engine)


def test_upgrade_at_head_is_a_no_op(
    owner_engine: Engine, run_migrations: Callable[[Engine], None]
) -> None:
    before = _snapshot(owner_engine)
    run_migrations(owner_engine)
    assert _snapshot(owner_engine) == before


def test_downgrade_is_refused_and_keeps_the_tables(
    owner_engine: Engine, migration_config: Callable[[], Config]
) -> None:
    with owner_engine.begin() as connection:
        config = migration_config()
        config.attributes["connection"] = connection
        with pytest.raises(RuntimeError, match="irreversible"):
            command.downgrade(config, "base")

    with owner_engine.connect() as connection:
        version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    assert version == "0002"
    assert set(inspect(owner_engine).get_table_names()) >= {"audit_records", "audit_payload_values"}


def test_cli_path_reads_the_migration_url_variable(
    fresh_database: Engine,
    migration_config: Callable[[], Config],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = fresh_database.url.render_as_string(hide_password=False)
    monkeypatch.setenv(MIGRATION_URL_VARIABLE, url)

    command.upgrade(migration_config(), "head")

    assert "audit_records" in inspect(fresh_database).get_table_names()


def test_cli_path_fails_clearly_without_the_migration_url(
    migration_config: Callable[[], Config], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(MIGRATION_URL_VARIABLE, raising=False)

    with pytest.raises(RuntimeError, match=MIGRATION_URL_VARIABLE):
        command.upgrade(migration_config(), "head")


def test_migration_refuses_to_run_without_the_provisioned_role(
    server_url: URL, fresh_database: Engine, run_migrations: Callable[[Engine], None]
) -> None:
    admin = create_engine(server_url, isolation_level="AUTOCOMMIT", poolclass=pool.NullPool)
    hidden = f"{APPLICATION_ROLE}_hidden_{secrets.token_hex(4)}"
    with admin.connect() as connection:
        connection.execute(text(f"ALTER ROLE {APPLICATION_ROLE} RENAME TO {hidden}"))
        try:
            with pytest.raises(Exception, match="must be provisioned"):
                run_migrations(fresh_database)
        finally:
            connection.execute(text(f"ALTER ROLE {hidden} RENAME TO {APPLICATION_ROLE}"))
    admin.dispose()

    assert "audit_records" not in inspect(fresh_database).get_table_names()


def test_migration_refuses_to_run_without_the_checkpoint_role(
    server_url: URL, fresh_database: Engine, run_migrations: Callable[[Engine], None]
) -> None:
    admin = create_engine(server_url, isolation_level="AUTOCOMMIT", poolclass=pool.NullPool)
    hidden = f"{CHECKPOINT_ROLE}_hidden_{secrets.token_hex(4)}"
    with admin.connect() as connection:
        connection.execute(text(f"ALTER ROLE {CHECKPOINT_ROLE} RENAME TO {hidden}"))
        try:
            with pytest.raises(Exception, match="audit_log_checkpoint must be provisioned"):
                run_migrations(fresh_database)
        finally:
            connection.execute(text(f"ALTER ROLE {hidden} RENAME TO {CHECKPOINT_ROLE}"))
    admin.dispose()

    # Every migration runs in one transaction, so nothing from 0001 remains either.
    assert "audit_records" not in inspect(fresh_database).get_table_names()
