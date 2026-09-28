"""The application-role guard (ADR-0009, Phase 4 decision P2)."""

import ast
from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import ProgrammingError

import audit_log_service.persistence as persistence_package
from audit_log_service.integrity.hashing import AuditRecord
from audit_log_service.persistence.schema import APPLICATION_ROLE

Append = Callable[..., AuditRecord]
PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


def _granted(engine: Engine, table: str) -> set[str]:
    with engine.connect() as connection:
        return {
            privilege
            for privilege in PRIVILEGES
            if connection.execute(
                text("SELECT has_table_privilege(:role, :table, :privilege)"),
                {"role": APPLICATION_ROLE, "table": table, "privilege": privilege},
            ).scalar_one()
        }


def test_application_role_has_exactly_the_approved_grants(owner_engine: Engine) -> None:
    assert _granted(owner_engine, "audit_records") == {"SELECT", "INSERT"}
    assert _granted(owner_engine, "audit_payload_values") == {"SELECT", "INSERT", "DELETE"}


def test_application_role_is_a_nologin_group_role(owner_engine: Engine) -> None:
    with owner_engine.connect() as connection:
        can_login = connection.execute(
            text("SELECT rolcanlogin FROM pg_roles WHERE rolname = :role"),
            {"role": APPLICATION_ROLE},
        ).scalar_one()
    assert can_login is False


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_records SET actor_id = 'forged'",
        "DELETE FROM audit_records",
        "TRUNCATE audit_records",
        "TRUNCATE audit_payload_values",
        "UPDATE audit_payload_values SET canonical_value = '1'",
        "ALTER TABLE audit_records DISABLE TRIGGER ALL",
        "ALTER TABLE audit_records DROP CONSTRAINT uq_audit_records_sequence",
        "SELECT * FROM alembic_version",
    ],
    ids=[
        "update-records",
        "delete-records",
        "truncate-records",
        "truncate-values",
        "update-values",
        "disable-triggers",
        "drop-constraint",
        "read-migration-state",
    ],
)
def test_application_role_is_refused(append: Append, app_engine: Engine, statement: str) -> None:
    append()
    with (
        pytest.raises(ProgrammingError, match=r"permission denied|must be owner"),
        app_engine.begin() as connection,
    ):
        connection.execute(text(statement))

    with app_engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM audit_records")).scalar_one() == 1


def test_application_role_may_delete_payload_values(append: Append, app_engine: Engine) -> None:
    # Retention and redaction will remove values and salts; records stay (ADR-0004, ADR-0009).
    append()
    with app_engine.begin() as connection:
        deleted = connection.execute(text("DELETE FROM audit_payload_values")).rowcount
    assert deleted > 0


def test_guard_is_scoped_to_the_application_role(append: Append, owner_engine: Engine) -> None:
    # No all-role trigger (P2): the owner, and later the privileged tamper tooling, can still change
    # records. Rolled back here.
    append()
    connection = owner_engine.connect()
    try:
        transaction = connection.begin()
        updated = connection.execute(text("UPDATE audit_records SET actor_id = 'x'")).rowcount
        transaction.rollback()
    finally:
        connection.close()
    assert updated == 1


def test_persistence_package_never_updates_and_deletes_only_payload_values() -> None:
    # ADR-0009: records are never updated or deleted. Redaction (FR-6) deletes only recoverable
    # payload values and their salts, which the application role is granted.
    package_dir = Path(persistence_package.__file__).parent
    for source in package_dir.glob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        used = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        used |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        used |= {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        delete_targets = [
            ast.unparse(node.args[0])
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "delete"
        ]
        raw_sql = [
            node.args[0].value.upper()
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "text"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ]
        assert "update" not in used, source.name
        assert all(target == "audit_payload_values" for target in delete_targets), source.name
        assert not [sql for sql in raw_sql if "UPDATE" in sql or "DELETE" in sql], source.name
