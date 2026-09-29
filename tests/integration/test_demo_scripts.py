"""Demonstration tamper tooling against PostgreSQL: the tamper role and tamper_demo.py (Phase 12,
decision P5).

The tamper tooling runs as `audit_log_tamper`, provisioned by scripts/provision_tamper_role.sql.
"""

import io
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest
from sqlalchemy import URL, Engine, text
from sqlalchemy.exc import ProgrammingError

from audit_log_service.integrity.hashing import AuditRecord
from audit_log_service.integrity.verification import (
    ChainEntry,
    ChainHead,
    VerificationResult,
    ViolationType,
    verify_chain,
)

ROOT = Path(__file__).resolve().parents[2]
TAMPER_SQL = ROOT / "scripts" / "provision_tamper_role.sql"
Append = Callable[..., AuditRecord]
Load = Callable[[], list[ChainEntry]]
V = ViolationType


@pytest.fixture(scope="session")
def tamper_role(database_url: URL) -> URL:
    from sqlalchemy import create_engine, pool

    engine = create_engine(database_url, isolation_level="AUTOCOMMIT", poolclass=pool.NullPool)
    with engine.connect() as connection:
        connection.execute(text(TAMPER_SQL.read_text(encoding="utf-8")))
        # Idempotent: a second run changes nothing and still passes its safety check.
        connection.execute(text(TAMPER_SQL.read_text(encoding="utf-8")))
    engine.dispose()
    return database_url


@pytest.fixture
def tamper(load_script: Callable[[str], ModuleType]) -> ModuleType:
    return load_script("tamper_demo")


@pytest.fixture
def run_tamper(tamper: ModuleType, tamper_role: URL) -> Callable[..., tuple[int, str, str]]:
    def run(*argv: str, engine: Engine | None = None) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        code: int = tamper.run(
            list(argv),
            environ={},
            stdout=stdout,
            stderr=stderr,
            engine=engine
            or tamper.tamper_engine(tamper_role.render_as_string(hide_password=False)),
        )
        return code, stdout.getvalue(), stderr.getvalue()

    return run


def _first(result: VerificationResult) -> tuple[ViolationType, int] | None:
    violation = result.first_violation
    return None if violation is None else (violation.type, violation.sequence)


def _head(entries: list[ChainEntry]) -> ChainHead:
    record = entries[-1].record
    return ChainHead(sequence=record.sequence, record_hash=record.record_hash)


# --- The tamper role (ADR-0009 constraint) ------------------------------------------------------


def test_tamper_role_is_a_restricted_nologin_role(owner_engine: Engine, tamper_role: URL) -> None:
    with owner_engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT rolsuper, rolcanlogin, rolcreaterole, rolcreatedb, rolbypassrls, "
                "pg_has_role('audit_log_tamper', 'pg_write_server_files', 'MEMBER'), "
                "pg_has_role('audit_log_tamper', 'pg_execute_server_program', 'MEMBER'), "
                "pg_has_role('audit_log_tamper', 'pg_read_server_files', 'MEMBER') "
                "FROM pg_roles WHERE rolname = 'audit_log_tamper'"
            )
        ).one()
    assert not any(row)


def test_tamper_role_cannot_write_server_files(
    tamper: ModuleType, tamper_role: URL, tmp_path: Path
) -> None:
    engine = tamper.tamper_engine(tamper_role.render_as_string(hide_password=False))
    try:
        with (
            pytest.raises(ProgrammingError, match=r"permission denied|must be superuser"),
            engine.begin() as connection,
        ):
            connection.execute(text("COPY (SELECT 1) TO '/tmp/audit-log-tamper-probe'"))
    finally:
        engine.dispose()


def test_tamper_role_cannot_change_the_schema(tamper: ModuleType, tamper_role: URL) -> None:
    engine = tamper.tamper_engine(tamper_role.render_as_string(hide_password=False))
    try:
        with (
            pytest.raises(ProgrammingError, match=r"must be owner|permission denied"),
            engine.begin() as connection,
        ):
            connection.execute(text("ALTER TABLE audit_records DISABLE TRIGGER ALL"))
    finally:
        engine.dispose()


def test_tamper_demo_refuses_a_session_that_is_not_the_tamper_role(
    run_tamper: Callable[..., tuple[int, str, str]], owner_engine: Engine, append: Append
) -> None:
    append()
    code, out, err = run_tamper("modify", "--sequence", "1", engine=owner_engine)
    assert (code, out) == (2, "")
    assert err.startswith("refused: the session must act as audit_log_tamper")


# --- Scenario A tampering, detected by verification ---------------------------------------------


@pytest.mark.parametrize(
    ("argv", "expected", "records"),
    [
        (("modify", "--sequence", "2"), (V.CONTENT_HASH_MISMATCH, 2), 4),
        (("delete", "--sequence", "2"), (V.SEQUENCE_GAP, 3), 3),
        (("insert", "--sequence", "2"), (V.PREVIOUS_HASH_MISMATCH, 2), 5),
        (("reorder", "--sequence", "2"), (V.PREVIOUS_HASH_MISMATCH, 2), 4),
    ],
    ids=["modification", "middle-deletion", "insertion", "reordering"],
)
def test_tampering_is_detected(
    run_tamper: Callable[..., tuple[int, str, str]],
    append: Append,
    load: Load,
    argv: tuple[str, ...],
    expected: tuple[ViolationType, int],
    records: int,
) -> None:
    for _ in range(4):
        append()
    assert verify_chain(load()).intact

    code, out, err = run_tamper(*argv)

    assert (code, err) == (0, ""), err
    assert out.strip()
    result = verify_chain(load())
    assert _first(result) == expected
    assert result.records_checked == records


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (("truncate", "--after", "2"), (V.CHAIN_TRUNCATED, 3)),
        (("rewrite", "--sequence", "2"), (V.ANCHOR_MISMATCH, 4)),
    ],
    ids=["tail-truncation", "full-rewrite"],
)
def test_truncation_and_rewrite_need_the_checkpoint(
    run_tamper: Callable[..., tuple[int, str, str]],
    append: Append,
    load: Load,
    argv: tuple[str, ...],
    expected: tuple[ViolationType, int],
) -> None:
    for _ in range(4):
        append()
    anchor = _head(load())

    assert run_tamper(*argv)[0] == 0

    entries = load()
    assert verify_chain(entries).intact  # undetectable without the trusted checkpoint
    assert _first(verify_chain(entries, anchor)) == expected


def test_rewrite_of_the_first_record_stays_consistent(
    run_tamper: Callable[..., tuple[int, str, str]], append: Append, load: Load
) -> None:
    append()
    append()
    anchor = _head(load())
    assert run_tamper("rewrite", "--sequence", "1")[0] == 0
    entries = load()
    assert verify_chain(entries).intact
    assert _first(verify_chain(entries, anchor)) == (V.ANCHOR_MISMATCH, 2)


@pytest.mark.parametrize(
    "argv",
    [
        ("modify", "--sequence", "9"),
        ("reorder", "--sequence", "2"),
        ("rewrite", "--sequence", "9"),
    ],
    ids=["missing", "no-successor", "rewrite-missing"],
)
def test_changes_to_missing_records_are_refused(
    run_tamper: Callable[..., tuple[int, str, str]],
    append: Append,
    load: Load,
    argv: tuple[str, ...],
) -> None:
    append()
    append()
    code, _, err = run_tamper(*argv)
    assert code == 2
    assert err.startswith("refused: no record has sequence")
    assert verify_chain(load()).intact


def test_tamper_demo_configuration_and_usage_errors(tamper: ModuleType) -> None:
    stderr = io.StringIO()
    assert (
        tamper.run(["modify", "--sequence", "1"], environ={}, stdout=io.StringIO(), stderr=stderr)
        == 2
    )
    assert stderr.getvalue() == "configuration error: AUDIT_LOG_TAMPER_DATABASE_URL must be set\n"
    stderr = io.StringIO()
    assert tamper.run(["modify"], environ={}, stdout=io.StringIO(), stderr=stderr) == 2
    assert stderr.getvalue().startswith("usage error: ")
