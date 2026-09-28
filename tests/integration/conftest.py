"""PostgreSQL integration-test harness.

AUDIT_LOG_TEST_DATABASE_URL must name a PostgreSQL server as a role that can create databases,
create roles, and `SET ROLE audit_log_app` (for local development, the compose superuser). The
suite fails, rather than being skipped, when it is not set.

Per session, the harness provisions the group role, creates a throwaway database, and migrates it
with Alembic. Each test starts from empty tables. Application-path tests connect as the owner and
switch to `audit_log_app` with `SET ROLE`, so every append runs with the application's privileges
and no application password is needed.
"""

import os
import secrets
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import URL, Connection, Engine, create_engine, event, insert, make_url, pool, text

from audit_log_service.integrity.hashing import AuditRecord
from audit_log_service.integrity.timestamps import parse_timestamp
from audit_log_service.integrity.verification import ChainEntry
from audit_log_service.persistence.audit_log import NewEvent, append_event, load_chain_entries
from audit_log_service.persistence.schema import APPLICATION_ROLE, audit_records

TEST_URL_VARIABLE = "AUDIT_LOG_TEST_DATABASE_URL"
ROOT = Path(__file__).resolve().parents[2]
PROVISIONING_SQL = ROOT / "scripts" / "provision_database_roles.sql"

AppendEvent = Callable[..., AuditRecord]
LoadEntries = Callable[[], list[ChainEntry]]


def alembic_config() -> Config:
    return Config(str(ROOT / "alembic.ini"))


def migrate(engine: Engine) -> None:
    with engine.begin() as connection:
        config = alembic_config()
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


@pytest.fixture(scope="session")
def server_url() -> URL:
    raw = os.environ.get(TEST_URL_VARIABLE)
    if not raw:
        pytest.fail(
            f"{TEST_URL_VARIABLE} is not set. The PostgreSQL integration tests need a server URL "
            "(postgresql+psycopg://...) for a role that can create databases and roles; see "
            "README.md.",
            pytrace=False,
        )
    return make_url(raw)


@pytest.fixture(scope="session")
def create_database(server_url: URL) -> Iterator[Callable[[], URL]]:
    """Create throwaway databases on the test server; all are dropped at session end."""
    admin = create_engine(server_url, isolation_level="AUTOCOMMIT", poolclass=pool.NullPool)
    with admin.connect() as connection:
        connection.execute(text(PROVISIONING_SQL.read_text(encoding="utf-8")))
    created: list[str] = []

    def create() -> URL:
        name = f"audit_log_test_{secrets.token_hex(6)}"
        with admin.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{name}"'))
        created.append(name)
        return server_url.set(database=name)

    try:
        yield create
    finally:
        with admin.connect() as connection:
            for name in created:
                connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.fixture(scope="session")
def database_url(create_database: Callable[[], URL]) -> URL:
    url = create_database()
    engine = create_engine(url, poolclass=pool.NullPool)
    migrate(engine)
    engine.dispose()
    return url


@pytest.fixture(scope="session")
def owner_engine(database_url: URL) -> Iterator[Engine]:
    engine = create_engine(database_url)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def app_engine(database_url: URL) -> Iterator[Engine]:
    engine = create_engine(database_url, pool_size=10, max_overflow=10)

    @event.listens_for(engine, "connect")
    def use_application_role(dbapi_connection: Any, _record: Any) -> None:  # pyright: ignore[reportUnusedFunction]
        dbapi_connection.execute(f"SET ROLE {APPLICATION_ROLE}")
        dbapi_connection.commit()

    yield engine
    engine.dispose()


@pytest.fixture(autouse=True)
def empty_tables(owner_engine: Engine) -> None:
    with owner_engine.begin() as connection:
        connection.execute(text("TRUNCATE audit_payload_values, audit_records"))


def make_event(**changes: Any) -> NewEvent:
    fields: dict[str, Any] = {
        "event_type": "CLIENT_ACCOUNT_VIEWED",
        "actor_id": "user-7",
        "resource_type": "CLIENT_ACCOUNT",
        "resource_id": "acct-42",
        "timestamp": None,
        "recorded_by": "svc-writer",
        "payload": {"channel": "web", "fields": ["email", "phone"]},
    }
    fields.update(changes)
    return NewEvent(**fields)


@pytest.fixture
def append(app_engine: Engine) -> AppendEvent:
    """Append one event in its own transaction, as the application role."""

    def run(**changes: Any) -> AuditRecord:
        with app_engine.begin() as connection:
            return append_event(connection, make_event(**changes))

    return run


@pytest.fixture
def load(app_engine: Engine) -> LoadEntries:
    def run() -> list[ChainEntry]:
        with app_engine.begin() as connection:
            return load_chain_entries(connection)

    return run


@pytest.fixture
def new_event() -> Callable[..., NewEvent]:
    return make_event


InsertSealed = Callable[..., None]


@pytest.fixture
def insert_sealed() -> InsertSealed:
    """Insert an already-sealed record directly, bypassing the append path."""

    def run(connection: Connection, record: AuditRecord, **overrides: Any) -> None:
        content = record.content
        row: dict[str, Any] = {
            "id": uuid.UUID(content.id),
            "sequence": record.sequence,
            "previous_hash": record.previous_hash,
            "content_hash": record.content_hash,
            "record_hash": record.record_hash,
            "event_type": content.event_type,
            "actor_id": content.actor_id,
            "resource_type": content.resource_type,
            "resource_id": content.resource_id,
            "timestamp": None if content.timestamp is None else parse_timestamp(content.timestamp),
            "recorded_at": parse_timestamp(content.recorded_at),
            "recorded_by": content.recorded_by,
            "committed_payload": content.payload,
        }
        row.update(overrides)
        connection.execute(insert(audit_records).values(**row))

    return run


@pytest.fixture
def migration_config() -> Callable[[], Config]:
    return alembic_config


@pytest.fixture
def run_migrations() -> Callable[[Engine], None]:
    return migrate
