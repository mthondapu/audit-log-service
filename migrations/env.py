"""Alembic environment for the audit log schema.

Migrations run as the schema owner, using the URL in AUDIT_LOG_MIGRATION_DATABASE_URL. Tests may
instead supply an open connection through `config.attributes["connection"]`. Offline (SQL script)
mode is not supported.
"""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, create_engine, pool

MIGRATION_URL_VARIABLE = "AUDIT_LOG_MIGRATION_DATABASE_URL"

config = context.config


def _run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=None)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    supplied: Connection | None = config.attributes.get("connection")
    if supplied is not None:
        _run_migrations(supplied)
        return

    if config.config_file_name is not None:
        fileConfig(config.config_file_name, disable_existing_loggers=False)
    url = os.environ.get(MIGRATION_URL_VARIABLE)
    if not url:
        raise RuntimeError(
            f"{MIGRATION_URL_VARIABLE} must be set to the schema owner's database URL "
            "(postgresql+psycopg://...)"
        )
    engine = create_engine(url, poolclass=pool.NullPool)
    try:
        with engine.connect() as connection:
            _run_migrations(connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("Offline migration mode is not supported")
run_migrations_online()
