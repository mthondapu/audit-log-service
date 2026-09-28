# audit-log-service
Tamper-evident, append-only audit log service with a SHA-256 hash chain, chain verification, retention, chain-safe redaction and verifiable exports. FastAPI + PostgreSQL.

## Local database

The compose file runs PostgreSQL for local development only.

1. Copy `.env.example` to `.env` (gitignored), set `POSTGRES_PASSWORD`, and run `docker compose up -d`.
2. Provision the application group role once per server, as the owner. The script is idempotent and creates only the `NOLOGIN` role `audit_log_app`:

   ```sh
   docker compose exec -T postgres psql -U postgres -d audit_log < scripts/provision_database_roles.sql
   ```

3. Apply the migrations as the schema owner. The URL is read only from the environment:

   ```sh
   export AUDIT_LOG_MIGRATION_DATABASE_URL="postgresql+psycopg://postgres:<password>@127.0.0.1:5432/audit_log"
   uv run alembic upgrade head
   ```

   The initial migration is irreversible: `alembic downgrade` refuses to drop the audit tables.

Application login users are created outside source control as members of `audit_log_app`, which may only select and insert audit records (see ADR-0009).

## Tests

- `uv run pytest tests/unit` runs the unit tests, which need no database.
- `uv run pytest --cov` runs everything, including the PostgreSQL integration tests. These need `AUDIT_LOG_TEST_DATABASE_URL`: a server URL for a role that can create databases and roles and `SET ROLE audit_log_app`, such as the compose superuser (`postgresql+psycopg://postgres:<password>@127.0.0.1:5432/postgres`). The tests create and drop their own throwaway databases. If the variable is not set, they fail rather than being skipped.
