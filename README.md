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

## Running the service

The service reads its configuration from the environment once, at startup, and refuses to start if any of it is invalid:

| Variable | Purpose |
|---|---|
| `AUDIT_LOG_DATABASE_URL` | Database URL for a login user that is a member of `audit_log_app` (never the owner; the service refuses a login that can update or delete audit records) |
| `AUDIT_LOG_API_KEYS_FILE` | API-key configuration (see `config/api-keys.example.toml`) |
| `AUDIT_LOG_VOCABULARY_FILE` | Scenario C vocabulary (see `config/client-account-vocabulary.example.toml`) |
| `AUDIT_LOG_TIMESTAMP_SKEW_SECONDS` | Optional; how far a caller `timestamp` may be ahead of `recordedAt` (default 300) |
| `AUDIT_LOG_RETENTION_WINDOW_SECONDS` | Optional; records older than this are archived by a retention run. Unset disables retention |
| `AUDIT_LOG_RETENTION_BATCH_SIZE` | Optional; payload values purged per batch (default 500) |
| `AUDIT_LOG_RETENTION_MAX_BATCHES` | Optional; batches per retention run before it stops with `503` and leaves the rest for the next run (default 20) |

```sh
uv run uvicorn audit_log_service.api.app:create_app --factory
```

Implemented endpoints: `POST /audit/events`, `GET /audit/events`, `GET /audit/events/{id}`, `GET /audit/verify`, `POST /audit/events/{id}/redactions`, and `POST /audit/retention-runs`. The OpenAPI document is served at `/openapi.json` and `/docs`.

## Redaction guidance for operators

Redaction (`POST /audit/events/{id}/redactions`, administrators only) permanently deletes the selected payload values and records who did it and why in an `AUDIT_LOG_REDACTION` event. The reason is stored and shown to readers exactly as given, so it must never contain the value being redacted. Redaction cannot be undone, and payload keys and structure remain visible.

## Tests

- `uv run pytest tests/unit` runs the unit tests, which need no database.
- `uv run pytest --cov` runs everything, including the PostgreSQL integration tests. These need `AUDIT_LOG_TEST_DATABASE_URL`: a server URL for a role that can create databases and roles and `SET ROLE audit_log_app`, such as the compose superuser (`postgresql+psycopg://postgres:<password>@127.0.0.1:5432/postgres`). The tests create and drop their own throwaway databases. If the variable is not set, they fail rather than being skipped.
