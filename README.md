# audit-log-service
Tamper-evident, append-only audit log service with a SHA-256 hash chain, chain verification, retention, chain-safe redaction and verifiable exports. FastAPI + PostgreSQL.

## Documentation

| Document | Contents |
|---|---|
| [docs/demo.md](docs/demo.md) | Step-by-step setup and the Scenario A, B, and C walkthrough |
| [docs/requirements.md](docs/requirements.md) | Requirements baseline and the API definitions of every phase |
| [docs/architecture.md](docs/architecture.md) | Architecture, trust boundaries, and limitations |
| [docs/adr/](docs/adr/) | Architecture decision records 0001 to 0009 |
| [docs/testing.md](docs/testing.md) | Testing approach, test layers, and limitations |
| [docs/performance.md](docs/performance.md) | NFR-3 measurements and observations |
| [docs/engineering-summary.md](docs/engineering-summary.md) | Engineering summary, traceability, final validation, limitations |
| [docs/ai-usage-log.md](docs/ai-usage-log.md) | Record of AI-assisted engineering work |

Requirements: Python 3.13, [uv](https://docs.astral.sh/uv/), Docker (for PostgreSQL), and OpenSSL (for demo keys). `uv sync --locked` installs the pinned dependencies.

## Local database

The compose file runs PostgreSQL for local development only.

1. Copy `.env.example` to `.env` (gitignored), set `POSTGRES_PASSWORD`, and run `docker compose up -d`.
2. Provision the group roles once per server, as the owner. The script is idempotent and creates only the `NOLOGIN` roles `audit_log_app` (the service) and `audit_log_checkpoint` (the read-only checkpoint CLI):

   ```sh
   docker compose exec -T postgres psql -U postgres -d audit_log < scripts/provision_database_roles.sql
   ```

3. Apply the migrations as the schema owner. The URL is read only from the environment:

   ```sh
   export AUDIT_LOG_MIGRATION_DATABASE_URL="postgresql+psycopg://postgres:<password>@127.0.0.1:5432/audit_log"
   uv run alembic upgrade head
   ```

   The migrations are irreversible: `alembic downgrade` refuses to drop the audit tables.

Application login users are created outside source control as members of `audit_log_app`, which may only select and insert audit records, and the checkpoint CLI's login as a member of `audit_log_checkpoint`, which may only select (see ADR-0009). [docs/demo.md](docs/demo.md) shows the commands for a local demonstration.

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
| `AUDIT_LOG_CHECKPOINT_STORE_DIR` | The checkpoint store directory, outside the database; the service only reads it |
| `AUDIT_LOG_CHECKPOINT_PUBLIC_KEY_FILE` | The trusted checkpoint public key (Ed25519, SubjectPublicKeyInfo PEM). The service never holds the private key |
| `AUDIT_LOG_EXPORT_SIGNING_KEY_FILE` | Optional; the export signing key (unencrypted Ed25519 PKCS#8 PEM), separate from the checkpoint key. Without it, exports return `503` |
| `AUDIT_LOG_EXPORT_MAX_RECORDS` | Optional; records per export (default 1,000, at most 10,000) |
| `AUDIT_LOG_EXPORT_MAX_BYTES` | Optional; bytes per export bundle (default 64 MiB, at most 1 GiB) |

```sh
uv run uvicorn audit_log_service.api.app:create_app --factory --no-access-log
```

Run it with `--no-access-log`: Uvicorn's access log records full request lines, including query strings such as `?actorId=...`, which the service's own logs deliberately omit (architecture §4). The service's own log lines carry request identifiers, methods, paths, and statuses, never credentials, payload values, salts, keys, or query strings. No logging configuration is applied, so at Python's default WARNING level only denied attempts and unexpected errors appear; INFO lines such as an export's record count appear only if the logging level is set to INFO.

| Endpoint | Capability | Purpose |
|---|---|---|
| `GET /health/live` | none | Liveness: `200 {"status": "ok"}` |
| `GET /health/ready` | none | Readiness: `200` when the database answers, otherwise `503` |
| `POST /audit/events` | `events:write` | Append an event (`201` with `Location`) |
| `GET /audit/events` | `events:read` | Query with filters and cursor pagination |
| `GET /audit/events/{id}` | `events:read` | Retrieve one event |
| `GET /audit/verify` | `chain:verify` | Verify the whole chain (against the latest checkpoint) |
| `POST /audit/events/{id}/redactions` | `events:redact` | Redact payload values |
| `POST /audit/retention-runs` | `retention:run` | Run bounded retention |
| `POST /audit/exports` | `export:create` | Create a signed export bundle |

The OpenAPI document is served at `/openapi.json` and `/docs`. Examples, with keys in shell variables:

```sh
curl -s -X POST http://127.0.0.1:8000/audit/events -H "Authorization: Bearer $WRITER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"eventType": "ORDER_PLACED", "actorId": "user-7", "resourceType": "ORDER", "resourceId": "order-1", "payload": {"amount": 12.5}}'
curl -s "http://127.0.0.1:8000/audit/events?resourceId=order-1&limit=50" -H "Authorization: Bearer $AUDITOR_KEY"
curl -s http://127.0.0.1:8000/audit/verify -H "Authorization: Bearer $AUDITOR_KEY"
curl -s -X POST http://127.0.0.1:8000/audit/events/$EVENT_ID/redactions -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" -d '{"paths": ["/amount"], "reason": "customer request"}'
curl -s -X POST http://127.0.0.1:8000/audit/retention-runs -H "Authorization: Bearer $ADMIN_KEY"
```

Errors are RFC 9457 Problem Details with a `requestId` that matches the `X-Request-ID` response header.

## Checkpoints

Signed checkpoints let verification detect truncation below, and a rewrite of, the latest checkpointed record (requirements FR-4, ADR-0006). Records appended after the latest checkpoint are not protected against an attacker with database write access, so create checkpoints regularly. Nothing creates them automatically.

Generate the checkpoint key pair outside the repository, keep the private key readable only by the operator, and give the service only the public key. It is separate from any export signing key:

```sh
openssl genpkey -algorithm ed25519 -out /secure/path/checkpoint-signing.pem
openssl pkey -in /secure/path/checkpoint-signing.pem -pubout -out /secure/path/checkpoint-public.pem
```

The checkpoint CLI reads its configuration from the environment:

| Variable | Purpose |
|---|---|
| `AUDIT_LOG_CHECKPOINT_DATABASE_URL` | Database URL for a login user that is a member of `audit_log_checkpoint` (read-only; the CLI refuses a login that can change audit data) |
| `AUDIT_LOG_API_KEYS_FILE` | The same API-key configuration as the service |
| `AUDIT_LOG_CHECKPOINT_STORE_DIR` | The checkpoint store directory |
| `AUDIT_LOG_CHECKPOINT_SIGNING_KEY_FILE` | The unencrypted Ed25519 PKCS#8 PEM private key, read only after the operator is authorized |

An administrator (`checkpoint:create`) creates a checkpoint by giving the API key on stdin, never as an argument or environment variable. On a terminal the key is prompted for without echo:

```sh
uv run audit-log-checkpoint create
uv run audit-log-checkpoint create < /secure/path/operator-api-key   # non-interactive
```

The CLI verifies the whole chain against the latest checkpoint and refuses (exit code 1) if it is not intact or is empty. Otherwise it writes `checkpoint-<sequence>.json` to the store, or reports `CHECKPOINT_CURRENT` when the head is already checkpointed. It prints one JSON line. Other exit codes: 2 usage or configuration error, 3 authentication failed, 4 not authorized, 5 database or store unavailable.

Anyone with the public key, obtained out of band, can verify checkpoint artifacts without the service or database:

```sh
uv run audit-log-verify checkpoint --public-key checkpoint-public.pem checkpoint-00000000000000000042.json
```

Deploy the store so that the service can only read it and the database cannot reach it; a database superuser can write files on the database host (ADR-0009).

## Exports

Auditors and regulators (`export:create`) export every record matching exactly one scope, `{"actorId"}`, `{"resourceId"}`, or `{"resourceId", "resourceType"}`, as a signed bundle (requirements FR-7):

```sh
curl -s -X POST http://127.0.0.1:8000/audit/exports \
  -H "Authorization: Bearer $AUDITOR_KEY" -H "Content-Type: application/json" \
  -d '{"resourceId": "acct-42", "resourceType": "CLIENT_ACCOUNT"}' > export.json
```

The bundle contains payload values and their salts: handle it as sensitive data. The service verifies the whole chain before signing and refuses (`409`) while it is broken. Each export is recorded as an `AUDIT_LOG_EXPORT` event.

Generate the export key pair like the checkpoint key pair, but as a separate key, and give recipients the public key out of band. Anyone with it can verify a bundle without the service or database, optionally anchoring checkpoints to it:

```sh
uv run audit-log-verify export --public-key export-public.pem export.json \
  --checkpoint-public-key checkpoint-public.pem --checkpoint checkpoint-00000000000000000042.json
```

The verifier prints a summary line and one line per checkpoint (`MATCH`, `MISMATCH`, `NOT_APPLICABLE`, or `INVALID`), and exits 0 when everything is valid, 1 otherwise, and 2 on a usage error. It never prints payload values.

## Demonstration tooling

Everything below is for local demonstrations only; [docs/demo.md](docs/demo.md) uses it step by step.

- `scripts/demo_setup.py keys --output local/api-keys.toml` generates random demo API keys, writes only their SHA-256 digests, and prints the raw keys once. `local/` is gitignored; never commit either file.
- `scripts/demo_setup.py seed` appends the Scenario C demonstration events through the API, with the writer's key on stdin.
- `scripts/provision_tamper_role.sql` creates the demonstration-only `audit_log_tamper` role: no login, not a superuser, no server-file or program roles (ADR-0009).
- `scripts/tamper_demo.py` tampers with the database directly as that role (modify, delete, insert, reorder, truncate, rewrite), never through the API, so verification can be shown to detect it. In the local demonstration it logs in as the owner (a superuser) and switches to the tamper role with `SET ROLE`; the database does not enforce that switch, so a dedicated non-superuser login in `audit_log_tamper` only is the production recommendation ([docs/demo.md](docs/demo.md), ADR-0009).

## Redaction guidance for operators

Redaction (`POST /audit/events/{id}/redactions`, administrators only) permanently deletes the selected payload values and records who did it and why in an `AUDIT_LOG_REDACTION` event. The reason is stored and shown to readers exactly as given, so it must never contain the value being redacted. Redaction cannot be undone, and payload keys and structure remain visible.

## Tests

- `uv run pytest tests/unit` runs the unit tests, which need no database.
- `uv run pytest --cov` runs everything, including the PostgreSQL integration tests. These need `AUDIT_LOG_TEST_DATABASE_URL`: a server URL for a role that can create databases and roles and `SET ROLE` to `audit_log_app` and `audit_log_checkpoint`, such as the compose superuser (`postgresql+psycopg://postgres:<password>@127.0.0.1:5432/postgres`). The tests create and drop their own throwaway databases. If the variable is not set, they fail rather than being skipped.
- Coverage must be 100% of statements and branches of the `audit_log_service` package (`fail_under = 100`).
- Quality gates: `uv run ruff format --check .`, `uv run ruff check .`, `uv run pyright`, `uv run bandit -c pyproject.toml -r src migrations scripts`, `uv run pip-audit`, `uv lock --check`.
- `scripts/benchmark.py` runs the NFR-3 measurements against a disposable PostgreSQL server named by `AUDIT_LOG_BENCHMARK_SERVER_URL`; results are in [docs/performance.md](docs/performance.md). It is not part of the test suite.

See [docs/testing.md](docs/testing.md) for the approach and its limitations.

## Limitations

This is a prototype. The main limitations, detailed in [docs/engineering-summary.md](docs/engineering-summary.md) and the architecture document, are: static API keys and prototype roles rather than an identity provider; plain HTTP for local use; keys, the checkpoint store, and configuration on the application host, with production key management deferred; records after the latest checkpoint are not protected against an attacker with database write access, and checkpoints are created manually; verification and exports verify the whole chain in memory; appends are serialized; exports are single bounded bundles whose completeness is attested by the signature; payload keys remain visible after redaction; and the Scenario C interpretation rests on documented assumptions awaiting stakeholder confirmation.
