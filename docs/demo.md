# Demonstration walkthrough

A reviewer's walkthrough of the Audit Log Service on a local machine: setup from nothing, then Scenario C, Scenario B, checkpoints, and Scenario A (requirements §9). Everything here is for local demonstration only. The commands are for a POSIX shell (bash, including Git Bash on Windows) from the repository root.

Tampering cannot be undone: once the chain is broken, verification, checkpoints, and exports are refused until the environment is reset. The walkthrough therefore tampers last. [Reset](#reset) describes how to start again, for example to show another kind of tampering.

## 1. Setup

Prerequisites: Docker, Python 3.13 with [uv](https://docs.astral.sh/uv/), OpenSSL, `curl`, and `jq` (optional, for readable output).

```sh
uv sync --locked
cp .env.example .env                                 # then set POSTGRES_PASSWORD in .env
set -a; . ./.env; set +a
docker compose up -d
export OWNER_URL="postgresql+psycopg://postgres:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT:-5432}/audit_log"
```

Provision the group roles, migrate as the owner, and provision the demonstration-only tamper role:

```sh
docker compose exec -T postgres psql -U postgres -d audit_log -v ON_ERROR_STOP=1 < scripts/provision_database_roles.sql
AUDIT_LOG_MIGRATION_DATABASE_URL="$OWNER_URL" uv run alembic upgrade head
docker compose exec -T postgres psql -U postgres -d audit_log -v ON_ERROR_STOP=1 < scripts/provision_tamper_role.sql
```

Create the service's and the checkpoint CLI's login users, with passwords generated locally and never stored in the repository:

```sh
export APP_DB_PASSWORD="$(openssl rand -hex 16)" CHECKPOINT_DB_PASSWORD="$(openssl rand -hex 16)"
docker compose exec -T postgres psql -U postgres -d audit_log -v ON_ERROR_STOP=1 \
  -c "CREATE ROLE demo_app LOGIN PASSWORD '${APP_DB_PASSWORD}' IN ROLE audit_log_app" \
  -c "CREATE ROLE demo_checkpoint LOGIN PASSWORD '${CHECKPOINT_DB_PASSWORD}' IN ROLE audit_log_checkpoint"
```

Generate the demo API keys and the two separate Ed25519 key pairs in the gitignored `local/` directory:

```sh
mkdir -p local/checkpoints
uv run python scripts/demo_setup.py keys --output local/api-keys.toml > local/demo-keys.env
. local/demo-keys.env                                 # WRITER_KEY, AUDITOR_KEY, REGULATOR_KEY, ADMIN_KEY
openssl genpkey -algorithm ed25519 -out local/checkpoint-signing.pem
openssl pkey -in local/checkpoint-signing.pem -pubout -out local/checkpoint-public.pem
openssl genpkey -algorithm ed25519 -out local/export-signing.pem
openssl pkey -in local/export-signing.pem -pubout -out local/export-public.pem
```

Configure and start the service in its own terminal (after `set -a; . ./.env; set +a` and the password exports there too):

```sh
export AUDIT_LOG_DATABASE_URL="postgresql+psycopg://demo_app:${APP_DB_PASSWORD}@127.0.0.1:${POSTGRES_PORT:-5432}/audit_log"
export AUDIT_LOG_API_KEYS_FILE=local/api-keys.toml
export AUDIT_LOG_VOCABULARY_FILE=config/client-account-vocabulary.example.toml
export AUDIT_LOG_CHECKPOINT_STORE_DIR=local/checkpoints
export AUDIT_LOG_CHECKPOINT_PUBLIC_KEY_FILE=local/checkpoint-public.pem
export AUDIT_LOG_EXPORT_SIGNING_KEY_FILE=local/export-signing.pem
export AUDIT_LOG_RETENTION_WINDOW_SECONDS=2592000     # 30 days
uv run uvicorn audit_log_service.api.app:create_app --factory --no-access-log
```

Back in the first terminal:

```sh
export BASE=http://127.0.0.1:8000
curl -s $BASE/health/live; echo
curl -s $BASE/health/ready; echo                      # {"status":"ok"}
```

Security spot checks: starting the service with `AUDIT_LOG_DATABASE_URL="$OWNER_URL"` is refused (the owner can update and delete audit records), and `curl -s $BASE/audit/verify` without a key returns `401` Problem Details.

## 2. Scenario C: regulatory access to client account data

The clarified interpretation, assumptions SC-A1 to SC-A8, scope, and scope-outs are in requirements FR-8. Seed the demonstration events through the API; the writer's key is read from stdin:

```sh
printf '%s\n' "$WRITER_KEY" | uv run python scripts/demo_setup.py seed --base-url $BASE
```

Access events for `CLIENT_ACCOUNT` must use the configured vocabulary and its required payload keys:

```sh
curl -s -X POST $BASE/audit/events -H "Authorization: Bearer $WRITER_KEY" -H "Content-Type: application/json" \
  -d '{"eventType": "CLIENT_ACCOUNT_EXPORTED", "actorId": "advisor-17", "resourceType": "CLIENT_ACCOUNT", "resourceId": "acct-1001", "payload": {}}'
# 422: the event type is not in the access-event vocabulary
```

A regulator retrieves the access events for one account, verifies the chain, and obtains a signed export:

```sh
curl -s "$BASE/audit/events?resourceType=CLIENT_ACCOUNT&resourceId=acct-1001" -H "Authorization: Bearer $REGULATOR_KEY" | jq '.items[] | {sequence, eventType, actorId}'
curl -s $BASE/audit/verify -H "Authorization: Bearer $REGULATOR_KEY" | jq '{intact, recordsChecked, anchor}'
curl -s -X POST $BASE/audit/exports -H "Authorization: Bearer $REGULATOR_KEY" -H "Content-Type: application/json" \
  -d '{"resourceId": "acct-1001", "resourceType": "CLIENT_ACCOUNT"}' > local/acct-1001-export.json
curl -s "$BASE/audit/events?eventType=AUDIT_LOG_EXPORT" -H "Authorization: Bearer $REGULATOR_KEY" | jq '.items[] | {sequence, resourceId, recordedBy}'
```

The last query shows the export itself recorded as an `AUDIT_LOG_EXPORT` event (SC-A6). The writer cannot read, and the regulator cannot redact (`403`).

## 3. Scenario B: redaction, retention, and export

Redact a value as the administrator; the value becomes `null`, `redactedPaths` lists it, and the chain stays intact:

```sh
EVENT_ID=$(curl -s "$BASE/audit/events?resourceId=acct-1001" -H "Authorization: Bearer $AUDITOR_KEY" | jq -r '.items[0].id')
curl -s -X POST $BASE/audit/events/$EVENT_ID/redactions -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" -d '{"paths": ["/purpose"], "reason": "data subject request"}' | jq '{sequence, eventType}'
curl -s $BASE/audit/events/$EVENT_ID -H "Authorization: Bearer $AUDITOR_KEY" | jq '{payload, redactedPaths}'
curl -s $BASE/audit/verify -H "Authorization: Bearer $AUDITOR_KEY" | jq '{intact}'
```

Retention archives records older than the configured window. Freshly appended events are not old enough, so a run reports `NOTHING_ELIGIBLE`; the retention path with old records (archiving, payload purge, and continued verification) is exercised by the integration tests and the benchmark:

```sh
curl -s -X POST $BASE/audit/retention-runs -H "Authorization: Bearer $ADMIN_KEY" | jq
```

Export every record for an actor and verify the bundle offline, with only the export public key:

```sh
curl -s -X POST $BASE/audit/exports -H "Authorization: Bearer $AUDITOR_KEY" -H "Content-Type: application/json" \
  -d '{"actorId": "advisor-17"}' > local/advisor-17-export.json
uv run audit-log-verify export --public-key local/export-public.pem local/advisor-17-export.json
```

## 4. Checkpoints

Create a checkpoint as the administrator (the key is read from stdin, never from arguments or the environment); a writer's key is refused:

```sh
export AUDIT_LOG_CHECKPOINT_DATABASE_URL="postgresql+psycopg://demo_checkpoint:${CHECKPOINT_DB_PASSWORD}@127.0.0.1:${POSTGRES_PORT:-5432}/audit_log"
export AUDIT_LOG_CHECKPOINT_SIGNING_KEY_FILE=local/checkpoint-signing.pem
printf '%s\n' "$WRITER_KEY" | uv run audit-log-checkpoint create; echo "exit $?"   # Not authorized (4)
printf '%s\n' "$ADMIN_KEY" | uv run audit-log-checkpoint create                   # CHECKPOINT_CREATED
curl -s $BASE/audit/verify -H "Authorization: Bearer $AUDITOR_KEY" | jq '.anchor'   # VERIFIED
uv run audit-log-verify checkpoint --public-key local/checkpoint-public.pem local/checkpoints/*.json
```

Export again and anchor the checkpoint to the bundle (L-D1): it matches at `asOfSequence`, or is `NOT_APPLICABLE` when the export has no signed evidence at its sequence:

```sh
curl -s -X POST $BASE/audit/exports -H "Authorization: Bearer $AUDITOR_KEY" -H "Content-Type: application/json" \
  -d '{"resourceId": "acct-1001"}' > local/acct-1001-anchored.json
uv run audit-log-verify export --public-key local/export-public.pem local/acct-1001-anchored.json \
  --checkpoint-public-key local/checkpoint-public.pem $(for f in local/checkpoints/*.json; do printf -- '--checkpoint %s ' "$f"; done)
```

## 5. Scenario A: tampering is detected

Append a few more events, query them, and verify that the chain is intact:

```sh
for n in 1 2 3; do curl -s -X POST $BASE/audit/events -H "Authorization: Bearer $WRITER_KEY" -H "Content-Type: application/json" \
  -d "{\"eventType\": \"ORDER_PLACED\", \"actorId\": \"user-$n\", \"resourceType\": \"ORDER\", \"resourceId\": \"order-$n\", \"payload\": {\"amount\": $n}}" | jq '.sequence'; done
curl -s "$BASE/audit/events?resourceType=ORDER" -H "Authorization: Bearer $AUDITOR_KEY" | jq '.items[] | {sequence, actorId}'
curl -s $BASE/audit/verify -H "Authorization: Bearer $AUDITOR_KEY" | jq '{intact, recordsChecked}'
```

Tamper with a stored record directly in PostgreSQL, outside the API, as the demonstration-only tamper role, then verify again:

```sh
export AUDIT_LOG_TAMPER_DATABASE_URL="$OWNER_URL"     # the tool switches to audit_log_tamper with SET ROLE
uv run python scripts/tamper_demo.py modify --sequence 3
curl -s $BASE/audit/verify -H "Authorization: Bearer $AUDITOR_KEY" | jq '{intact, violationCount, firstViolation}'
# firstViolation: CONTENT_HASH_MISMATCH at sequence 3
curl -s -X POST $BASE/audit/exports -H "Authorization: Bearer $AUDITOR_KEY" -H "Content-Type: application/json" \
  -d '{"actorId": "advisor-17"}'                        # 409: nothing is signed while the chain is broken
uv run audit-log-verify export --public-key local/export-public.pem local/advisor-17-export.json
# the earlier bundle still verifies offline: it was signed before the tampering
```

> **Limitation of this demonstration login.** `AUDIT_LOG_TAMPER_DATABASE_URL` is the local owner login, which is a PostgreSQL superuser. `tamper_demo.py` switches every connection to `audit_log_tamper` with `SET ROLE`, and every change it makes runs with only that role's privileges (`SELECT`, `INSERT`, `UPDATE`, `DELETE` on the audit tables; no `TRUNCATE`, schema changes, trigger control, or server-file access). However, the database does not enforce that switch. PostgreSQL checks `SET ROLE` against the login, not the current role, so a session that logged in as the superuser can `RESET ROLE` or `SET ROLE` to any role, including back to the superuser. The limit holds because the tool never does so and checks, before every change, that the effective role is the unprivileged `audit_log_tamper`; that check examines the current role, not the login. This is acceptable for a local demonstration whose operator already holds the owner credentials. **Production recommendation:** use a dedicated non-superuser login that is a member of `audit_log_tamper` only, so that the database itself enforces the boundary (ADR-0009).

Other kinds of tampering, each on a freshly reset environment (see below):

| Command | Detected as |
|---|---|
| `tamper_demo.py delete --sequence 3` | `SEQUENCE_GAP` at the next sequence |
| `tamper_demo.py insert --sequence 3` | `PREVIOUS_HASH_MISMATCH` at 3 |
| `tamper_demo.py reorder --sequence 3` | `PREVIOUS_HASH_MISMATCH` at 3 |
| `tamper_demo.py truncate --after N` (N below the latest checkpoint) | `CHAIN_TRUNCATED`, anchor `TRUNCATED` |
| `tamper_demo.py rewrite --sequence 3` (before the latest checkpoint) | `ANCHOR_MISMATCH` at the checkpoint's sequence, anchor `MISMATCH` |

The last two are consistent chains that only the signed checkpoint exposes (FR-4); without a checkpoint they verify as intact, which is the documented limitation. The integration tests (`tests/integration/test_demo_scripts.py`) exercise every row.

## Reset

```sh
docker compose down -v          # removes the database volume
rm -rf local/checkpoints local/*.json local/api-keys.toml local/demo-keys.env
```

Then repeat [Setup](#1-setup). `local/` stays out of Git (`.gitignore`); it holds demo keys and private keys that must never be committed.
