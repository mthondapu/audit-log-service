# Engineering summary

The final engineering summary of the Audit Log Service prototype: what was built, how it meets the requirements, how it was validated, and what remains out of scope. The requirements baseline is [requirements.md](requirements.md); the design is [architecture.md](architecture.md) and the ADRs in [adr/](adr/).

## 1. What was built

A tamper-evident, append-only audit log service (FastAPI, PostgreSQL 18, SQLAlchemy 2 Core, Alembic, psycopg 3, Pydantic 2), structured as a modular monolith around a dependency-light integrity library (ADR-0001):

- **Append and query.** `POST /audit/events` appends through one serialized path (a PostgreSQL advisory lock, ADR-0003); `GET /audit/events` filters by actor, event type, resource, and a half-open `recordedAt` range with opaque cursor pagination; `GET /audit/events/{id}` retrieves one record.
- **Integrity.** Every record carries `contentHash` and `recordHash` over RFC 8785 canonical JSON with versioned domain labels (ADR-0002). Payload values are individually salted commitments, so values can be deleted without changing any hash (ADR-0004). `GET /audit/verify` recomputes the whole chain and reports fixed violation types.
- **Redaction and retention.** Administrators redact values, recorded as `AUDIT_LOG_REDACTION` events (FR-6); bounded retention archives old records by purging their values, recorded as `AUDIT_LOG_RETENTION` events (FR-5, ADR-0005). Verification accepts only missing values those events authorize.
- **Checkpoints.** An operator CLI signs Ed25519 checkpoints of the verified head into a store outside the database; verification compares the chain with the latest checkpoint, detecting tail truncation and consistent rewrites (FR-4, ADR-0006).
- **Exports.** `POST /audit/exports` produces a signed bundle for one actor or resource, verified before signing and recorded as an `AUDIT_LOG_EXPORT` event; `audit-log-verify` verifies bundles and checkpoints offline, with no service or database (FR-7, ADR-0007).
- **Security.** Static Bearer API keys stored as SHA-256 digests, prototype roles mapped to capabilities, authorization before validation and lookup (ADR-0008); separate database roles for the service, the checkpoint CLI, migrations, and the demonstration tamper actor (ADR-0009).
- **Operations.** Health and readiness endpoints, request identifiers, RFC 9457 Problem Details, fail-fast configuration, and demonstration tooling (`scripts/`).

## 2. Requirements traceability

Tests are named by module; `u/` is `tests/unit/`, `i/` is `tests/integration/`, and `a/` is `tests/integration/api/`.

| Requirement | Implementation | Tests | Decisions and documents |
|---|---|---|---|
| FR-1 Append | `application/events.py`, `persistence/audit_log.py`, `api/events.py` | `u/application/test_event_validation.py`, `i/test_append.py`, `i/test_constraints.py`, `a/test_events_api.py` | ADR-0002, ADR-0003; requirements FR-1 |
| FR-2 Query and representation | `application/queries.py`, `application/views.py`, `api/schemas.py` | `u/application/test_event_queries.py`, `u/api/test_representation.py`, `a/test_query_api.py` | requirements FR-2 (Phase 6) |
| FR-3 Verification | `integrity/verification.py`, `application/verification.py`, `api/verification.py` | `u/integrity/test_verification.py`, `test_redaction_verification.py`, `test_retention_verification.py`, `test_anchor_verification.py`, `a/test_verify_api.py` | ADR-0002; requirements FR-3 (Phase 7) |
| FR-4 Checkpoints | `integrity/checkpoints.py`, `persistence/checkpoint_store.py`, `checkpoint_writer.py`, `application/checkpoints.py`, `cli/checkpoint.py` | `u/integrity/test_checkpoints.py`, `u/persistence/test_checkpoint_store.py`, `u/cli/test_checkpoint_cli.py`, `i/test_checkpoint_cli.py`, `a/test_checkpoint_verify_api.py` | ADR-0006; requirements FR-4 (Phase 10) |
| FR-5 Retention | `application/retention.py`, `persistence/retention.py`, `api/retention.py` | `u/integrity/test_retention_verification.py`, `u/persistence/test_retention_boundary_parsing.py`, `a/test_retention_api.py` | ADR-0005; requirements FR-5 (Phase 9) |
| FR-6 Redaction | `integrity/commitments.py`, `application/redactions.py`, `api/redactions.py` | `u/integrity/test_commitments.py`, `u/application/test_redaction_request.py`, `a/test_redaction_api.py` | ADR-0004; requirements FR-6 (Phase 8) |
| FR-7 Export and offline verification | `integrity/exports.py`, `application/exports.py`, `api/exports.py`, `offline/verify.py` | `u/integrity/test_exports.py`, `u/application/test_export_request.py`, `u/offline/test_offline_*`, `a/test_export_api.py`, `u/test_import_boundaries.py` | ADR-0007; requirements FR-7 (Phase 11) |
| FR-8 Scenario C | `config/vocabulary.py`, `application/events.py`, `scripts/demo_setup.py` | `u/config/test_vocabulary.py`, `a/test_events_api.py`, `a/test_demo_seed.py`, `u/scripts/test_demo_setup_keys.py` | requirements FR-8; [demo.md](demo.md) §2 |
| NFR-1 Integrity | integrity package, migrations 0001 and 0002, role grants | `u/integrity/*`, `u/dependency_gates/*`, `i/test_privileges.py`, `i/test_migrations.py`, `i/test_concurrency.py`, `i/test_demo_scripts.py` | ADR-0002 to ADR-0004, ADR-0009 |
| NFR-2 Security | `security/*`, `config/api_keys.py`, `api/events.py` (`authorize_request`), `cli/checkpoint.py` | `u/security/*`, `u/config/test_api_keys.py`, `a/test_api_failures.py`, access-control tests in every API module | ADR-0008, ADR-0009 |
| NFR-3 Performance | `scripts/benchmark.py` | `u/scripts/test_benchmark_helpers.py` | [performance.md](performance.md) |
| NFR-4 Operability | `compose.yaml`, `scripts/*.sql`, `migrations/`, README | operational smoke test (§5) | README, [demo.md](demo.md) |
| NFR-5 Observability | `api/app.py` (request identifiers, logging), `api/health.py` | `u/api/test_health.py`, `a/test_api_failures.py`, log-content tests | architecture §4, §5 |
| NFR-6 Quality | `pyproject.toml` quality gates | the whole suite | [testing.md](testing.md) |
| NFR-7 API conventions | `api/*`, `problem_details.py`, `api/body.py` | `u/api/test_openapi.py`, `u/test_problem_details.py`, `a/test_api_failures.py` | requirements NFR-7 |

Every row of requirements §12 (Requirements-to-Validation Summary) is covered by the tests above; the rewrite and tamper row is additionally demonstrated with the tamper tooling ([demo.md](demo.md) §5).

## 3. Key decisions and trade-offs

- **Serialized appends** (ADR-0003): an advisory lock gives one unforked chain and simple reasoning, at the cost of write throughput (measured in [performance.md](performance.md)).
- **Salted per-value commitments** (ADR-0004): redaction and retention delete values without touching any hash, so the chain stays verifiable from genesis; payload keys and structure stay visible.
- **Retention as payload purge** (ADR-0005): records are never deleted, so verification is always complete; metadata is kept indefinitely.
- **Signed checkpoints outside the database** (ADR-0006): the only mechanism that detects truncation and consistent rewrites against a database writer; records after the latest checkpoint remain exposed, and checkpoints are created manually.
- **Signed single-bundle exports** (ADR-0007): independent verification without the service; completeness is an attested claim; a broken chain blocks every export.
- **Full-chain verification** (Phase 7): simple and always complete, O(n) in time and memory per verification, checkpoint creation, and export.
- **Separate keys and roles** (CP7, ADR-0009): the running service never holds the checkpoint key; the tamper actor cannot write files on the database host.

## 4. AI-assisted engineering

The project followed a developer-led, AI-assisted workflow: for each phase, a read-only plan identified conflicts and ambiguities, the developer decided every consequential question, the AI implemented the approved decisions, ran the full validation suite, performed a read-only review, and recorded the work in [ai-usage-log.md](ai-usage-log.md). The developer performed every Git operation and reviews each phase before committing. The log records the decisions as given and marks each phase's sign-off as pending the developer's review.

## 5. Final validation

Run by Claude on 2026-09-29 against the Phase 12 working tree (Windows 11, Python 3.13.15, PostgreSQL 18.6 in Docker), results as observed:

| Check | Command | Result |
|---|---|---|
| Tests and coverage | `uv run pytest --cov --cov-branch` with `AUDIT_LOG_TEST_DATABASE_URL` | 1479 passed (1065 unit, 413 integration, 1 package); 100% of 2614 statements and 568 branches; `fail_under = 100` met; one known warning (`httpx2`, Phase 5 decision) |
| Repeatability | concurrency and lock-timeout tests, 3 runs | 7 of 7 passed in each run |
| Formatting | `uv run ruff format --check .` | 113 files already formatted |
| Lint | `uv run ruff check .` | all checks passed |
| Types | `uv run pyright` (strict; source, tests, migrations, scripts) | 0 errors, 0 warnings |
| Security | `uv run bandit -c pyproject.toml -r src migrations scripts` | no issues identified |
| Dependencies | `uv run pip-audit` | no known vulnerabilities |
| Lock | `uv lock --check`, `uv sync --locked` | consistent |
| Whitespace | `git diff --check` | clean |
| Clean copy | the 149 committable files (tracked and new, not ignored) copied to an empty directory, then `uv sync --locked` and the full suite | 1479 passed, 100% coverage; `audit-log-verify` and `audit-log-checkpoint` installed and runnable |
| Repository hygiene | tracked and untracked files scanned | no private keys, API keys, `.env`, database files, or generated artifacts in the committable set; `docs/assignment.md` never in Git history; the only PEM headers are an invalid placeholder in a settings test and an assertion in the Ed25519 gate test |

**After the final documentation review.** That review changed only documentation, docstrings, and the benchmark script's defaults and help text (aligned to the final 1,000 and 10,000-record scope, with its unit test). Afterwards the unit suite (1065 passed), the tamper and demo-seed integration tests (17 passed), `ruff format --check`, `ruff check`, `pyright`, `bandit`, `uv lock --check`, and `git diff --check` were rerun and passed; the full integration suite was not rerun, because no code it exercises changed.

**Operational smoke test** (from nothing, following [demo.md](demo.md) §1 on a separate compose project): role provisioning, `alembic upgrade head` through `AUDIT_LOG_MIGRATION_DATABASE_URL` (0001 and 0002), the tamper-role script, login users, demo keys, and both Ed25519 key pairs all succeeded; the service started under `uvicorn --no-access-log` with the `audit_log_app` login and refused to start with the owner login; `/health/live` and `/health/ready` returned `200`. The benchmark's HTTP sample also ran a real `uvicorn` process. The service log contained only startup lines and three `denied` lines (request identifier, method, path, status), with no keys, payload values, identifiers, or query strings. Because no logging configuration is applied, the service's INFO lines (for example `export created`) are not emitted at Python's default WARNING level; JSON or configured logging was not adopted (P8).

## 6. Scenario demonstrations

The walkthrough in [demo.md](demo.md) was run end to end on 2026-09-29 against the live service (the environment was then reset and the demo keys deleted). `jq`, optional in the document, was not installed, so equivalent Python one-liners selected the same fields. Observed:

- **Scenario C.** Six demonstration events were appended through the API with the writer's key on stdin; an event outside the access-event vocabulary returned `422`; the regulator listed the three `acct-1001` access events, verified the chain (intact, 6 records, anchor `NONE`), and exported the account (3 records); the export appeared as an `AUDIT_LOG_EXPORT` event recorded by `demo-regulator`; the writer could not read and the regulator could not redact (`403`).
- **Scenario B.** Redacting `/purpose` appended an `AUDIT_LOG_REDACTION` event; the record showed `purpose: null` and `redactedPaths: ["/purpose"]`; the chain stayed intact. A retention run reported `NOTHING_ELIGIBLE` (fresh events are inside the 30-day window; retention with old records is covered by the tests and the benchmark). An export of `advisor-17` (5 records) verified offline as `VALID`.
- **Checkpoints.** The writer's key was refused (exit 4); the administrator created checkpoint 9 (`CHECKPOINT_CREATED`); verification reported the anchor `VERIFIED` at 9; the artifact verified offline; a later export anchored the checkpoint as `MATCH` at `asOfSequence` 9.
- **Scenario A.** Three events were appended (sequences 11 to 13), queried, and verified (intact, 13 records). `tamper_demo.py modify --sequence 3`, run as the tamper role outside the API, changed record 3; verification then reported `intact: false`, one violation, `CONTENT_HASH_MISMATCH` at sequence 3; a new export was refused with `409`; the bundle exported before the tampering still verified offline.

Middle deletion, insertion, reordering, tail truncation, and full rewrite against a checkpoint are exercised by the tamper integration tests (`tests/integration/test_demo_scripts.py`), each on a fresh chain.

## 7. Performance

Measured and reported in [performance.md](performance.md). The final benchmark evidence covers chains of 1,000 and 10,000 records only; 50,000- and 100,000-record results are not part of it (a benchmarking-time decision and a since-corrected benchmark-script error, not application failures), and no numbers are extrapolated. In brief: appends are serialized (about 40 to 51 appends/s at 10,000 records whatever the number of writers, with no lock timeouts and intact chains); per-request latency grows with chain size, and query plans show two sequential scans that every read and append performs; full-chain verification (about 350 to 900 records/s) dominates checkpoint and export time; offline verification is fast. Indexes were not added (P9); a possible migration is described in performance.md for review.

## 8. Limitations and deferred items

- **Identity and transport:** static API keys and prototype roles instead of an identity provider; plain HTTP for local use (TLS is a production concern).
- **Keys:** the checkpoint key, export key, checkpoint store, and configuration live on the application host; production key lifecycle, storage, rotation, and distribution are deferred. There is no trusted timestamping, so a stolen key could sign back-dated artifacts.
- **Checkpoint window:** records after the latest checkpoint can be rewritten, fabricated, or truncated by a database writer without detection; checkpoints are created manually, with no scheduling.
- **Scale:** appends are serialized; verification, checkpoint creation, and every export verify the whole chain in memory; there are no secondary indexes (see [performance.md](performance.md)); exports are single bounded bundles; retention runs are bounded and may need several runs.
- **Privacy:** payload keys and structure remain visible after redaction; exported bundles contain values and salts and must be handled as sensitive data.
- **Scope-outs** (requirements §7): physical deletion, streaming or asynchronous exports, chain-bridging evidence in exports, per-record signatures, per-account regulator scoping, appending reads or denied attempts to the chain, scheduled retention.
- **Scenario C:** the interpretation rests on documented assumptions; the stakeholder questions (requirements §8) remain unanswered by design, and production vocabulary names are configuration to be agreed.
- **Testing:** one platform and one PostgreSQL version; no load or soak testing ([testing.md](testing.md)).
- **Tamper demonstration login:** the local demonstration runs `tamper_demo.py` with the owner login (a superuser) and `SET ROLE audit_log_tamper`; every change runs with the tamper role's privileges, but the database does not enforce the switch (the superuser session could `RESET ROLE`). A dedicated non-superuser login in `audit_log_tamper` only is the production recommendation ([demo.md](demo.md), ADR-0009).
