# Testing approach and limitations

How the Audit Log Service is tested, what the tests establish, and what they do not. Requirements NFR-6 and §12 set the expected evidence; [engineering-summary.md](engineering-summary.md) maps each requirement to its tests, and records the final validation run.

## Principles

- **Risk-based.** The integrity core (canonicalization, commitments, hashing, verification, checkpoints, exports) carries the most tests, including property tests, because a defect there silently weakens every guarantee.
- **Real datastore.** Persistence, privilege, concurrency, and API tests run against real PostgreSQL 18, never a substitute, because the guarantees depend on PostgreSQL behavior: advisory locks, `REPEATABLE READ` snapshots, role privileges, and constraints.
- **Tampering outside the application.** Tamper tests change the database directly, as the owner or as the demonstration-only tamper role, never through the API, and assert that verification or a checkpoint detects the change.
- **No secrets.** API keys in tests are obviously fake, deterministic values; Ed25519 keys are generated per test in memory or in a temporary directory; nothing sensitive is committed.
- **Coverage as a floor, not a goal.** 100% statement and branch coverage of the `audit_log_service` package is enforced (`fail_under = 100`, no exclusions), but the tests are written against requirements and failure modes, not lines.

## Layers

| Layer | Location | What it covers |
|---|---|---|
| Unit | `tests/unit/` | Integrity core, request validation, configuration, authentication and authorization, representation, OpenAPI, CLIs, offline verifier, store, scripts' pure parts. No database. |
| Dependency gates | `tests/unit/dependency_gates/` | RFC 8785 test vectors and Ed25519 behavior of the adopted libraries (Phase 2). |
| Property | Hypothesis tests in unit and integration modules | Canonicalization and hashing invariants, storage round trips, verification of arbitrary interleavings of appends, redactions, and retention, anchoring against any checkpoint prefix, exports of any interleaving verifying, and any mutation of a bundle failing. |
| Integration | `tests/integration/` | Append path, constraints, migrations, role privileges, the checkpoint CLI end to end, concurrency, the tamper role and tamper tooling. |
| API | `tests/integration/api/` | Every endpoint against PostgreSQL through the ASGI app: contract, statuses, Problem Details, check order, tampering and verification, redaction, retention, exports, health, demo seeding. |
| Import boundaries | `tests/unit/test_import_boundaries.py` | In fresh interpreters: the offline verifier loads only the integrity modules; the service never imports the checkpoint writer. |

The integration harness (`tests/integration/conftest.py`) needs `AUDIT_LOG_TEST_DATABASE_URL`, a server URL for a role that can create databases and roles. Per session it provisions the group roles, creates a throwaway database, and migrates it; each test starts from empty tables. Application-path tests switch to `audit_log_app` with `SET ROLE`, checkpoint CLI tests to `audit_log_checkpoint`, and tamper tests to `audit_log_tamper`, so each runs with exactly its role's privileges. Integration tests fail, rather than skip, when the variable is missing.

## Notable techniques

- **Concurrency.** Parallel writers on separate connections must produce one contiguous, unforked chain; a held append lock must turn into a `503` after the lock timeout; concurrent redaction, retention, and export runs are interleaved deliberately, including inside an open export snapshot.
- **Snapshot and race regressions.** Tests inject work between steps (a checkpoint written between the store read and the snapshot, appends and redactions inside an export snapshot) to pin the approved ordering.
- **Secret hygiene.** Tests assert that raw keys, payload values, salts, private-key material, and scope identifiers never appear in responses, errors, logs, CLI output, or stored export events.
- **Tamper matrix.** Modification, middle deletion, insertion, reordering, and deleted values are detected by verification alone; tail truncation and a consistent full rewrite are detected against a signed checkpoint, and shown to be undetectable without one.

## Quality gates

`ruff format --check`, `ruff check`, `pyright` in strict mode (source, tests, migrations, and scripts), `bandit` (source, migrations, scripts), `pip-audit`, `uv lock --check`, `uv sync --locked`, `git diff --check`, and the full pytest run with coverage. The final results are in [engineering-summary.md](engineering-summary.md#final-validation).

## Performance

Performance is measured by `scripts/benchmark.py`, not by the test suite, because timing assertions are unreliable and NFR-3 sets no targets. Only the script's statistics and argument handling are unit-tested. Results: [performance.md](performance.md).

## Limitations

- Tests run on one developer machine and one PostgreSQL version (18); other platforms and versions are not exercised.
- Concurrency tests show correctness under contention (no forks, contiguous sequences, intact chains), not throughput under production load; there is no load or soak testing.
- Timing-dependent tests (the 5-second lock timeout, thread interleavings) are deterministic in design but slower, and could be affected by an extremely overloaded machine.
- The ASGI test client exercises the application without a network; the real `uvicorn` process is exercised by the operational smoke test and the benchmark's HTTP sample, not by pytest.
- The demonstration scripts (`scripts/`) are tested, but they are outside the package, so they are not part of the 100% coverage measurement.
- The Starlette test client emits a deprecation warning about `httpx2`; the project deliberately keeps `httpx` (Phase 5 decision).
- Manual validation of the Scenario A, B, and C demonstrations follows [demo.md](demo.md); its latest run is recorded in the engineering summary.
