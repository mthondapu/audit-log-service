# ADR-0009: Database privileges and tamper boundary

- **Status:** Accepted (application and checkpoint CLI grants implemented; tamper-actor grants deferred)
- **Date:** 2026-09-28
- **Decision owner:** Developer (AD-4, RB-1, D4; requirements NFR-1)

## Context

Append-only behavior must not depend only on application code. The assignment's demonstration requires modifying stored records directly in the database, outside the normal API, and then detecting the change.

## Decision

- **Three privilege boundaries:**
  1. **Application role:** inserts and selects immutable records; inserts, selects, and deletes recoverable values and salts. It has **no update or delete** on immutable records, and a database-level guard also rejects such changes.
  2. **Owner / migration role:** owns the schema and applies migrations. It is not used by the running service.
  3. **Tamper actor:** privileged direct modification for demonstrations, **outside the application trust boundary**.
- **Checkpoint CLI access (D4):** the checkpoint CLI uses read-only database access for chain verification, with no insert, update, or delete. Since Phase 10 this is the `audit_log_checkpoint` role (below).
- **Tamper tooling** is separate from the application and never uses the normal API. How it obtains its privileges belongs to the tooling, not to the application architecture.
- The tamper actor **cannot access or modify** the checkpoint store, signing keys, or API-key configuration.

## Consequences

- The normal application has no path to mutate immutable records.
- Detection of tampering relies on verification and checkpoints, which is what the demonstrations exercise.
- Owner and tamper credentials must never appear in the application's configuration.

## Application role and guard (Phase 4 decisions)

Decided by the developer on 2026-09-28, before Phase 4 implementation:

- **Provisioning.** Migrations run as the schema owner and do not create server-wide roles. `audit_log_app` is a `NOLOGIN` group role, created by a separate owner-run provisioning step. Login users are made members of it outside source control. No credentials appear in migrations or the repository.
- **Grants.** `audit_log_app` has `SELECT` and `INSERT` on `audit_records`, and `SELECT`, `INSERT`, and `DELETE` on `audit_payload_values`. It has no `UPDATE`, `DELETE`, or `TRUNCATE` on `audit_records`.
- **Guard.** The database-level guard is scoped to the application role and enforced through these privileges. There is deliberately **no** trigger that rejects changes for every role: such a trigger would block the future privileged tamper tooling unless it disabled triggers or relied on superuser behavior, which is not the intended design.
- The application persistence package exposes no update or delete operation on `audit_records`.

## Checkpoint CLI role and tamper-role constraint (Phase 10 decisions)

Decided by the developer on 2026-09-28 (decision CP4 and the trust-boundary finding):

- **Checkpoint CLI role.** `audit_log_checkpoint` is a `NOLOGIN` group role created by the same provisioning script. Migration 0002 grants it `SELECT` on `audit_records` and `audit_payload_values`, and nothing else. The CLI's login (`AUDIT_LOG_CHECKPOINT_DATABASE_URL`) is a member of it. The CLI refuses a login that has `INSERT`, `UPDATE`, `DELETE`, or `TRUNCATE` on either table, and verifies in a read-only transaction.
- **Tamper-role constraint.** A PostgreSQL superuser, or a role with `pg_write_server_files` or `pg_execute_server_program`, can write files on the database host (for example with `COPY ... TO`). If the checkpoint store were on that host, such a role could rewrite it and break TB-3. The tamper actor must therefore not be a superuser and must not hold those roles; alternatively, the store must be outside the database's host or container. The tamper role itself remains deferred.

## Deferred

- The tamper-actor role and grants, and how the demonstration environment provisions the tamper actor (within the constraint above).

## Alternatives considered

- **A single database role for everything:** rejected; the application could then rewrite history.
- **Tampering through a hidden application endpoint:** rejected; it would place tampering inside the application trust boundary (CLAUDE.md).

## References

- [architecture.md](../architecture.md) Sections 14, 15, 17
- [requirements.md](../requirements.md) NFR-1, §9 Scenario A, assumption 9
