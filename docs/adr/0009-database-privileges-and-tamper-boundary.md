# ADR-0009: Database privileges and tamper boundary

- **Status:** Accepted in principle (exact grants deferred to implementation)
- **Date:** 2026-09-28
- **Decision owner:** Developer (AD-4, RB-1; requirements NFR-1)

## Context

Append-only behavior must not depend only on application code. The assignment's demonstration requires modifying stored records directly in the database, outside the normal API, and then detecting the change.

## Decision

- **Three privilege boundaries:**
  1. **Application role:** inserts and selects immutable records; inserts, selects, and deletes recoverable values and salts. It has **no update or delete** on immutable records, and a database-level guard also rejects such changes.
  2. **Owner / migration role:** owns the schema and applies migrations. It is not used by the running service.
  3. **Tamper actor:** privileged direct modification for demonstrations, **outside the application trust boundary**.
- **Tamper tooling** is separate from the application and never uses the normal API. How it obtains its privileges belongs to the tooling, not to the application architecture.
- The tamper actor **cannot access or modify** the checkpoint store, signing keys, or API-key configuration.

## Consequences

- The normal application has no path to mutate immutable records.
- Detection of tampering relies on verification and checkpoints, which is what the demonstrations exercise.
- Owner and tamper credentials must never appear in the application's configuration.

## Deferred

- Exact grants, role names, and how the demonstration environment provisions the tamper actor.

## Alternatives considered

- **A single database role for everything:** rejected; the application could then rewrite history.
- **Tampering through a hidden application endpoint:** rejected; it would place tampering inside the application trust boundary (CLAUDE.md).

## References

- [architecture.md](../architecture.md) Sections 14, 15, 17
- [requirements.md](../requirements.md) NFR-1, §9 Scenario A, assumption 9
