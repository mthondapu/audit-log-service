# ADR-0005: Retention and archived boundary

- **Status:** Accepted
- **Date:** 2026-09-28
- **Decision owner:** Developer (Focused Discussion #3, decisions R1–R6 and N1–N6; AD-5, AD-9, RB-2)

## Context

Records older than a configurable window must be archivable without verification reporting false integrity violations. The audit chain must remain verifiable from genesis, and archived state must be distinguishable from active records.

## Decision

- **Payload purge.** Immutable records remain, including metadata. Recoverable payload values and salts of archived records are purged. Physical deletion of records is future work.
- **Retention events.** Each run that finds newly eligible records appends a retention system event recording the cutoff and `upToSequence`. Eligibility is based on `recordedAt` from the database clock, so archived records always form the oldest contiguous block.
- **Archived boundary.** Derived from the latest applicable retention event in the chain. There is no redundant retention-runs table. The latest retention event keeps its own payload values, because only a later retention event can archive it.
- **Synchronous, bounded run.** `POST /audit/retention-runs` requires `retention:run`. `recordedBy` is the authenticated operator; no separate internal identity is needed. Under the append lock, the run determines the boundary and appends the retention event, then purges within the configured bound.
  - If no new records are eligible but an earlier purge is incomplete, the run resumes that outstanding purge without appending another retention event.
  - It returns `201 Created` when a new event was recorded and its bounded purge completed.
  - It returns `200 OK` with the resumed-purge result when an outstanding purge was resumed and completed.
  - It returns `200 OK` with a structured "nothing eligible" result when there is neither a new eligible boundary nor unfinished purge work, and creates no event.
  - It returns `422` for an invalid request, configuration, or input.
  - It returns `503 Service Unavailable` when a valid run cannot complete because the configured operational bound prevents it. Committed work is kept, and later runs resume the purge.
- **No asynchronous job infrastructure** and no scheduling in the prototype.

## Consequences

- Verification always runs from genesis; purged values are authorized by the retention boundary.
- Large backlogs require several bounded runs.
- The exact response schema is an implementation detail, documented consistently with the API conventions.

## Alternatives considered

- **Logical archive only:** no purge, so no privacy or storage benefit.
- **Physical deletion with an authenticated boundary:** deferred; requires the checkpoint lifecycle and privileged deletes.
- **Asynchronous purge jobs:** rejected for the prototype.
- **A retention-runs table:** rejected as redundant state.

## References

- [architecture.md](../architecture.md) Sections 10, 11
- [requirements.md](../requirements.md) FR-2, FR-3, FR-5
