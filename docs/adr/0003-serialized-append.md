# ADR-0003: Serialized append

- **Status:** Accepted
- **Date:** 2026-09-28
- **Decision owner:** Developer (Focused Discussion #2, decisions I7 and I7a; AD-11)

## Context

Concurrent writers must never fork the chain. `sequence` must start at 1, be contiguous, and never be renumbered. `recordedAt` is server-authoritative, and verification reports `RECORDED_AT_REGRESSION`.

## Decision

- Serialize appends with a **PostgreSQL transaction-scoped advisory lock** at **READ COMMITTED** isolation.
- Read the chain head **after** acquiring the lock. `sequence` is the head's `sequence + 1`; it is not taken from a PostgreSQL sequence object, which can skip values.
- Take `recordedAt` from the **database clock after locking**, **clamped so it never goes backwards** relative to the head.
- Enforce `UNIQUE(sequence)` (required) and `UNIQUE(previous_hash)` (defense in depth against a permanent fork). There is no foreign key from `previous_hash` to `record_hash`, because retention may remove older records in future.
- Bound lock waiting with a lock timeout; the server does not retry failed appends automatically.
- Implement the transaction with SQLAlchemy 2.x Core and explicit transaction control. Redaction, retention, and export reuse the append path inside their own transactions.

## Consequences

- There are no gaps and no forks; a rolled-back transaction leaves no trace.
- Write throughput is limited to one append at a time, which is accepted for the prototype (requirements assumptions 1–2).
- Clamping prevents the application from writing a regression; verification still detects regressions introduced outside the application.
- The exact lock key and timeout values are implementation details.

## Alternatives considered

- **Chain-head row with `SELECT … FOR UPDATE`:** acceptable, but adds a mutable row that duplicates chain state.
- **`LOCK TABLE … IN EXCLUSIVE MODE`:** rejected, because it requires update or delete privileges that conflict with the append-only application role.
- **SERIALIZABLE isolation with retry, or optimistic inserts:** correct, but they add retry handling without benefit.

## References

- [architecture.md](../architecture.md) Section 8
- [requirements.md](../requirements.md) NFR-1 (Append concurrency), FR-3
