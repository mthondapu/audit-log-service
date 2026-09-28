# ADR-0006: Checkpoint trust anchor

- **Status:** Accepted (artifact format, storage location, lifecycle, and CLI syntax deferred)
- **Date:** 2026-09-28
- **Decision owner:** Developer (Focused Discussion #2, decision I9; AD-3, RB-1)

## Context

A plain public hash chain cannot detect a full rewrite or tail truncation by an attacker with database write access, because the attacker can recompute every hash. A trust anchor outside the database is needed.

## Decision

- Use **Ed25519-signed checkpoints** of the chain head, stored **outside the audit database**. They are deterministic artifacts (canonical content plus signature) that the service and the offline verifier can read.
- Create checkpoints **explicitly through an authorized checkpoint CLI**, not a public HTTP endpoint. The CLI:
  - requires the `checkpoint:create` capability from the operator's credential;
  - is not available to writers, readers, auditors, or regulators;
  - uses the checkpoint signing key;
  - writes only to the configured checkpoint store, never to arbitrary paths;
  - verifies the applicable audit chain state before creating and signing a checkpoint, and refuses to create or sign one if verification fails, so no trusted checkpoint is ever created over known-bad chain state.
- The **offline verifier** loads checkpoint artifacts, verifies their signatures, establishes the trusted checkpoint boundary, and uses it during independent export verification, without the live service or database.
- The **tamper actor cannot modify or replace** the checkpoint store or the signing key.
- Verification compares the chain with the latest checkpoint: truncation below it is reported as `CHAIN_TRUNCATED`, and a rewrite that changes the checkpointed head is reported as `ANCHOR_MISMATCH`.
- Per-record signatures are not used.

### Why checkpoint creation is outside the public API

Checkpoints are trust anchors. Keeping their creation off the HTTP API:

- removes a remotely reachable signing operation;
- keeps the capability away from ordinary API principals; and
- makes checkpoint creation a deliberate operator action.

## Consequences

- The truncation and full-rewrite demonstrations become possible: create a checkpoint, tamper with the database, and verify.
- Records appended after the latest checkpoint remain exposed to an attacker with database write access (requirements FR-4). Checkpoint timing determines the window.
- The prototype stores keys and checkpoints on the application host; host compromise is a documented limitation.

## Deferred

- Exact CLI command syntax and how the operator credential is presented.
- Checkpoint artifact format and store location.
- Lifecycle and timing.
- Whether checkpoint and export signing keys are separate (S23), and production key lifecycle, storage, and distribution.
- Recording the `cryptography` dependency-gate outcome (AD-12).

## Alternatives considered

- **An HTTP checkpoint endpoint:** rejected by developer decision RB-1.
- **Keyed hash chain (HMAC):** rejected; it does not detect truncation, and recipients could not verify without the secret.
- **Per-record signatures:** rejected by developer decision.
- **External timestamping or transparency logs:** out of scope (requirements §7).

## References

- [architecture.md](../architecture.md) Sections 12, 15, 17
- [requirements.md](../requirements.md) FR-3, FR-4, assumption 9
