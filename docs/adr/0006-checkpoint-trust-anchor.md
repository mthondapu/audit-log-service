# ADR-0006: Checkpoint trust anchor

- **Status:** Accepted; implemented in Phase 10 (production key lifecycle deferred)
- **Date:** 2026-09-28
- **Decision owner:** Developer (Focused Discussion #2, decision I9; AD-3, RB-1, L-D1)

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
- The **offline verifier** loads supplied checkpoint artifacts and verifies their signatures, without the live service or database. During export verification it uses a checkpoint only when the checkpoint can be directly anchored to signed export evidence (see below).
- The **tamper actor cannot modify or replace** the checkpoint store or the signing key.
- Verification compares the chain with the latest checkpoint: truncation below it is reported as `CHAIN_TRUNCATED`, and a rewrite that changes the checkpointed head is reported as `ANCHOR_MISMATCH`.
- Per-record signatures are not used.

### Why checkpoint creation is outside the public API

Checkpoints are trust anchors. Keeping their creation off the HTTP API:

- removes a remotely reachable signing operation;
- keeps the capability away from ordinary API principals; and
- makes checkpoint creation a deliberate operator action.

### Offline use of supplied checkpoints during export verification (L-D1)

An export contains only the records in its scope, together with `asOfSequence` and `asOfRecordHash` in the signed manifest. A supplied checkpoint can therefore be tied to an export only at positions for which the export carries signed evidence. The offline verifier:

1. verifies the supplied checkpoint's signature;
2. if the checkpoint's sequence equals `asOfSequence`, requires its `recordHash` to equal the signed `asOfRecordHash`;
3. if its sequence matches an included record, requires its `recordHash` to equal that record's signed and recomputed `recordHash`;
4. otherwise reports the checkpoint as "not applicable / insufficient evidence". That is not treated as a chain-integrity failure; and
5. continues all other export-integrity checks in every case.

Exports do not gain intervening chain-link evidence, and no request parameter selects a checkpoint or range.

Implemented in Phase 11 by `audit-log-verify export --checkpoint-public-key ... --checkpoint ...`, which reports each supplied checkpoint as `MATCH`, `MISMATCH`, `NOT_APPLICABLE`, or `INVALID` (never used). A mismatching or invalid checkpoint makes the result invalid; a checkpoint that cannot be anchored does not (requirements FR-7). Exports read the checkpoint store only for pre-signing verification and never create or update a checkpoint.

**Rationale:** this keeps the export scope and size unchanged and discloses nothing about out-of-scope records. It uses only evidence the signed manifest already provides.

## Consequences

- The truncation and full-rewrite demonstrations become possible: create a checkpoint, tamper with the database, and verify.
- Records appended after the latest checkpoint remain exposed to an attacker with database write access (requirements FR-4). Checkpoint timing determines the window.
- The prototype stores keys and checkpoints on the application host; host compromise is a documented limitation.
- A recipient-supplied checkpoint strengthens offline export verification only when it can be directly anchored.
  - Because the export audit event is appended above `asOfSequence`, a checkpoint created after an export cannot match that export's `asOfSequence`.
  - When a checkpoint cannot be anchored, the recipient relies on the service's pre-signing verification (including its own checkpoint checks) and on the export signature.

## Implementation (Phase 10)

Decided by the developer on 2026-09-28 (decisions CP1 to CP16). The full contract is in requirements FR-4.

- **Commands.** `audit-log-checkpoint create` creates checkpoints; `audit-log-verify checkpoint --public-key <spki.pem> <artifact>...` verifies artifacts offline. The offline verifier imports only the integrity library and needs no service, database, or configuration; export bundles are verified by `audit-log-verify export` since Phase 11 (FR-7).
- **Operator credential.** The raw API key is read from stdin (without echo on a terminal), never from arguments or environment variables, and checked against the service's API-key configuration by the same digest comparison (`authenticate_api_key`). `checkpoint:create` is required before the signing key is read or the database is contacted.
- **Trust boundary of that check.** The capability check attributes each checkpoint to an operator (the signed `createdBy`) and keeps the tool from other API principals. It is not a cryptographic control: anyone who can read the signing key can sign without the CLI. File-system access to the signing key is the actual signing boundary.
- **Database access.** A read-only role, `audit_log_checkpoint` (ADR-0009). Creating a checkpoint appends nothing to the chain.
- **Artifact.** One JSON file per checkpoint: a `checkpoint` object with exactly `scheme`, `sequence`, `recordHash`, `createdAt`, `createdBy`, and `keyId`, and an Ed25519 `signature` (lowercase hex) over `UTF-8("audit-log/v1/checkpoint") || 0x00 || RFC8785(checkpoint)`, with no pre-hash. `keyId` is inside the signed content. `createdAt` is the database clock at verification and is not a trusted timestamp.
- **Store.** A configured directory (`AUDIT_LOG_CHECKPOINT_STORE_DIR`) with files named `checkpoint-<20-digit sequence>.json`. Other names are ignored; any invalid matching file makes the whole store invalid. New files are written to a temporary file, flushed, and hard-linked into place, so none is overwritten.
- **Keys (S23).** The checkpoint key is separate from the export key. The export key must be loaded by the running HTTP service; the checkpoint key must not be, so a service compromise cannot forge trust anchors. The service holds only the trusted public key (`AUDIT_LOG_CHECKPOINT_PUBLIC_KEY_FILE`), and both settings are required. Keys are generated outside the project; test keys are generated per test.
- **Verification.** The service and the CLI read and validate the store before opening their database snapshot, so a checkpoint written in between is never mistaken for truncation, and take the latest valid checkpoint as the anchor. `CHAIN_TRUNCATED`, `ANCHOR_MISMATCH`, their messages, and the anchor statuses are defined in requirements FR-3 and FR-4. An invalid or unreadable store is a `500` for `GET /audit/verify` and exit code `5` for the CLI.
- **Creation.** The CLI refuses an empty chain and any chain that is not intact against the existing checkpoint; an unchanged head is reported as `CHECKPOINT_CURRENT` and nothing is written.
- **Lifecycle.** Manual; nothing is scheduled.
- **Store protection.** The tamper actor must not be a PostgreSQL superuser or hold server-file or program-execution privileges, which could write the store if it shared the database host (ADR-0009).

## Deferred

- Production key lifecycle, storage, and distribution, including key rotation for the checkpoint store (the prototype trusts one public key).

## Signing dependency outcome

Recorded 2026-09-28 (Phase 2 dependency gate). This outcome also applies to export signing (ADR-0007).

- **Library:** [`cryptography`](https://pypi.org/project/cryptography/), version constraint `>=50.0.1`, license Apache-2.0 OR BSD-3-Clause. It brings in `cffi` and `pycparser`. No upper bound is set, so that security releases are not blocked; its Ed25519 API is long-standing.
- **Verified with Python 3.13:**
  - Ed25519 key generation, signing (64-byte, deterministic signatures), and verification;
  - rejection of a modified message, a modified, truncated, or extended signature, and a signature from another key;
  - raw 32-byte and PEM (SubjectPublicKeyInfo) public-key round trips, and rejection of a public key of the wrong length. The raw form is the input to the approved `keyId` fingerprint;
  - loading a private key from an in-memory PKCS#8 encoding;
  - verification of the RFC 8032 Section 7.1 TEST 2 vector, using only its public key, message, and signature;
  - signing RFC 8785 canonical bytes, with the signature kept outside the signed content.
- All test keys are generated in memory; no key material is stored or committed.
- The checkpoint artifact format and key separation were decided in Phase 10 (see "Implementation (Phase 10)"); key storage and lifecycle remain deferred.
- **Tests:** `tests/unit/dependency_gates/test_ed25519_gate.py`.

## Alternatives considered

- **An HTTP checkpoint endpoint:** rejected by developer decision RB-1.
- **Keyed hash chain (HMAC):** rejected; it does not detect truncation, and recipients could not verify without the secret.
- **Per-record signatures:** rejected by developer decision.
- **External timestamping or transparency logs:** out of scope (requirements §7).

## References

- [architecture.md](../architecture.md) Sections 12, 15, 17
- [requirements.md](../requirements.md) FR-3, FR-4, assumption 9
