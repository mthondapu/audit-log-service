# ADR-0002: Hash chain and canonicalization

- **Status:** Accepted (library adoption outcome pending the dependency gate)
- **Date:** 2026-09-28
- **Decision owner:** Developer (Focused Discussion #2, decisions I1–I6; AD-12)

## Context

Every stored record must carry a hash of its own content and a link to its predecessor, so that modification, deletion, insertion, and reordering are detectable. Two independent verifiers, including one in another language, must compute identical hashes for the same logical record.

## Decision

- **Three hashes.**
  - `contentHash` covers `id`, `eventType`, `actorId`, `resourceType`, `resourceId`, `timestamp` (explicit null when absent), `recordedAt`, `recordedBy`, and the payload commitments.
  - `recordHash` covers `sequence`, `previousHash`, and `contentHash`.
  - `previousHash` is the predecessor's `recordHash`, or the genesis value for `sequence` 1.
- **Genesis.** 64 lowercase hexadecimal zeros, applying only to `sequence` 1. No chain identifier.
- **Canonicalization.** RFC 8785 (JSON Canonicalization Scheme) over I-JSON input, with the input restrictions in requirements FR-1.
- **Hash algorithm.** SHA-256, represented as lowercase hexadecimal. Every hash input starts with a distinct versioned domain label under the `audit-log/v1` scheme.
- **No mutable state is hashed.** Archive status, redaction status, and derived response fields are never hash inputs.
- **Dependency gate.** A maintained RFC 8785 library must pass an adoption check (maintenance, license, conformance with the RFC 8785 test vectors) before the integrity library is implemented. The outcome is recorded here. No in-house RFC 8785 implementation is created. If no maintained library can be adopted without violating the approved requirements, implementation stops for a new developer decision.

## Consequences

- Content integrity is independent of chain position, which lets redaction, retention, and export reuse the same hashes.
- Verifiers in other languages can use standard RFC 8785 and SHA-256 implementations.
- The input restrictions constrain what callers may submit, in exchange for deterministic hashing.

## Alternatives considered

- **A two-hash design** that folds the link into the content hash: rejected; it mixes position into content and makes redaction and export harder.
- **An in-house canonicalizer:** rejected by developer decision.
- **Other algorithms** (SHA-3, BLAKE2/3): no practical benefit for the prototype and less universal tooling.

## Library adoption outcome

Pending: to be recorded when the dependency gate is executed.

## References

- [architecture.md](../architecture.md) Section 8
- [requirements.md](../requirements.md) §3 rows 5–7, FR-1, NFR-1 (Integrity design)
