# ADR-0002: Hash chain and canonicalization

- **Status:** Accepted (library adopted and numeric domain finalized in the Phase 2 dependency gate)
- **Date:** 2026-09-28
- **Decision owner:** Developer (Focused Discussion #2, decisions I1–I6; AD-12; Phase 2 numeric domain; Phase 3 hash-encoding and verification decisions)

## Context

Every stored record must carry a hash of its own content and a link to its predecessor, so that modification, deletion, insertion, and reordering are detectable. Two independent verifiers, including one in another language, must compute identical hashes for the same logical record.

## Decision

- **Three hashes.**
  - `contentHash` covers `id`, `eventType`, `actorId`, `resourceType`, `resourceId`, `timestamp` (explicit null when absent), `recordedAt`, `recordedBy`, and the payload commitments.
  - `recordHash` covers `sequence`, `previousHash`, and `contentHash`.
  - `previousHash` is the predecessor's `recordHash`, or the genesis value for `sequence` 1.
- **Genesis.** 64 lowercase hexadecimal zeros, applying only to `sequence` 1. No chain identifier.
- **Canonicalization.** RFC 8785 (JSON Canonicalization Scheme) over I-JSON input, with the input restrictions in requirements FR-1.
- **Numeric domain.** Every accepted JSON number, whether written as an integer, a fraction, or in exponent notation, must have a numeric value within ±(2^53−1); values outside it are rejected. This is an application-level restriction, not a requirement of RFC 8785 (see "Library adoption outcome").
- **Hash algorithm.** SHA-256, represented as lowercase hexadecimal. Every hash input starts with a distinct versioned domain label under the `audit-log/v1` scheme.
- **Hash input encoding (Phase 3).** Every hash input is `SHA-256(UTF-8(label) || 0x00 || RFC8785(object))`. The zero byte is the label boundary; RFC 8785 defines only the canonical bytes that follow it. Labels: `audit-log/v1/content`, `audit-log/v1/record`, and `audit-log/v1/commitment` (ADR-0004). Checkpoint and manifest labels are deferred.
- **Hash input objects (Phase 3).** `contentHash` hashes `{id, eventType, actorId, resourceType, resourceId, timestamp, recordedAt, recordedBy, payload}` (API field names; `timestamp` null when absent; `payload` the committed structure). `recordHash` hashes `{sequence, previousHash, contentHash}`.
- **Text forms (Phase 3).** Timestamps are `YYYY-MM-DDTHH:MM:SS.ffffffZ` (UTC, exactly six fractional digits, `Z` suffix). `id` is a lowercase hyphenated 8-4-4-4-12 UUID; the UUID version does not affect hashing. The integrity core rejects other forms rather than normalizing them.
- **Verification rules (Phase 3).** One violation per record, chosen in this order: `SEQUENCE_DUPLICATE`, `SEQUENCE_GAP`, `GENESIS_MISMATCH`, `PREVIOUS_HASH_MISMATCH`, `CONTENT_HASH_MISMATCH`, `PAYLOAD_VALUE_MISMATCH`, `PAYLOAD_VALUE_MISSING` (added in Phase 8), `RECORD_HASH_MISMATCH`, `RECORDED_AT_REGRESSION`. Each record is checked against the record actually preceding it; a first record other than `sequence` 1, or a sequence jump, is `SEQUENCE_GAP`; `GENESIS_MISMATCH` means `sequence` 1 does not link to the genesis value; a malformed stored hash counts as a mismatch of that hash; `recordedAt` regresses only when strictly earlier than its predecessor's. The pure result holds `intact`, `recordsChecked`, `head`, `violationCount`, and `firstViolation` (`type`, `sequence`, `recordId`). `PAYLOAD_VALUE_MISSING` is implemented for redaction since Phase 8 (and for retention since Phase 9); `ANCHOR_MISMATCH` and `CHAIN_TRUNCATED` are deferred to checkpoints.
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

Recorded 2026-09-28 (Phase 2 dependency gate).

- **Library:** [`rfc8785`](https://pypi.org/project/rfc8785/) (Trail of Bits), version constraint `>=0.1.4,<0.2`. A 0.x release can change behavior in a minor version, and canonical output determines every hash, so the ceiling is deliberate.
- **Adoption check:**
  - *Maintenance:* the source repository is active and not archived.
  - *License:* Apache-2.0.
  - *Conformance:* the library matches the RFC 8785 Section 3.2.4 sample bytes, the Section 3.2.3 property-sorting sample, and every finite number sample in Appendix B.
  - *Input profile:* it rejects NaN and infinities, integers outside ±(2^53−1), unpaired surrogates, and non-JSON types. Its output is UTF-8 bytes, suitable as SHA-256 input.
  - *Tooling:* it is pure Python and typed, and works with Python 3.13, Pyright (strict), and the rest of the project tooling.
- **Limitation:** an unpaired surrogate in an object **key** raises `UnicodeEncodeError` rather than the library's `CanonicalizationError`; both are `ValueError` subclasses. FR-1 validation rejects unpaired surrogates before canonicalization.
- **Conflict found and resolved.** A property test showed that RFC 8785 writes some whole-number doubles between 2^53 and 10^21 as plain integer digits (for example, `1e16` becomes `10000000000000000`). FR-1 then accepted such values in fraction or exponent notation, but their canonical text reads back as an integer outside the ±(2^53−1) integer domain, which FR-1 and the library both reject. The library's output is correct RFC 8785, so a different library would not change it. Three options were considered:
  1. bound every number to ±(2^53−1) by numeric value, whatever its notation;
  2. reject only whole numbers from 2^53 up to 10^21;
  3. keep FR-1 unchanged and require every verifier to parse numbers as doubles or never re-parse canonical text.

  The developer chose option 1. It keeps canonical representations closed under the service's parse-and-canonicalize round trip, with no special verifier behavior tied to RFC 8785's 10^21 formatting boundary. Values such as `1e21` or `1e300` are no longer accepted.
- **Tests:** `tests/unit/dependency_gates/test_rfc8785_gate.py`.

## References

- [architecture.md](../architecture.md) Section 8
- [requirements.md](../requirements.md) §3 rows 5–7, FR-1, NFR-1 (Integrity design)
