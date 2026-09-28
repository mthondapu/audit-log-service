# ADR-0007: Signed exports

- **Status:** Accepted (manifest schema and retention-evidence representation deferred; Ed25519 approved in principle; the `cryptography` dependency gate passed, see ADR-0006)
- **Date:** 2026-09-28
- **Decision owner:** Developer (Focused Discussions #3 and #4, decisions E1–E10, N8–N14, S18–S22, S24; AD-7, RB-3, L-D1)

## Context

An export of all records for an `actorId` or `resourceId` must be self-contained and independently verifiable without trusting the live service. Recomputed hashes alone cannot show that a bundle is unaltered, and the completeness of an export can only be attested, not proven.

## Decision

- **Bounded single bundle.** `POST /audit/exports` requires `export:create`. Records are in ascending `sequence` order, archived records are always included, and the size is bounded by configuration.
- **Snapshot.** One read-only snapshot establishes `asOfSequence` **before** signing.
- **Pre-signing verification.** The complete chain is verified up to `asOfSequence`, including checkpoint checks. Failure returns `409`, and nothing is signed.
- **Signed manifest.** The manifest binds format, scheme, scope, `asOfSequence`, `asOfRecordHash`, `generatedAt`, the completeness statement, `recordCount`, the record list, `requestedBy`, and the **retention evidence** needed to authorize missing archived values. All of it is inside the canonical signed content, so modifying the evidence invalidates the signature. It is signed with **Ed25519**, and `keyId` is the SHA-256 fingerprint of the raw public key.
- **Export audit event after signing.** After the bundle is signed and before it is returned, an export audit event in the reserved namespace is appended. Its `sequence` is greater than `asOfSequence`, so it is never part of its own export. It inherits identifying fields from the export scope. If it cannot be appended, the service returns `503` and no bundle.
- **Offline verification.** The offline verifier:
  - verifies the manifest signature with an out-of-band trusted public key before trusting any content;
  - recomputes commitments, `contentHash`, and `recordHash`;
  - checks the record list and count;
  - validates missing-value authorization against the signed retention evidence and any included redaction events; and
  - when checkpoint artifacts are supplied, verifies their signatures and uses a checkpoint only when it can be directly anchored to signed export evidence (L-D1, ADR-0006):
    - at `asOfSequence`, compared with the signed `asOfRecordHash`; or
    - at an included record's sequence, compared with that record's signed and recomputed `recordHash`.

    Otherwise the checkpoint is reported as "not applicable / insufficient evidence", which is not a chain-integrity failure, and the other checks continue.
- **No bridging evidence.** Exports do not contain intervening chain-link evidence solely to bridge arbitrary recipient checkpoints. The signed manifest remains the authoritative signed export evidence.

## Consequences

- Recipients can verify integrity without the service. Completeness remains an attested claim of the signer.
- A broken chain blocks all exports.
- Exports disclose values and salts for unredacted values and must never be logged.

## Deferred

- Exact manifest schema and retention-evidence field structure, constrained to remain inside the signed manifest.
- Export audit event payload fields.
- Separate or shared checkpoint and export keys (S23); production key lifecycle, storage, and distribution.

## Alternatives considered

- **Including the intervening chain entries instead of a signed manifest:** documented as a future extension.
- **Including hash-only chain-link evidence to bridge recipient-supplied checkpoints:** not adopted (L-D1). It would enlarge exports with out-of-scope chain data, and it would need a range-selection rule.
- **Retention evidence outside the signature:** rejected by developer decision RB-3.
- **`GET` export:** rejected because export creation has an audit side effect.

## References

- [architecture.md](../architecture.md) Section 13
- [requirements.md](../requirements.md) §3 rows 12–13, FR-7
