# ADR-0007: Signed exports

- **Status:** Accepted; implemented in Phase 11 (production key lifecycle deferred; the `cryptography` dependency gate passed, see ADR-0006)
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
- **Separate signing key (Phase 10, S23).** The export signing key is separate from the checkpoint signing key (ADR-0006): the running service holds the export key, but must never hold the checkpoint key.
- **No bridging evidence.** Exports do not contain intervening chain-link evidence solely to bridge arbitrary recipient checkpoints. The signed manifest remains the authoritative signed export evidence.

## Consequences

- Recipients can verify integrity without the service. Completeness remains an attested claim of the signer.
- A broken chain blocks all exports.
- Exports disclose values and salts for unredacted values and must never be logged.

## Implementation (Phase 11)

Decided by the developer on 2026-09-28 (Phase 11 decisions E1 to E17, distinct from the Focused Discussion #3 decisions above). The full contract is in requirements FR-7 (API definition).

- **Manifest (E1, E2).** `format` `audit-log-export/v1`, `scheme`, `scope`, `asOfSequence`, `asOfRecordHash`, `generatedAt`, a fixed `completeness` statement, `requestedBy`, `recordCount`, `records` (`sequence`, `id`, `recordHash`), `retention`, and `keyId`, signed with Ed25519 over `UTF-8("audit-log/v1/manifest") || 0x00 || RFC8785(manifest)`. The bundle is `{manifest, signature, records}`.
- **Records (E3).** Hash inputs plus `committedPayload` and `payloadValues` (`{value, salt}` by JSON Pointer). Redacted values are absent; archived records carry no values. No second rendered payload.
- **Retention evidence (E4).** `null` or `{upToSequence, cutoff, eventSequence, eventId, eventRecordHash}` of the latest applicable retention event, inside the signed manifest.
- **Empty chain (E5).** `asOfSequence` `0` and `asOfRecordHash` `null`.
- **Keys (E6, E7).** `AUDIT_LOG_EXPORT_SIGNING_KEY_FILE` is optional and validated at startup; when unset, exports return `503`. It is refused if it is the checkpoint key pair.
- **Limits (E8).** At most `AUDIT_LOG_EXPORT_MAX_RECORDS` records (checked in the snapshot before verification) and `AUDIT_LOG_EXPORT_MAX_BYTES` bytes (checked after serialization, before the export event); both `422`.
- **Export event (E9).** `AUDIT_LOG_EXPORT`, with identity from the scope and fixed server values otherwise, and payload `{scope, asOfSequence, recordCount, keyId, manifestSignature}`.
- **Failures (E10, E11).** A failed pre-signing verification is `409` with a fixed detail and no violation details; an invalid checkpoint store is `500`.
- **Offline verifier (E12 to E15).** Strict parsing, key and signature first, then the list, order, scope, `asOfSequence`, links, hashes, commitments, and missing-value authorization, with the approved violation types and exit codes; checkpoints per L-D1, an invalid checkpoint making the result invalid.
- **Validation and handling (E16, E17).** Scope fields use the FR-2 rules; responses use `Cache-Control: no-store`; logs never contain scope identifiers, values, salts, keys, or the manifest.

## Deferred

- Production key lifecycle, storage, and distribution, including export key rotation (the verifier trusts the public key it is given).

## Alternatives considered

- **Including the intervening chain entries instead of a signed manifest:** documented as a future extension.
- **Including hash-only chain-link evidence to bridge recipient-supplied checkpoints:** not adopted (L-D1). It would enlarge exports with out-of-scope chain data, and it would need a range-selection rule.
- **Retention evidence outside the signature:** rejected by developer decision RB-3.
- **`GET` export:** rejected because export creation has an audit side effect.

## References

- [architecture.md](../architecture.md) Section 13
- [requirements.md](../requirements.md) §3 rows 12–13, FR-7
