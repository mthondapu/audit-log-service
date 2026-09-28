# ADR-0004: Redaction commitments and value storage

- **Status:** Accepted
- **Date:** 2026-09-28
- **Decision owner:** Developer (Focused Discussions #2 and #3, decisions I10, X1–X9, S12, S13; AD-2, AD-6)

## Context

Sensitive payload values must be removable without rewriting the original record's hashes. Remaining values must stay verifiable, and verifiers must be able to tell an authorized removal from tampering.

## Decision

- **Per-value salted commitments.** Each scalar payload value receives a cryptographically secure salt of at least 128 bits. `contentHash` covers the payload structure with each value replaced by its commitment. Commitments use the approved RFC 8785, SHA-256, and domain-label design. The exact byte layout is documented for verifiers during implementation.
- **Storage.** The immutable record stores the committed structure. Recoverable values are stored separately, one row per value, together with their salts. Each value is stored as its **RFC 8785 canonical JSON text**, not as JSONB, so that its exact representation survives the round trip. The committed structure may be stored as JSONB, because it contains only keys, arrays, and hexadecimal strings.
- **Redaction.** Values are addressed with RFC 6901 JSON Pointers; a pointer to an object or array covers every value beneath it. Value and salt deletion and the redaction system event are committed atomically under the append lock.
  - Only values not yet redacted are redacted and recorded.
  - Nothing new, an archived target, or a **system-event target** returns `409`.
  - Invalid or nonexistent pointers return `422`, identified by position.
  - The redaction event inherits `actorId`, `resourceType`, and `resourceId` from the target, and `recordedBy` is the operator.
- **Verification.** A missing value is authorized only by a covering valid retention event or a later valid reserved redaction event that names the target and covers the pointer. Otherwise it is reported as `PAYLOAD_VALUE_MISSING`, identified only by `sequence` and `recordId`.

## Consequences

- `contentHash` never changes because of redaction or retention.
- Payload keys and structure remain visible after redaction (documented limitation).
- Storing values as canonical text keeps commitment verification exact; payload values are not queryable as JSON, which no requirement needs.
- System events cannot be redacted, so their authorizing content is never lost to redaction.

## Alternatives considered

- **Re-hashing a redacted version, authorized by an event:** rejected; it weakens the binding to the original content, and an unsalted original hash would let short redacted values be guessed.
- **Top-level commitments only:** rejected; too coarse for structured redaction.
- **Encrypting values and destroying the key:** rejected as more complex, requiring key management for every record.
- **JSONB value storage:** rejected; number normalization can break commitment verification.

## References

- [architecture.md](../architecture.md) Sections 7, 9
- [requirements.md](../requirements.md) FR-2, FR-3, FR-6, NFR-1
