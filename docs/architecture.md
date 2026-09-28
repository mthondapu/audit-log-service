# Architecture — Audit Log Service

This document describes the approved prototype architecture of the Audit Log Service. It explains *how* the system is structured to meet the requirements; it does not restate or change them.

- Requirements baseline: [requirements.md](requirements.md)
- Architecture decision records: [adr/](adr/)
- Editable diagrams (Draw.io / diagrams.net): [diagrams/](diagrams/)

Where this document refers to requirement identifiers (for example FR-3, NFR-1, S13, SC-A5), the definitions in `requirements.md` are authoritative. Items marked **deferred** are intentionally not finalized here.

## 1. Architecture overview

The service is a **modular monolith**: a single FastAPI application backed by a single PostgreSQL database, with clear internal module boundaries. Two programs run outside the service process:

- the **offline export verifier**, which is independently runnable and independently verifiable without the live service or database; and
- the **checkpoint CLI**, an authorized operator tool that creates signed checkpoints outside the public API.

Privileged **tamper-demonstration tooling** exists outside the application's trust boundary and is not part of the application architecture.

The architecture centers on a dependency-light **integrity library** (canonicalization, hashing, commitments, chain verification, manifest checks). It has no web or database dependencies and is shared by the service, the checkpoint CLI, and the offline verifier. See [ADR-0001](adr/0001-modular-monolith-and-shared-integrity-library.md).

## 2. Architectural principles

1. **Append-only by construction.** Immutable audit records are only ever inserted. Mutable data (recoverable payload values and salts) is stored separately and can only be deleted through authorized operations.
2. **Integrity logic is pure and shared.** Canonicalization, hashing, and verification are implemented once in the integrity library and exercised by unit and property tests independently of HTTP and SQL.
3. **The chain is the single source of truth.** Derived state (archived status, redacted paths) is computed from the chain and the value store, never stored as redundant mutable state in the immutable record.
4. **Explicit transactions.** Every operation that depends on ordering, isolation, or atomicity controls its own transaction (SQLAlchemy 2.x Core).
5. **Least privilege at every boundary.** Callers receive only the capabilities they need; the application database role cannot modify immutable records; signing keys and the checkpoint store are outside the database.
6. **Fail closed.** The service does not sign unverified data, does not return an export whose audit event could not be recorded, and does not report success for incomplete retention.
7. **Prototype-appropriate simplicity.** No microservices, no asynchronous job infrastructure, and no enterprise identity infrastructure.

## 3. System context

Diagram: [diagrams/system-context.drawio](diagrams/system-context.drawio)

| Participant | Interaction | Capability (NFR-2) |
|---|---|---|
| Participating business systems (writers) | Append audit events, including Scenario C access events | `events:write` |
| Auditor / regulator | Query, verify, and export | `events:read`, `chain:verify`, `export:create` |
| Administrator (operator) | Redact payload values, run retention, and create checkpoints through the checkpoint CLI | `events:read`, `events:redact`, `retention:run`, `checkpoint:create` |
| Export recipient | Verifies a bundle with the offline verifier and an out-of-band trusted public key | none (no service access required) |
| Tamper actor | Privileged direct database modification for demonstrations | outside the application trust boundary |

The service depends on PostgreSQL, a mounted API-key configuration file, signing-key files, and an external checkpoint store.

## 4. Component architecture

Diagram: [diagrams/component-architecture.drawio](diagrams/component-architecture.drawio)

| Component | Responsibility | Depends on |
|---|---|---|
| **API layer** | HTTP routing, status codes, `Location` headers, OpenAPI documentation | security, request validation, services |
| **Security** | Resolve the Bearer API key to a principal; enforce the route's capability before any resource lookup | configuration |
| **Request validation** | Strict JSON parsing (duplicate keys, I-JSON rules, U+0000, integer range, finite numbers, request size); Discussion #1 schemas; reserved system-event namespace; configuration-driven `CLIENT_ACCOUNT` validation for public writes | configuration |
| **Integrity library** | RFC 8785 canonicalization, domain labels, salts and per-value commitments, `contentHash` and `recordHash`, genesis, chain-verification algorithm, missing-value authorization, manifest construction and checks | adopted RFC 8785 library, `hashlib` |
| **Signing** | Load Ed25519 keys, sign checkpoints and manifests, compute `keyId`, verify signatures | `cryptography` (subject to the dependency gate) |
| **Append service** | The only writer of chain records; serialized append; reusable inside an existing transaction by the redaction, retention, and export services | integrity library, persistence |
| **Query service** | Filters, cursor binding, archived boundary, payload reassembly (`null` values, `redactedPaths`, `archived`) | persistence |
| **Verification service** | Consistent-snapshot streaming verification, checkpoint checks, missing-value authorization | integrity library, persistence, checkpoint store adapter |
| **Redaction service** | Pointer resolution and the atomic redaction transaction | append service, persistence |
| **Retention service** | Synchronous, bounded retention run | append service, persistence |
| **Export service** | Snapshot, bound check, pre-signing verification, bundle and manifest construction, signing, export audit event | verification, signing, append service |
| **Checkpoint store adapter** | Read signed checkpoints from the external store (the service reads only; the CLI writes) | signing |
| **Persistence** | SQLAlchemy 2.x Core repositories with explicit transaction control (isolation level, advisory lock, snapshot) | PostgreSQL |
| **Configuration** | Typed settings: database connection, API-key configuration file, limits, retention window, purge bound, key and store locations, `CLIENT_ACCOUNT` vocabulary | environment, mounted files |
| **Observability and errors** | Request identifiers, structured logs without payload values, credentials, or query strings; RFC 9457 Problem Details | — |
| **Checkpoint CLI** (separate program) | Authorized checkpoint creation | integrity library, signing, persistence (read), checkpoint store |
| **Offline export verifier** (separate program) | Verify export bundles (and checkpoint artifacts) without the service or database | integrity library, signature verification |

**Persistence technology.** SQLAlchemy 2.x Core is used instead of the ORM because correctness depends on precise control of advisory locks, isolation levels, snapshots, and multi-statement atomicity; there are no object graphs that would benefit from an ORM.

## 5. API/service boundary

Request and response semantics are defined in `requirements.md` (FR-1 to FR-7, NFR-7). The endpoint paths below follow the approved resource-oriented direction.

| Method and path | Purpose | Capability |
|---|---|---|
| `GET /health/live`, `GET /health/ready` | Liveness and readiness | none |
| `GET /docs`, `GET /openapi.json` | API documentation (public in the prototype only) | none |
| `POST /audit/events` | Append an audit event | `events:write` |
| `GET /audit/events` | Query with filters and cursor pagination | `events:read` |
| `GET /audit/events/{id}` | Retrieve one record | `events:read` |
| `GET /audit/verify` | Verify the chain | `chain:verify` |
| `POST /audit/events/{id}/redactions` | Redact payload values of one record | `events:redact` |
| `POST /audit/retention-runs` | Run synchronous, bounded retention | `retention:run` |
| `POST /audit/exports` | Create a signed export bundle | `export:create` |

Checkpoint creation is deliberately **not** an HTTP endpoint (Section 12).

## 6. Authentication and authorization

See [ADR-0008](adr/0008-authentication-and-authorization.md).

- **Credentials.** Callers present a static API key as a Bearer credential. The service hashes the presented key with SHA-256 and compares it with configured hashes in constant time. Raw keys are never stored or committed.
- **Configuration.** A mounted configuration file outside the database maps each key hash to a non-secret principal ID and its role or capabilities. A database writer therefore cannot grant itself credentials.
- **Principal.** The principal ID becomes `recordedBy` for every event the caller causes, including system events created on the caller's request.
- **Capabilities.** Each route declares one capability. The prototype roles (writer, auditor, regulator, administrator) are a prototype security boundary, not an assignment requirement or an enterprise RBAC design.
- **Ordering.** Authorization is enforced before resource lookup, so an unauthorized caller cannot infer whether a resource exists. Its order relative to body validation is an implementation choice, not a requirement.
- **Failures.** Missing or invalid credentials return `401`; a missing capability returns `403`. Denied attempts are logged operationally and never appended to the audit chain.

## 7. Audit event lifecycle

1. **Appended.** The immutable record (identity fields, committed payload structure, three hashes) is inserted together with the recoverable payload values and their salts.
2. **Partially or fully redacted (optional).** Selected values and their salts are deleted; a redaction system event records the operation. The immutable record is unchanged.
3. **Archived.** Once a committed retention event covers the record's `sequence`, the record is archived and its payload values are no longer available; bounded physical purge of its recoverable values and salts may still be in progress or may resume in a later run. The immutable record, including metadata, remains.

`redactedPaths` and `archived` are derived response fields and are never hashed. System events (retention, redaction, export) follow the same lifecycle but cannot be redacted in the prototype.

## 8. Append and hash-chain integrity flow

Diagram: [diagrams/audit-append-integrity-sequence.drawio](diagrams/audit-append-integrity-sequence.drawio). See [ADR-0002](adr/0002-hash-chain-and-canonicalization.md) and [ADR-0003](adr/0003-serialized-append.md).

1. Authenticate and authorize (`events:write`).
2. Strictly parse and validate the request (FR-1), including the reserved namespace and, for public `CLIENT_ACCOUNT` events, the configured vocabulary.
3. Generate the record `id` and one salt per payload value; compute the per-value commitments and the committed payload structure.
4. Open a transaction at READ COMMITTED and acquire the transaction-scoped advisory lock.
5. Read the chain head after acquiring the lock. For the first record, `previousHash` is the genesis value (64 lowercase hexadecimal zeros) and `sequence` is 1.
6. Take `recordedAt` from the database clock after locking, clamped so that it never goes backwards relative to the head.
7. Compute `contentHash` and `recordHash` with the integrity library.
8. Insert the immutable record and its payload-value rows; commit, which releases the lock.
9. Return `201 Created` with `Location`.

Database constraints (`UNIQUE(sequence)`, `UNIQUE(previous_hash)`, `UNIQUE(id)`) reject any fork even if application logic were wrong. `recordedAt` clamping prevents the application from writing a regression; verification still reports `RECORDED_AT_REGRESSION` for regressions introduced outside the application.

## 9. Payload commitment and redaction model

See [ADR-0004](adr/0004-redaction-commitments-and-value-storage.md) and [diagrams/retention-redaction.drawio](diagrams/retention-redaction.drawio).

- **Commitments.** Each scalar payload value receives a cryptographically secure salt of at least 128 bits. Its commitment is computed with RFC 8785 and SHA-256 under a distinct domain label. The committed payload structure preserves keys and array shape, replacing each value with its commitment; `contentHash` covers this structure.
- **Value storage.** Each recoverable value is stored as its RFC 8785 canonical JSON text, together with its salt, keyed by record and JSON Pointer. Canonical text avoids number re-interpretation by JSONB that would break commitment verification. The committed structure contains only keys, arrays, and hexadecimal strings, so it may be stored as JSONB.
- **Redaction transaction.** Under the append lock: load the target (`404` if absent); reject system-event targets and archived targets with `409`; resolve pointers (a pointer covers a value whose pointer equals it or starts with it followed by `/`); reject invalid or nonexistent pointers with `422`; reject with `409` if no value remains to redact; delete the covered value and salt rows; append the redaction system event; commit. The redaction event inherits `actorId`, `resourceType`, and `resourceId` from the target, and `recordedBy` is the operator.
- **Verification.** `contentHash` is recomputed from the immutable record alone; each present value must open its commitment; each missing value must be authorized (Section 10) or is reported as `PAYLOAD_VALUE_MISSING`, identified only by `sequence` and `recordId`.

## 10. Retention model

See [ADR-0005](adr/0005-retention-and-archived-boundary.md).

`POST /audit/retention-runs` (capability `retention:run`) performs a **synchronous, bounded** retention operation. No asynchronous job infrastructure is used.

1. Under the append lock, compute the cutoff from the database clock and the configured retention window, and determine the highest eligible `sequence`.
2. If new records are eligible, append a retention system event recording the cutoff and `upToSequence`; this event establishes the new archived boundary. `recordedBy` is the authenticated operator; no separate internal identity is used.
3. Purge recoverable values and salts for records at or below the current boundary, within the configured bound. If no new records are eligible but an earlier purge is incomplete, the run resumes that outstanding purge without appending another retention event.
4. Respond:
   - `201 Created` when a new retention event was recorded and its bounded purge completed;
   - `200 OK` with the resumed-purge result when no new records were eligible and an outstanding purge was resumed and completed;
   - `200 OK` with a structured "nothing eligible" result when there is neither a new eligible boundary nor unfinished purge work;
   - `422` for an invalid request, configuration, or input;
   - `503 Service Unavailable` when a valid retention operation cannot complete because the configured operational bound prevents it. Committed work is kept, and a subsequent run resumes the purge.

The exact response schema follows the existing API conventions and is an implementation detail. Missing-value authorization for purged values comes from the retention boundary (requirements FR-3).

## 11. Archived boundary

The archived boundary is the `upToSequence` of the latest applicable retention event in the chain. There is no redundant retention-runs table. Queries exclude records at or below the boundary unless `includeArchived=true`; `GET /audit/events/{id}` returns archived records with `archived: true`.

The latest retention event always retains its own payload values: its `upToSequence` is below its own `sequence`, so only a later retention event can archive it, and that later event then becomes the latest. The boundary therefore remains readable and verifiable.

## 12. Checkpoint trust model

See [ADR-0006](adr/0006-checkpoint-trust-anchor.md).

- **Creation.** Checkpoints are created explicitly by an authorized **checkpoint CLI**, not by a public HTTP endpoint. The CLI requires the `checkpoint:create` capability from the operator's credential, uses the checkpoint signing key, and writes to the checkpoint store configured for the deployment. It does not accept arbitrary output paths.
- **Verification before signing.** The CLI verifies the applicable audit chain state before creating and signing a checkpoint. If verification fails, it refuses to create or sign the checkpoint, so no trusted checkpoint is ever created over known-bad chain state.
- **Why not an HTTP endpoint.** Checkpoints are trust anchors. Keeping their creation off the public API removes a remotely reachable signing operation, keeps the capability out of reach of ordinary writers, readers, auditors, and regulators, and makes checkpoint creation a deliberate operator action.
- **Artifacts.** Checkpoints are deterministic, signed artifacts (canonical content plus Ed25519 signature) stored outside the audit database. The service and the offline verifier read them. The offline verifier loads checkpoint artifacts, verifies their signatures, establishes the trusted checkpoint boundary, and uses that boundary during independent export verification, without the live service or database.
- **Protection.** The tamper actor has database privileges only and cannot modify or replace the checkpoint store or the signing key.
- **What they enable.** Record modification is detected without a checkpoint. After a checkpoint is created, tail truncation below it is reported as `CHAIN_TRUNCATED`, and a full rewrite with recomputed hashes is reported as `ANCHOR_MISMATCH`.
- **Limitation.** Records appended after the latest checkpoint can be rewritten, fabricated, or truncated by an attacker with database write access (FR-4).

The exact CLI syntax, checkpoint file format, store location, and lifecycle or timing are deferred.

## 13. Export and offline verification

Diagram: [diagrams/export-independent-verification.drawio](diagrams/export-independent-verification.drawio). See [ADR-0007](adr/0007-signed-exports.md).

1. Authenticate and authorize (`export:create`); validate the scope; confirm the signing key is available (`503` otherwise).
2. Open one read-only REPEATABLE READ snapshot and establish `asOfSequence`.
3. Check the configured export bound (`422` if exceeded).
4. Verify the complete chain up to `asOfSequence`, including checkpoint checks (`409` on failure).
5. Select matching records, including archived records, and the retention evidence needed to authorize missing archived values.
6. Build the manifest, including scope, `asOfSequence`, record list, `requestedBy`, and the retention evidence, and sign it with Ed25519. The retention evidence is inside the signed manifest.
7. Leave the snapshot. Append the export audit event under the append lock; its `sequence` is greater than `asOfSequence`, so it is never part of its own export. If the event cannot be appended, return `503` and no bundle.
8. Return `200 OK` with the bundle.

The **offline verifier** runs in the recipient's environment without the service, database, service credentials, or network access to the service. It:

- verifies the manifest signature with an out-of-band trusted public key before trusting any content;
- recomputes commitments, `contentHash`, and `recordHash`;
- checks the record list and count;
- validates missing-value authorization against the signed retention evidence and any included redaction events; and
- when checkpoint artifacts are supplied, loads them, verifies their signatures, and uses the trusted checkpoint boundary during export verification (Section 12).

The exact manifest schema and retention-evidence representation are implementation and documentation details, constrained by the rule that the evidence must remain inside the signed manifest.

## 14. Database privilege boundaries

See [ADR-0009](adr/0009-database-privileges-and-tamper-boundary.md).

| Boundary | Purpose | Privileges (principle) |
|---|---|---|
| Application role | Normal service operation | Insert and select immutable records; insert, select, and delete recoverable values and salts. No update or delete on immutable records. |
| Owner / migration role | Schema ownership and migrations | Schema changes; not used by the running service |
| Tamper actor | Demonstrations of detection | Privileged direct modification of the database, outside the application trust boundary |

Immutable records are additionally protected by a database-level guard against update and delete for the application role. Exact grants are an implementation detail.

## 15. Tamper demonstration boundary

Tamper demonstrations run through separate, privileged tooling, never through the normal application API. The tooling may reuse the integrity library, for example to recompute a consistent forged chain for the full-rewrite demonstration. The tamper actor has no access to the checkpoint store, signing keys, or API-key configuration. How the tamper actor obtains its database privileges is part of the tooling, not the application architecture.

## 16. Scenario C architecture

Scenario C follows the prototype clarification and assumptions in `requirements.md` FR-8 (SC-A1 to SC-A8). These are developer assumptions, not stakeholder-confirmed requirements.

- Participating business systems report access to client account data through `POST /audit/events` (`events:write`), with `resourceType` `CLIENT_ACCOUNT`, `actorId` set to whoever accessed the account, and `recordedBy` identifying the reporting system.
- Request validation applies the configured access-event vocabulary and required payload keys to public writes of `CLIENT_ACCOUNT` events only; reserved system events are exempt.
- Regulators and auditors use the existing query, verification, and export capabilities. Exports are recorded as export audit events; queries are logged operationally.
- Redacted values appear as `null` with `redactedPaths`.
- Production concerns such as per-account regulator scoping remain outside the prototype.

## 17. Trust boundaries

| # | Boundary | Control |
|---|---|---|
| TB-1 | Callers → API | Bearer API keys, capabilities, authorization before resource lookup |
| TB-2 | Service → database | Application role cannot update or delete immutable records; uniqueness constraints prevent forks |
| TB-3 | Database → checkpoint store and signing keys | Stored outside the database; not accessible to the tamper actor |
| TB-4 | Operator → checkpoint CLI | `checkpoint:create` required; configured store only |
| TB-5 | Service → export recipient | Ed25519-signed manifest verified with an out-of-band trusted public key |
| TB-6 | Tamper actor → database | Outside the application trust boundary; detected by verification and checkpoints |

## 18. Security considerations

- The integrity library is shared by the service, the CLI, and the offline verifier, so a defect would affect all of them. RFC 8785 test vectors, property tests, and a documented verification algorithm that others can reimplement mitigate this.
- Signing keys, the checkpoint store, and the API-key configuration reside on the application host in the prototype; host compromise compromises them. Production key management is deferred.
- The application role can delete recoverable values (required for redaction and retention); unauthorized deletion is detected as `PAYLOAD_VALUE_MISSING`, except for forged authorization within the checkpoint window.
- Export bundles contain values and salts and must never be logged.
- Owner and tamper credentials must never be part of the application's configuration.

## 19. Failure and verification behavior

| Condition | Behavior |
|---|---|
| Missing or invalid credentials | `401` with `WWW-Authenticate` |
| Missing capability | `403`, before resource lookup |
| Invalid request or reserved event type from a public caller | `422` |
| Redaction target missing | `404` |
| Redaction of a system event, archived record, or nothing new | `409` |
| Export bound exceeded / scope invalid | `422` |
| Pre-signing verification fails | `409`; nothing is signed |
| Signing key unavailable | `503` |
| Export audit event cannot be appended | `503`; no bundle returned |
| Retention request, configuration, or input invalid | `422` |
| Retention cannot complete within its configured bound | `503`; committed work is kept and later runs resume |
| Retention: nothing new eligible, outstanding purge resumed and completed | `200` with the resumed-purge result |
| Retention: nothing eligible and no unfinished purge | `200` with a "nothing eligible" result |
| Checkpoint CLI: chain verification fails | Checkpoint is not created or signed |
| Database unavailable | `503` |
| `/audit/verify` detects violations | `200` with the verification result |

## 20. Architecture limitations and trade-offs

- Appends are serialized: correct and simple, with limited write throughput (accepted by assumptions 1–2).
- A broken chain blocks all exports, because unverified data is never signed.
- Verification and pre-signing verification scan the full chain (O(n)).
- The unanchored window after the latest checkpoint remains exposed to an attacker with database write access.
- Retention keeps metadata indefinitely; physical deletion is future work.
- Synchronous retention bounds each run; large backlogs need several runs.
- Payload keys and structure remain visible after redaction.
- Prototype secrets share the application host.

## 21. Deferred implementation details

- Checkpoint CLI syntax, checkpoint artifact format, store location, and lifecycle or timing.
- Separate or shared checkpoint and export signing keys; production key lifecycle, storage, and distribution.
- Exact manifest schema and retention-evidence representation (inside the signed manifest).
- Retention-run response schema.
- Retention event resource identity; export audit event payload fields.
- Commitment byte layout (to be documented for verifiers).
- Reserved namespace prefix, access-event vocabulary, and configuration layout.
- Table and column names, exact database grants, limits, batch sizes, cursor encoding, advisory-lock key, and timeouts.
- Dependency gates: RFC 8785 library adoption and `cryptography` approval, with outcomes recorded before the integrity and signing code is implemented.

## 22. Architecture decision references

| ADR | Title |
|---|---|
| [0001](adr/0001-modular-monolith-and-shared-integrity-library.md) | Modular monolith and shared integrity library |
| [0002](adr/0002-hash-chain-and-canonicalization.md) | Hash chain and canonicalization |
| [0003](adr/0003-serialized-append.md) | Serialized append |
| [0004](adr/0004-redaction-commitments-and-value-storage.md) | Redaction commitments and value storage |
| [0005](adr/0005-retention-and-archived-boundary.md) | Retention and archived boundary |
| [0006](adr/0006-checkpoint-trust-anchor.md) | Checkpoint trust anchor |
| [0007](adr/0007-signed-exports.md) | Signed exports |
| [0008](adr/0008-authentication-and-authorization.md) | Authentication and authorization |
| [0009](adr/0009-database-privileges-and-tamper-boundary.md) | Database privileges and tamper boundary |
