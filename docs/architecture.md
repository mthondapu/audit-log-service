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
| **Request validation** | Strict JSON parsing (duplicate keys, I-JSON rules, U+0000, the ±(2^53−1) numeric domain, finite numbers, request size); Discussion #1 schemas; reserved system-event namespace; configuration-driven `CLIENT_ACCOUNT` validation for public writes | configuration |
| **Integrity library** | RFC 8785 canonicalization, domain labels, salts and per-value commitments, `contentHash` and `recordHash`, genesis, chain-verification algorithm, missing-value authorization, manifest construction and checks | `rfc8785` (RFC 8785 library), `hashlib` |
| **Signing** | Load Ed25519 keys, sign checkpoints and manifests, compute `keyId`, verify signatures | `cryptography` |
| **Append service** | The only writer of chain records; serialized append; reusable inside an existing transaction by the redaction, retention, and export services | integrity library, persistence |
| **Query service** | Filters, cursor binding, archived boundary, payload reassembly (`null` values, `redactedPaths`, `archived`) | persistence |
| **Verification service** | Consistent-snapshot streaming verification, checkpoint checks, missing-value authorization | integrity library, persistence, checkpoint store adapter |
| **Redaction service** | Pointer resolution and the atomic redaction transaction | append service, persistence |
| **Retention service** | Synchronous, bounded retention run | append service, persistence |
| **Export service** | Snapshot, bound check, pre-signing verification, bundle and manifest construction, signing, export audit event | verification, signing, append service |
| **Checkpoint store adapter** | Read signed checkpoints from the external store (the service reads only; the CLI writes) | signing |
| **Persistence** | SQLAlchemy 2.x Core repositories with explicit transaction control (isolation level, advisory lock, snapshot) | PostgreSQL |
| **Configuration** | Typed settings validated with plain Pydantic v2: scalar and secret settings and file paths from environment variables; the API-key file and the `CLIENT_ACCOUNT` vocabulary as separate mounted TOML files, read with `tomllib`; loaded once at startup, failing fast when invalid | environment, mounted files |
| **Observability and errors** | Request identifiers, structured logs without payload values, credentials, or query strings; RFC 9457 Problem Details | — |
| **Checkpoint CLI** (separate program) | Authorized checkpoint creation | integrity library, signing, persistence (read), checkpoint store |
| **Offline export verifier** (separate program) | Verify export bundles (and checkpoint artifacts) without the service or database | integrity library, signature verification |

**Persistence technology.** SQLAlchemy 2.x Core is used instead of the ORM because correctness depends on precise control of advisory locks, isolation levels, snapshots, and multi-statement atomicity; there are no object graphs that would benefit from an ORM.

## 5. API/service boundary

Request and response semantics are defined in `requirements.md` (FR-1 to FR-7, NFR-7). The endpoint paths below are final.

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

**Implemented so far (Phases 5–9):** `POST /audit/events`, `GET /audit/events`, `GET /audit/events/{id}`, `GET /audit/verify`, `POST /audit/events/{id}/redactions`, and `POST /audit/retention-runs`. Route handlers only authenticate, authorize, and translate HTTP; an application layer validates requests (including Scenario C for `CLIENT_ACCOUNT` events) and calls the persistence layer, which appends through the serialized path and computes nothing cryptographic itself. The request body is read and checked explicitly after authentication and authorization, so that the D4 check order holds and duplicate JSON keys are detected.

**Command-line programs (Phase 10):** `audit-log-checkpoint create` (the checkpoint CLI) and `audit-log-verify checkpoint` (the offline verifier, checkpoint artifacts only until exports exist). See Section 12 and requirements FR-4.

## 6. Authentication and authorization

See [ADR-0008](adr/0008-authentication-and-authorization.md).

- **Credentials.** Callers present a static API key as a Bearer credential. The service hashes the presented key with SHA-256 and compares it with configured hashes in constant time. Raw keys are never stored or committed.
- **Configuration.** A mounted TOML file outside the database, read with the standard library's `tomllib`, maps each principal to a non-secret principal ID, exactly one approved prototype role, and one or more lowercase hexadecimal SHA-256 key hashes (to support rotation). A database writer therefore cannot grant itself credentials.
  - The approved role-to-capability mapping is authoritative; the file cannot list arbitrary capabilities.
  - Principal IDs match `^[a-z][a-z0-9._-]{0,63}$`.
  - Raw keys are machine-generated with at least 128 bits of entropy (applying to the raw key, not the digest) and are never stored in PostgreSQL, Git, or logs.
  - The service and CLI load the file once at startup, and changes require a restart. They fail fast on invalid configuration: missing or malformed file, unknown fields, duplicate principal IDs or key hashes, invalid hash format, unknown role, a principal with no keys, no principals, or an invalid principal ID.
  - Errors never echo raw keys or hash values.
  - See ADR-0008 (D3).
- **Principal.** The principal ID becomes `recordedBy` for every event the caller causes, including system events created on the caller's request.
- **Capabilities.** Each route declares one capability. The prototype roles (writer, auditor, regulator, administrator) are a prototype security boundary, not an assignment requirement or an enterprise RBAC design.
- **Ordering.** Requests are processed in a fixed order (D4): authenticate (`401`), authorize (`403`), validate the request (`400`/`422`), then look up resources (`404`/`409`). An unauthorized caller therefore cannot infer whether a resource exists, and receives no validation feedback.
- **Failures.** Every authentication failure returns `401` with `WWW-Authenticate: Bearer` and the same Problem Details structure (D4). This covers a missing Authorization header, a non-Bearer scheme, an empty or malformed token, multiple Authorization headers, and unknown credentials. A missing capability returns `403`. Denied attempts are logged operationally and never appended to the audit chain.

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

**Canonicalization and numeric domain.** Hash and signature inputs are canonicalized with the `rfc8785` library (ADR-0002), which serializes numbers as RFC 8785 requires. The service separately bounds every accepted JSON number to ±(2^53−1) by numeric value, whatever its notation (requirements FR-1). This bound is an application-level rule, not part of RFC 8785. RFC 8785 writes some whole-number doubles between 2^53 and 10^21 as plain integer digits, which would read back as integers outside the service's integer domain. With the bound in place, every accepted value canonicalizes to text that parses back under the same rules and canonicalizes to the same bytes, so stored canonical text and exports need no special verifier handling of RFC 8785's 10^21 formatting boundary.

**Hash inputs.** Every hash input is `SHA-256(UTF-8(label) || 0x00 || RFC8785(object))`, where the zero byte is the label boundary. `contentHash` uses `audit-log/v1/content` over `{id, eventType, actorId, resourceType, resourceId, timestamp, recordedAt, recordedBy, payload}`; `recordHash` uses `audit-log/v1/record` over `{sequence, previousHash, contentHash}`; commitments use `audit-log/v1/commitment` (Section 9). Timestamps are written as `YYYY-MM-DDTHH:MM:SS.ffffffZ` and `id` as a lowercase hyphenated UUID; the integrity core rejects any other form instead of normalizing it.

## 9. Payload commitment and redaction model

See [ADR-0004](adr/0004-redaction-commitments-and-value-storage.md) and [diagrams/retention-redaction.drawio](diagrams/retention-redaction.drawio).

- **Commitments.** Each scalar payload value receives a cryptographically secure salt of at least 128 bits. Its commitment is computed with RFC 8785 and SHA-256 under a distinct domain label. The committed payload structure preserves keys and array shape, replacing each value with its commitment; `contentHash` covers this structure. The commitment is `SHA-256(UTF-8("audit-log/v1/commitment") || 0x00 || RFC8785({"salt": <salt>, "value": <value>}))` with a 128-bit salt written as lowercase hex. Only scalar leaves are committed; empty objects and arrays stay as structure, and a value's JSON Pointer is bound by `contentHash`, not by its commitment.
- **Value storage.** Each recoverable value is stored as its RFC 8785 canonical JSON text, together with its salt, keyed by record and JSON Pointer. Canonical text avoids number re-interpretation by JSONB that would break commitment verification. The committed structure contains only keys, arrays, and hexadecimal strings, so it may be stored as JSONB.
- **Redaction transaction.** The request body is validated first (`400`/`422`, including pointer syntax), following the D4 order. Then, under the append lock: load the target (`404` if absent); reject system-event targets and archived targets with `409`; resolve pointers (a pointer covers a value whose pointer equals it or starts with it followed by `/`); reject nonexistent pointers with `422`; reject with `409` if no value remains to redact; delete the covered value and salt rows; append the redaction system event; commit. The redaction event inherits `actorId`, `resourceType`, and `resourceId` from the target, and `recordedBy` is the operator.
- **Verification.** `contentHash` is recomputed from the immutable record alone; each present value must open its commitment; each missing value must be authorized (Section 10) or is reported as `PAYLOAD_VALUE_MISSING`, identified only by `sequence` and `recordId`. Missing values are checked; redaction events (since Phase 8) and retention events (since Phase 9) authorize them.

## 10. Retention model

See [ADR-0005](adr/0005-retention-and-archived-boundary.md).

`POST /audit/retention-runs` (capability `retention:run`) performs a **synchronous, bounded** retention operation. No asynchronous job infrastructure is used.

1. Under the append lock, compute the cutoff from the database clock and the configured retention window, and determine the highest eligible `sequence`.
2. If new records are eligible, append a retention system event recording the cutoff and `upToSequence`; this event establishes the new archived boundary. `recordedBy` is the authenticated operator; no separate internal identity is used.
3. Purge recoverable values and salts for records at or below the current boundary, within the configured bound. If no new records are eligible but an earlier purge is incomplete, the run resumes that outstanding purge without appending another retention event.
4. Respond:
   - `201 Created` when a new retention event was recorded and its bounded purge completed, with `Location: /audit/events/{retentionEventId}`. The retention event is the persisted resource the run creates; there is no retention-run resource;
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
- **Artifacts.** Checkpoints are deterministic, signed artifacts (canonical content plus Ed25519 signature) stored outside the audit database. The service and the offline verifier read them. The offline verifier loads supplied checkpoint artifacts and verifies their signatures, without the live service or database. It uses a checkpoint during export verification only when the checkpoint can be directly anchored to signed export evidence (Section 13).
- **Protection.** The tamper actor has database privileges only and cannot modify or replace the checkpoint store or the signing key.
- **What they enable.** Record modification is detected without a checkpoint. After a checkpoint is created, tail truncation below it is reported as `CHAIN_TRUNCATED`, and a full rewrite with recomputed hashes is reported as `ANCHOR_MISMATCH`.
- **Limitation.** Records appended after the latest checkpoint can be rewritten, fabricated, or truncated by an attacker with database write access (FR-4).

**Implementation (Phase 10).** The command syntax, operator credential, artifact format, store layout, keys, and exit codes are recorded in requirements FR-4. In brief:

- the operator's API key is read from stdin, never from arguments or the environment, and checked with the service's API-key configuration; `checkpoint:create` is required before the signing key is read or the database is contacted. This check attributes the checkpoint and keeps other principals from the tool; the real boundary is file-system access to the signing key;
- the CLI's database login is in `audit_log_checkpoint`, which has only `SELECT`;
- a checkpoint is an Ed25519 signature over `UTF-8("audit-log/v1/checkpoint") || 0x00 || RFC8785(checkpoint)`, stored as one JSON file per checkpoint in a configured directory, named by its 20-digit sequence and never overwritten;
- the checkpoint key is separate from the export key; the service holds only the trusted public key;
- the service and the CLI validate every artifact in the store, fail closed on any invalid one, and read the store before opening their database snapshot; and
- checkpoints are created manually; nothing is scheduled.

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
- when checkpoint artifacts are supplied, loads them, verifies their signatures, and handles each one as follows:
  - if the checkpoint's sequence equals `asOfSequence`, its `recordHash` must equal the signed `asOfRecordHash`;
  - if its sequence matches an included record, its `recordHash` must equal that record's signed and recomputed `recordHash`;
  - otherwise the checkpoint cannot be directly anchored to the export, and is reported as "not applicable / insufficient evidence". That is not a chain-integrity failure, and the other checks continue.

A supplied checkpoint therefore does not establish a trusted boundary for every export. Exports do not carry intervening chain-link evidence to bridge arbitrary recipient checkpoints. Where a checkpoint cannot be anchored, assurance rests on the service's pre-signing verification (which includes checks against the service's own checkpoint store) and on the export signature.

The exact manifest schema and retention-evidence representation are implementation and documentation details, constrained by the rule that the evidence must remain inside the signed manifest.

## 14. Database privilege boundaries

See [ADR-0009](adr/0009-database-privileges-and-tamper-boundary.md).

| Boundary | Purpose | Privileges (principle) |
|---|---|---|
| Application role | Normal service operation | Insert and select immutable records; insert, select, and delete recoverable values and salts. No update or delete on immutable records. |
| Owner / migration role | Schema ownership and migrations | Schema changes; not used by the running service |
| Checkpoint CLI access | Chain verification before checkpoint signing | Read-only access to the audit data (D4); no insert, update, or delete |
| Tamper actor | Demonstrations of detection | Privileged direct modification of the database, outside the application trust boundary |

Immutable records are additionally protected by a database-level guard for the application role. In Phase 4 the guard is the application role's privileges: `audit_log_app` (a `NOLOGIN` group role provisioned outside the migrations) has `SELECT` and `INSERT` on `audit_records`, and `SELECT`, `INSERT`, and `DELETE` on `audit_payload_values`, with no `UPDATE`, `DELETE`, or `TRUNCATE` on `audit_records`. There is deliberately no trigger that blocks every role, so the future privileged tamper tooling needs no trigger disabling (ADR-0009). Since Phase 10, the checkpoint CLI uses `audit_log_checkpoint`, a `NOLOGIN` group role with only `SELECT` on both tables (migration 0002). Tamper-actor grants are deferred.

## 15. Tamper demonstration boundary

Tamper demonstrations run through separate, privileged tooling, never through the normal application API. The tooling may reuse the integrity library, for example to recompute a consistent forged chain for the full-rewrite demonstration. The tamper actor has no access to the checkpoint store, signing keys, or API-key configuration. How the tamper actor obtains its database privileges is part of the tooling, not the application architecture. It must not be a PostgreSQL superuser or hold `pg_write_server_files` or `pg_execute_server_program`: those can write files on the database host (for example with `COPY ... TO`), which would reach the checkpoint store if it shared that host (ADR-0009).

## 16. Scenario C architecture

Scenario C follows the prototype clarification and assumptions in `requirements.md` FR-8 (SC-A1 to SC-A8). These are developer assumptions, not stakeholder-confirmed requirements.

- Participating business systems report access to client account data through `POST /audit/events` (`events:write`), with `resourceType` `CLIENT_ACCOUNT`, `actorId` set to whoever accessed the account, and `recordedBy` identifying the reporting system.
- Request validation applies the configured access-event vocabulary and required payload keys to public writes of `CLIENT_ACCOUNT` events only; reserved system events are exempt.
- The vocabulary file (a separate TOML file, D3) has a minimal structure: a `resource_type` value, and one or more `event_types` entries, each with a `name` and a list of `required_payload_keys`. Names must be unique, and an entry's required keys must not repeat. The `resource_type` value, every event-type name, and every required payload key must be non-empty, must have no leading or trailing whitespace, and must contain no ASCII control characters (U+0000–U+001F, U+007F). The vocabulary names themselves remain deferred.
- Regulators and auditors use the existing query, verification, and export capabilities. Exports are recorded as export audit events; queries are logged operationally.
- Redacted values appear as `null` with `redactedPaths`.
- Production concerns such as per-account regulator scoping remain outside the prototype.

## 17. Trust boundaries

| # | Boundary | Control |
|---|---|---|
| TB-1 | Callers → API | Bearer API keys, capabilities, authorization before resource lookup |
| TB-2 | Service → database | Application role cannot update or delete immutable records; uniqueness constraints prevent forks |
| TB-3 | Database → checkpoint store and signing keys | Stored outside the database; not accessible to the tamper actor, which must not hold server-file or program-execution privileges; the service reads the store only, with the public key |
| TB-4 | Operator → checkpoint CLI | API key from stdin; `checkpoint:create` required; read-only database role; configured store only. File access to the signing key is the actual signing boundary |
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
| Any authentication failure (missing, non-Bearer, empty or malformed, multiple headers, unknown key) | `401` with `WWW-Authenticate: Bearer`, uniform Problem Details |
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
- The prototype serves plain HTTP for local use, so Bearer API keys are not encrypted in transit. TLS/HTTPS is a production consideration, not a prototype requirement (D4).

## 21. Deferred implementation details

- Production key lifecycle, storage, and distribution.
- Exact manifest schema and retention-evidence representation (inside the signed manifest).
- Export audit event payload fields.
- Access-event vocabulary names.
- Configuration file paths and the demo-key generation mechanism. The configuration format and validation, and the environment-variable names, are decided in ADR-0008 (D3).
- Tamper-actor database grants, limits, batch sizes, and cursor encoding. The tables, columns, application-role grants, advisory-lock key, and lock timeout are implemented in Phase 4 (ADR-0003, ADR-0009).

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
