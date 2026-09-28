# Requirements Baseline - Audit Log Service

## 1. Problem Statement

Build a service that records an append-only history of audit events and makes later modification, deletion, insertion, reordering, or unauthorized rewriting of stored records detectable.

The service shall allow authorized callers to:

- append audit events;
- query audit events;
- verify the integrity of the audit history;
- retain audit history according to defined retention rules;
- redact sensitive values while preserving integrity and auditability; and
- export all audit records matching a specified `actorId` or `resourceId` in a form that can be independently verified.

The system shall provide sufficient evidence for auditors and regulators to determine whether the recorded audit history has been altered.

## 2. Actors

| Actor | Primary Need |
|---|---|
| Writing service | Append audit events |
| Auditor | Query events, verify integrity, and obtain verifiable exports |
| Regulator | Audit access to client account data |
| Administrator | Perform authorized operational actions such as retention and redaction |

The exact authorization boundaries for these actors will be finalized during security and Scenario C design.

## 3. Initial Requirements Decisions

The following establish the behavioral baseline. Detailed technical mechanisms remain design decisions unless explicitly stated here.

| # | Requirement / Decision | Source | Rationale |
|---|---|---|---|
| 1 | The assignment's `timestamp` field shall be the optional, caller-supplied time at which the event occurred; if omitted, it is stored as null. The server always assigns the authoritative `recordedAt` recording time. | Assignment + Developer-derived | Keeps the assignment's field name while separating business occurrence time from authoritative recording time. |
| 2 | Timestamps shall be RFC 3339 date-times with an explicit timezone offset; values without an offset shall be rejected. Both `recordedAt` and the caller-supplied `timestamp` shall be normalized to UTC and represented at fixed microsecond precision; the caller's original offset is not retained. Timestamps with more than six fractional-second digits shall be rejected. Timestamps shall be immutable once recorded. | Developer-derived + Design decision | Avoids ambiguous local times and gives a single representation for storage, hashing, and responses. |
| 3 | Audit events shall contain `eventType`, `actorId`, `resourceType`, `resourceId`, `payload`, optional caller-supplied `timestamp`, and the server-assigned fields `id` (UUID), `sequence` (integer chain position), `recordedAt`, and `recordedBy` (the authenticated technical caller). Callers shall not supply server-assigned fields. | Assignment + Developer-derived | Uses the assignment's event terminology, gives each record a stable identifier and an explicit chain position, and distinguishes the business actor (`actorId`) from the technical caller (`recordedBy`). |
| 4 | `payload` shall be a JSON object conforming to the I-JSON profile (RFC 7493) used for canonical hashing; the resulting input restrictions are listed in FR-1. | Assignment + Developer-derived + Design decision | Supports structured querying, redaction, validation, and deterministic integrity processing. |
| 5 | The audit history shall have a defined logical ordering, and concurrent appends shall preserve that ordering without conflicting chain histories. `sequence` starts at 1, is contiguous, is never renumbered, and defines chain order (NFR-1). | Assignment + Developer-derived + Design decision | Required for a reliable append-only integrity model. |
| 6 | Each audit record shall contain `contentHash` (a hash of its own content), `previousHash` (a link to the preceding record), and `recordHash` (a hash binding the record to its chain position). The first record's `previousHash` is the genesis value: 64 lowercase hexadecimal zeros. Definitions are in NFR-1. | Assignment + Design decision | Establishes the hash-chain structure and its starting point, and keeps content integrity separate from chain-position integrity. |
| 7 | Integrity protection shall cover the immutable audit-event content and the chain/order metadata necessary to detect modification, deletion, insertion, reordering, and unauthorized rewriting. Exact hash coverage is defined in NFR-1. | Assignment + Developer-derived | The integrity guarantee must extend beyond simple field edits. |
| 8 | The integrity design shall address unauthorized tail truncation and complete historical rewriting. The approved direction is Ed25519-signed checkpoints stored outside the database (FR-4). | Developer-derived + Design decision | A plain public hash chain cannot detect these cases when an attacker with database write access can recompute subsequent hashes. |
| 9 | Retention processing shall not cause legitimate archived history to appear as unexplained integrity corruption. Retention shall preserve sufficient chain evidence for verification (FR-5). | Assignment + Developer-derived | Retention must coexist with meaningful verification. |
| 10 | Sensitive values within event payloads shall be capable of being redacted after recording. | Assignment | Sensitive information may need removal after ingestion. |
| 11 | Authorized redaction shall preserve audit-history verification, shall not rewrite the original record's integrity hashes, and shall itself be auditable. | Assignment + Developer-derived + Design decision | Privacy operations must not undermine the audit trail. |
| 12 | Audit records shall be exportable as all records matching a specified `actorId` or `resourceId`. | Assignment | Supports auditor and regulator investigations while preserving complete matching scope. |
| 13 | An exported audit bundle shall contain sufficient integrity evidence for the integrity of its records to be independently verified without trusting the live service. Completeness of the export selection is an attested claim, not something the hashes alone can prove (FR-7). | Developer-derived + Design decision | Provides evidence that can be validated outside the running service without overstating what it proves. |
| 14 | Duplicate-write idempotency is not required for the initial version. | Developer-derived | Keeps the initial implementation focused; duplicate events remain part of the audit history. |
| 15 | Full-history verification is required for the initial version. More advanced checkpoint/range verification may be considered during design if justified. | Assignment + Developer-derived | Establishes a correctness-first baseline. |
| 16 | A caller-supplied `timestamp` more than a configurable allowed skew (default 5 minutes) ahead of `recordedAt` shall be rejected. No lower bound is imposed. | Developer-derived | Catches clearly erroneous future times from writing services while accepting valid late-arriving historical events. |

## 4. Functional Requirements

### FR-1 — Append Audit Events

The service shall provide an API to append a new audit event.

A successful append shall return sufficient information for the caller to identify the recorded event and its integrity position. The response shall contain the full stored record, including `id` and `sequence`, and shall reference the record's location (`GET /audit/events/{id}`).

The server shall assign `recordedBy` from the authenticated caller. `recordedBy` shall be a stable, non-secret identifier of the calling service and is covered by `contentHash` (NFR-1). The authentication mechanism and exact `recordedBy` format are deferred to the security design.

Append requests shall be validated and bounded:

- `eventType` and `resourceType` shall match a documented pattern;
- `actorId` and `resourceId` shall have bounded lengths;
- `payload` shall be a JSON object with bounded size and nesting depth;
- the overall request size shall be bounded;
- duplicate JSON keys shall be rejected;
- strings shall not contain unpaired Unicode surrogates;
- numbers shall be finite, and integers shall be within ±(2^53−1); fractional and exponent notation are accepted and interpreted as IEEE-754 double values, as I-JSON specifies;
- strings shall not contain U+0000;
- timestamps shall not have more than six fractional-second digits; and
- unknown fields, including attempts to supply server-assigned fields, shall be rejected with `422`.

The surrogate, finite-number, and integer-range rules (with duplicate-key rejection) are required for deterministic canonical hashing. The U+0000 and microsecond-precision rules are required by PostgreSQL storage; rejecting rather than silently truncating timestamps is defensive validation. There are no numeric restrictions beyond the approved I-JSON/JCS profile and applicable storage constraints; fractional and exponent-form numbers are permitted.

Exact limits and patterns are implementation constraints documented with the API definition rather than in this baseline.

Concurrent appends shall be serialized so that the chain cannot fork (NFR-1).

The normal API shall not provide an operation for arbitrary modification or deletion of an existing audit event.

Authorized privacy or retention operations that change the representation of stored information shall follow explicitly defined integrity-preserving rules and shall not be treated as unauthorized tampering.

### FR-2 — Query Audit Events

The service shall provide an API for authorized users to query audit events.

Queries shall support filtering by:

- `actorId`;
- `eventType`;
- `resourceType`;
- `resourceId`; and
- time range (`from` / `to`).

Filters are independent and shall be combined with AND semantics. Resource identifiers are scoped by resource type; a `resourceId` filter used without `resourceType` matches that identifier across all resource types.

The time-range filter shall use only the authoritative server-recorded timestamp (`recordedAt`), not the caller-supplied `timestamp`. The range is half-open: `from <= recordedAt < to`.

The API shall support pagination for potentially large result sets using opaque cursor pagination:

- the default page size is 50 and the maximum is 200;
- a requested page size outside the allowed range shall be rejected with `422`; and
- no total result count is provided.

Results shall be returned in deterministic ascending chain `sequence` order. No client-controlled sort parameter is provided.

Unknown query parameters shall be rejected with `422`, because silently ignoring an unrecognized filter could return a broader result than the caller intended.

The service shall also provide `GET /audit/events/{id}` to retrieve a single audit record by its identifier.

Whether and how archived or redacted records appear in query results is deferred to the retention and redaction design. `sequence` assignment under concurrent appends is defined in NFR-1.

### FR-3 — Verify Audit History

The service shall provide:

`GET /audit/verify`

The verification endpoint shall require authentication and authorization.

A verification request that executes successfully shall return `200`, with the verification result in the response body whether the chain is intact or broken. A detected integrity violation is a verification result, not an HTTP error.

The verification response shall provide:

1. whether the audit chain is intact; and
2. if the chain is not intact, the first detected inconsistency and its violation type.

Verification behavior (design decision):

- verification scans the complete chain in `sequence` order against a consistent database snapshot;
- verification starts at `sequence` 1 using the genesis value, or at an authenticated retention boundary (mechanism deferred to Focused Discussion #3);
- verification continues after the first violation, counting at most one violation per record, and reports the first violation and the total count; a complete list of violations is not returned in v1.

The v1 verification response shall contain:

| Field | Content |
|---|---|
| `intact` | `true` when `violationCount` is 0 |
| `scheme` | Integrity scheme identifier (`audit-log/v1`) |
| `verifiedAt` | Time of verification |
| `recordsChecked` | Number of records checked |
| `head` | `sequence` and `recordHash` of the verified chain head; `null` for an empty chain |
| `anchor` | Checkpoint `status` and `sequence`; `NONE` when no checkpoint exists. Statuses specific to the checkpoint lifecycle are deferred with FR-4. |
| `violationCount` | Number of records with a violation |
| `firstViolation` | `type`, `sequence`, `recordId`, and a fixed message; `null` when intact |

Core violation types: `GENESIS_MISMATCH`, `SEQUENCE_GAP`, `SEQUENCE_DUPLICATE`, `CONTENT_HASH_MISMATCH`, `PAYLOAD_VALUE_MISMATCH`, `RECORD_HASH_MISMATCH`, `PREVIOUS_HASH_MISMATCH`, `RECORDED_AT_REGRESSION`, `ANCHOR_MISMATCH`, and `CHAIN_TRUNCATED`. Violation types for missing payload values and retention boundaries are deferred to Focused Discussion #3.

Violation messages shall be fixed per violation type and shall not be derived from record data. The response may expose sequence numbers, record identifiers, violation types, head information, and anchor information. It shall not expose payload values, payload keys, `actorId`, `resourceId`, or `recordedBy`.

Verification shall detect, where applicable:

- modified event content;
- broken hash links;
- missing records;
- unexpected insertion or reordering;
- invalid integrity evidence;
- unauthorized tail truncation, relative to the latest checkpoint; and
- unauthorized historical rewriting within the documented threat model.

Legitimate archived and redacted records shall not be reported as integrity violations solely because they have undergone an authorized retention or redaction operation.

### FR-4 — Integrity Anchoring / Checkpoints

The solution shall provide a mechanism that addresses detection of unauthorized rewriting of the complete historical chain and of tail truncation.

Approved direction (design decision): Ed25519-signed checkpoints of the chain head, stored outside the audit database. A plain public hash chain cannot provide this, because an attacker with database write access can recompute every subsequent hash or remove the newest records.

Threat model: the attacker may have write access to the audit database, but not to the checkpoint signing key or the checkpoint store. Within this model, rewriting or truncating records up to the latest checkpoint is detectable.

Limitation: records appended after the latest checkpoint can be rewritten, fabricated, or truncated without detection by such an attacker. The size of this window depends on checkpoint timing.

Per-record signatures are not used.

Checkpoint lifecycle and timing, checkpoint format, storage mechanics, and key-management details remain deferred.

### FR-5 — Retention

The service shall support retention processing according to a configurable retention policy.

The retention window shall be evaluated using the authoritative server-recorded timestamp (`recordedAt`).

Retention processing shall:

- identify records eligible for retention processing;
- preserve the integrity semantics of the audit history;
- make retained/archived state distinguishable from active records; and
- allow verification to remain meaningful after retention processing.

Integrity principles (design decision):

- retention shall preserve sufficient chain evidence for verification to continue;
- intentional archival or removal shall be distinguishable from unexplained tampering;
- `sequence` is never renumbered, and genesis applies only to `sequence` 1; and
- if the oldest records are removed, verification may begin from an authenticated retention boundary.

The retention model, the boundary mechanism, the archive representation, and the datastore implementation are deferred to Focused Discussion #3.

### FR-6 — Redaction

An authorized administrator shall be able to request redaction of specified sensitive fields within an audit event.

A redaction shall:

- remove or replace the sensitive value according to the final integrity-preserving design;
- preserve verification of the audit history;
- record the redaction reason; and
- produce an auditable record of the redaction operation.

Redaction is an authorized privacy operation and shall be distinguished from unauthorized tampering.

The final engineering documentation shall describe the selected redaction approach, its trade-offs, and its limitations.

Integrity model (design decision):

- each payload value has a salted commitment, and `contentHash` covers the payload structure with each value replaced by its commitment;
- salts shall be generated by a cryptographically secure random generator and be at least 128 bits;
- redaction deletes the value together with its salt and leaves the commitment in place;
- the original `contentHash` is never rewritten, and remaining values stay independently verifiable against their commitments;
- raw payload values shall not be stored in the immutable audit-record representation; and
- redaction scope is the payload only; `actorId` and `resourceId` are not redaction targets.

Known limitation: payload keys and structure (such as array lengths) remain visible after redaction.

The redaction API, authorization, separation of duties, reason field, response representation, and storage tables are deferred to Focused Discussion #3.

### FR-7 — Export

The service shall support exporting **all audit records matching**:

- a specified `actorId`; or
- a specified `resourceId`.

An export shall include sufficient integrity information to establish that the included records belong to the expected audit history.

The exported bundle shall be independently verifiable without requiring the recipient to trust the live service.

The export shall distinguish between:

- cryptographic integrity of the exported records, which a recipient can verify independently by recomputing their hashes and commitments; and
- completeness of the export selection, which is an attested claim by the service and cannot be proven by the hashes alone.

The export bundle format, provenance evidence, and completeness attestation mechanism are deferred to Focused Discussion #3.

### FR-8 — Regulatory Access Audit / Scenario C

The system shall support regulatory auditing of access to client account data.

The provided requirement is intentionally under-specified and shall be clarified before finalizing the Scenario C implementation scope.

The developer's initial clarification questions are listed in Section 8. These questions are intended for requirements brainstorming and Claude-assisted challenge; they are not treated as answered stakeholder requirements.

No specific interpretation of "access" shall be treated as finalized until the Scenario C clarification process is completed.

## 5. Non-Functional Requirements

### NFR-1 — Integrity

Append-only and tamper-evident behavior shall not depend solely on application-level API behavior.

The final implementation shall include appropriate datastore-level protections against unauthorized modification or deletion.

This is a developer-derived engineering control supporting the assignment's integrity objective. Database roles, privileges, and the privileged path for tampering demonstrations are deferred to the security design.

#### Integrity design

The following were approved in Focused Discussion #2. Each item is marked as an engineering convention or a design decision.

**Hash structure and coverage (design decision):**

- `contentHash` covers the event content: `id`, `eventType`, `actorId`, `resourceType`, `resourceId`, `timestamp` (an explicit null when absent), `recordedAt`, `recordedBy`, and the payload commitments (FR-6).
- `recordHash` covers `sequence`, `previousHash`, and `contentHash`.
- `previousHash` is the `recordHash` of the record at `sequence − 1`, or the genesis value for `sequence` 1.
- Content integrity is kept separate from chain-position integrity. No hash covers itself or any state that can legitimately change after recording, such as archive or redaction status.

**Canonicalization and hashing:**

- Records are canonicalized with RFC 8785 (JSON Canonicalization Scheme) over I-JSON (RFC 7493) input. *(Engineering convention)*
- A maintained RFC 8785 library shall be used, subject to an implementation adoption check covering maintenance status, license, and conformance with the RFC 8785 test vectors. If no maintained library can be adopted without violating the approved canonicalization requirements, including the FR-1 numeric profile, implementation shall stop for developer review and a new explicit decision. *(Design decision)*
- The hash algorithm is SHA-256, represented as lowercase hexadecimal. *(Engineering convention)*
- Every hash input begins with a distinct, versioned domain label under the `audit-log/v1` scheme, and the scheme identifier is reported in verification output. *(Design decision)*

**Sequence and genesis (design decision):**

- `sequence` starts at 1, is contiguous, is never renumbered, and defines chain order.
- The genesis value is 64 lowercase hexadecimal zeros and applies only to `sequence` 1.
- No chain identifier is used.

**Append concurrency (design decision):**

- Appends are serialized with a PostgreSQL transaction-scoped advisory lock at READ COMMITTED isolation. The chain head is read after the lock is acquired.
- `recordedAt` is taken from the database clock after locking, and clamped so it never goes backwards.
- A lock timeout bounds waiting. The server does not retry failed appends automatically.
- `UNIQUE(sequence)` is required. `UNIQUE(previous_hash)` is defense in depth against a permanent fork.
- There is no foreign key from `previous_hash` to `record_hash`, because retention can remove older records.
- The exact lock key and timeout values are implementation details.

**Storage separation (design decision):** raw payload values are stored outside the immutable audit-record representation so that redaction can remove them without modifying the immutable record. The exact tables are deferred to Focused Discussion #3.

### NFR-2 — Security

The implementation shall follow least-privilege principles.

At minimum:

- application credentials shall have only the database privileges required by the application;
- privileged operational actions shall require appropriate authorization;
- secrets and cryptographic private keys shall not be committed to source control;
- sensitive values shall not unnecessarily appear in application logs;
- error responses, including validation errors, shall not echo submitted input or payload values;
- potentially identifying query-string values (such as `actorId` and `resourceId`) shall not be written to operational logs; and
- dependency and security checks shall be included in the quality process where practical.

Authorization controls are developer-derived engineering requirements supporting the assignment's security and Scenario C objectives.

The exact authentication and authorization mechanism shall be finalized during security design.

### NFR-3 — Performance

The implementation shall be evaluated for:

- append performance;
- query performance;
- pagination behavior;
- full-chain verification;
- retention processing;
- redaction operations; and
- export generation.

Performance results shall be measured and documented for the implemented prototype.

Production-scale throughput and history-size targets remain an open question.

### NFR-4 — Operability

The service shall be runnable locally without requiring cloud infrastructure.

The development environment shall provide a straightforward way to start the required application and datastore components.

### NFR-5 — Observability

The service shall provide sufficient operational visibility for development and troubleshooting.

This should include, where appropriate:

- structured application logs;
- request/correlation identifiers;
- health information; and
- readiness information.

Sensitive audit payload values shall not be unnecessarily written to operational logs.

### NFR-6 — Quality

The implementation shall include quality gates covering, as appropriate:

- static analysis/linting;
- unit tests;
- integration tests against the real datastore;
- API-level tests;
- property or invariant testing where valuable;
- concurrency testing;
- security and authorization testing;
- performance validation; and
- manual validation of the required demonstration scenarios.

Coverage shall be meaningful and risk-based rather than treated as the sole measure of test quality.

### NFR-7 — API Contract Conventions

The API shall follow established HTTP/REST conventions. These are engineering conventions adopted by the developer, not assignment requirements or new functional behavior:

- REST-style resource naming under `/audit`, retaining the assignment-defined `/audit/verify` path;
- standard HTTP methods and status codes; update and delete methods are not provided for audit records;
- `201 Created` with a `Location` header for a successful append;
- RFC 9457 Problem Details (`application/problem+json`) for all error responses, including a request identifier where appropriate;
- camelCase JSON field and query-parameter names, consistent with the assignment's field names;
- consistent request and response schemas; and
- OpenAPI documentation as the API and schema definition.

`POST` requests are not idempotent: because duplicate-write idempotency is not required (§3 #14), a client retry may record a duplicate event.

## 6. Assumptions

1. The initial implementation uses a single logical audit history rather than multiple independent tenant chains.
2. Horizontal write scaling and cross-region replication are outside the initial implementation scope.
3. A production deployment would use an appropriate managed identity and secret/key-management solution; local development may use controlled development credentials.
4. Audit event payloads contain JSON-safe structured data.
5. Production authentication and authorization would integrate with an organizational identity provider or equivalent mechanism.
6. The initial implementation does not provide client-side idempotency keys for retry deduplication.
7. The final implementation will document prototype limitations where behavior is intentionally narrower than a production deployment.
8. Authenticated writing services are trusted to assert the business `actorId`; the server-assigned `recordedBy` records which technical caller submitted each event.
9. For integrity anchoring, an attacker may have write access to the audit database but not to the checkpoint signing key or the checkpoint store. In the prototype, the checkpoint store stands in for an external witness.

## 7. Out of Scope

The following are outside the initial implementation scope:

- User interface;
- multi-tenant audit chains;
- cross-region replication;
- horizontal write scaling;
- production cloud deployment;
- infrastructure-as-code deployment;
- client-side idempotency keys;
- integration with a production identity provider;
- production key-management infrastructure;
- external regulatory timestamping infrastructure;
- per-record digital signatures (signed checkpoints are used instead); and
- production-specific regulatory retention rules until the applicable regulation is identified.

Design considerations for these areas may be documented where they materially affect the prototype architecture.

## 8. Scenario C — Initial Clarification Questions

The following are the developer's initial questions for brainstorming and requirements clarification. They are not finalized answers.

1. Which regulation, regulatory body, or compliance framework applies?

2. What exactly constitutes "access" to client account data?

3. Does access include:
   - reads;
   - writes;
   - updates;
   - deletes;
   - exports; and/or
   - other operations?

4. Are denied access attempts required to be recorded, or only successful access?

5. What is the relevant identity:
   - authenticated user;
   - service account;
   - application;
   - business actor; or
   - another principal?

6. Does system-to-system access to client account data need to be audited?

7. Must regulators' or auditors' own access to the audit system also be recorded?

8. What specifically qualifies as "client account data"?

9. What evidence must be captured for each access event?

10. What retention period and deletion/redaction requirements apply?

11. Who is authorized to perform redaction?

12. Does redaction require a second approver or separation of duties?

13. What production throughput and historical data volume must the system support?

Because stakeholder answers are not expected to be available during the assessment, the final Scenario C requirement will be resolved through:

1. documented requirements brainstorming;
2. Claude-assisted challenge and identification of missing considerations;
3. explicit developer assumptions where clarification cannot be obtained;
4. a documented clarified requirement statement; and
5. an explicit implementation scope and scope-out list.

## 9. Assignment Acceptance Scenarios

### Scenario A — Core Audit Flow

The implementation shall demonstrate the following sequence:

1. Write multiple audit events, including records at different positions in the chain.
2. Query the events.
3. Verify the audit chain and demonstrate that it is intact.
4. Directly modify or otherwise tamper with a stored audit record in the datastore, outside the normal application API.
5. Run verification again.
6. Demonstrate that the integrity violation is detected.

### Scenario B — Retention, Redaction, and Export

The implementation shall demonstrate:

- retention processing without invalidating legitimate integrity verification;
- authorized redaction while preserving integrity and auditability; and
- export of all records matching an `actorId` or `resourceId` with independent verification evidence.

### Scenario C — Regulatory Access

The implementation shall demonstrate the clarified interpretation of regulatory access to client account data, including:

- the documented requirement clarification;
- explicit assumptions where stakeholder clarification is unavailable;
- the resulting implementation scope;
- authorization boundaries;
- captured audit evidence; and
- explicit scope-outs or limitations.

## 10. Initial Risks

| Risk | Potential Impact | Initial Mitigation / Follow-up |
|---|---|---|
| Ambiguous Scenario C access semantics | Incorrect regulatory audit behavior | Resolve through documented brainstorming, assumptions, and a clarified requirement statement |
| Simple hash chains may not detect complete rewrites | False confidence in historical integrity | Ed25519-signed checkpoints stored outside the database (FR-4) |
| Records appended after the latest checkpoint can be rewritten, fabricated, or truncated by an attacker with database write access | Undetected tampering within the unanchored window | Document the limitation; checkpoint timing (deferred) determines the window size |
| Checkpoint signing key compromise | Forged checkpoints undermine rewrite and truncation detection | Keep the key out of the database and source control; key-management details deferred |
| Concurrent appends may create ordering or chain-integrity problems | Corrupted or inconsistent audit history | Advisory-lock serialized appends with `UNIQUE(sequence)` and `UNIQUE(previous_hash)` (NFR-1), plus concurrency tests |
| Canonicalization differs between the service and an independent verifier | False tamper reports, or exports that cannot be verified | RFC 8785 over I-JSON input, FR-1 input restrictions, RFC test vectors, and storage round-trip tests |
| No maintained RFC 8785 library passes the adoption check | Canonicalization cannot be implemented as approved | Stop implementation for developer review and a new explicit decision |
| Retention may conflict with verification | Legitimate archival could appear as tampering | Design retention and verification together; verification may start from an authenticated boundary |
| Redaction may conflict with immutability | Sensitive data removal could invalidate integrity | Salted per-value commitments keep `contentHash` stable (FR-6) |
| Payload keys and structure remain visible after redaction | Limited metadata disclosure | Document as a known limitation |
| Export may omit necessary integrity evidence | Recipients cannot independently verify evidence | Define export provenance, completeness, and verification rules |
| Privileged database access may bypass application controls | Unauthorized modification of audit records | Enforce least privilege and test direct datastore tampering |
| Prototype security assumptions may differ from production | Production deployment may require additional controls | Explicitly document authentication, key management, scaling, and deployment limitations |
| No external timestamping authority in prototype | Complete rewrite detection may depend on the chosen trust boundary | Explicitly document attacker model, trust assumptions, and limitations |
| A writing service can assert an arbitrary `actorId` | Misleading audit evidence about who caused an event | Record the authenticated technical caller in server-assigned `recordedBy` |

## 11. Traceability

The implementation shall maintain traceability between:

1. the requirements baseline;
2. architectural and security decisions;
3. implementation tasks;
4. automated and manual validation;
5. Scenario A, B, and C demonstrations;
6. material AI-assisted development activities; and
7. final engineering conclusions, limitations, and trade-offs.

Material AI-assisted work shall remain traceable through the project's AI usage log.

Developer decisions, approvals, validation results, and final acceptance remain the responsibility of the developer.

## 12. Requirements-to-Validation Summary

| Area | Required Evidence |
|---|---|
| Append-only audit history | Successful append tests and direct datastore tampering demonstration |
| Query | API tests covering combined filters, half-open time ranges, cursor pagination, page-size bounds, ascending sequence order, and rejection of unknown parameters |
| API contract | API tests covering input validation (including the FR-1 canonicalization and storage restrictions), unknown-field rejection, Problem Details error format, absence of echoed input values, and status codes |
| Canonicalization | RFC 8785 test vectors, deterministic output tests, and property tests showing hashes survive the datastore round trip |
| Hash-chain integrity | Unit/integration/property tests showing that each covered field affects the correct hash, plus genesis and chain-link verification scenarios |
| Concurrent writes | Concurrency tests showing that parallel appends produce contiguous sequences and an intact chain, and that the database constraints reject a forced fork |
| Rewrite/tamper detection | Controlled datastore modification and verification demonstration covering modification, middle deletion, insertion, reordering, tail truncation, and full rewrite (the last two against a signed checkpoint) |
| Verification | Tests of the v1 response fields, violation types, `violationCount`, empty-chain behavior, and absence of payload values, payload keys, `actorId`, `resourceId`, and `recordedBy` |
| Retention | Retention execution plus post-retention verification |
| Redaction | Redaction execution plus integrity and auditability verification, showing that `contentHash` is unchanged, remaining values verify against their commitments, and the redacted value and salt are removed |
| Export | Export generation plus standalone verification |
| Scenario C | Clarified interpretation, documented scope, implementation evidence, and explicit scope-outs |
| Security | Authorization/privilege tests and security review |
| Quality | Linting, automated tests, integration validation, and performance measurements |
| Documentation | Setup, architecture, scenarios, assumptions, limitations, trade-offs, and engineering summary |
| AI-assisted development | Meaningful AI usage and decision traceability with developer sign-off |

## 13. Requirement Baseline Status

This document represents the **developer-authored draft requirements baseline** established before substantive AI-assisted design and implementation.

The `Source` classifications distinguish assignment-required behavior (`Assignment`), developer-derived engineering requirements (`Developer-derived`), and technical design decisions approved in focused engineering discussions (`Design decision`). Established engineering conventions are identified where they are used (NFR-1, NFR-7).

Requirements requiring technical design decisions are intentionally not finalized here. Those decisions will be evaluated through focused engineering analysis, with the developer retaining final responsibility for acceptance or rejection.

Event model and API contract decisions (Focused Discussion #1) and integrity decisions (Focused Discussion #2) have been incorporated. The following remain open:

- Focused Discussion #3: retention model and boundary mechanism; redaction API, authorization, separation of duties, reason field, response representation, and storage tables; export bundle format and completeness attestation; visibility of archived and redacted records; and export pairing of `resourceType` and `resourceId`.
- Security design: authentication mechanism, `recordedBy` format, database roles and privileges, and the privileged path for tampering demonstrations.
- Checkpoint design: lifecycle and timing, format, storage mechanics, and key management.
- Implementation: selection of the canonicalization library, subject to the adoption check.

Scenario C remains intentionally open until its business meaning and implementation boundary are clarified through the documented requirements-brainstorming process.
