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
| 1 | Each audit event shall have a server-recorded `recordedAt` timestamp. The assignment's `timestamp` field is represented by the optional caller-supplied `occurredAt`; the server always assigns the authoritative `recordedAt`. | Assignment + Developer-derived | Separates business occurrence time from authoritative recording time. |
| 2 | Timestamps shall use an unambiguous UTC representation and shall be immutable once recorded. | Developer-derived | Provides consistent querying, retention, and integrity behavior. |
| 3 | Audit events shall contain `eventType`, `actorId`, `resourceType`, `resourceId`, `payload`, optional `occurredAt`, and server-assigned `recordedAt`. | Assignment + Developer-derived | Uses the assignment's event terminology and provides a predictable audit contract. |
| 4 | `payload` shall contain structured JSON data. | Developer-derived | Supports structured querying, redaction, validation, and deterministic integrity processing. |
| 5 | The audit history shall have a defined logical ordering, and concurrent appends shall preserve that ordering without conflicting chain histories. | Assignment + Developer-derived | Required for a reliable append-only integrity model. |
| 6 | Each audit record shall contain its own content/integrity hash, a link to the preceding record, and a defined genesis value for the first record. | Assignment | Establishes the hash-chain structure and its starting point. |
| 7 | Integrity protection shall cover the immutable audit-event content and the chain/order metadata necessary to detect modification, deletion, insertion, reordering, and unauthorized rewriting. | Assignment + Developer-derived | The integrity guarantee must extend beyond simple field edits. |
| 8 | The integrity design shall address unauthorized tail truncation and complete historical rewriting. | Developer-derived | A basic hash chain alone may not detect these cases when an attacker can rewrite subsequent hashes. |
| 9 | Retention processing shall not cause legitimate archived history to appear as unexplained integrity corruption. | Assignment + Developer-derived | Retention must coexist with meaningful verification. |
| 10 | Sensitive values within event payloads shall be capable of being redacted after recording. | Assignment | Sensitive information may need removal after ingestion. |
| 11 | Authorized redaction shall preserve audit-history verification and shall itself be auditable. | Assignment + Developer-derived | Privacy operations must not undermine the audit trail. |
| 12 | Audit records shall be exportable as all records matching a specified `actorId` or `resourceId`. | Assignment | Supports auditor and regulator investigations while preserving complete matching scope. |
| 13 | An exported audit bundle shall contain sufficient integrity evidence to be independently verified without trusting the live service. | Developer-derived | Provides evidence that can be validated outside the running service. |
| 14 | Duplicate-write idempotency is not required for the initial version. | Developer-derived | Keeps the initial implementation focused; duplicate events remain part of the audit history. |
| 15 | Full-history verification is required for the initial version. More advanced checkpoint/range verification may be considered during design if justified. | Assignment + Developer-derived | Establishes a correctness-first baseline. |

## 4. Functional Requirements

### FR-1 — Append Audit Events

The service shall provide an API to append a new audit event.

A successful append shall return sufficient information for the caller to identify the recorded event and its integrity position.

The normal API shall not provide an operation for arbitrary modification or deletion of an existing audit event.

Authorized privacy or retention operations that change the representation of stored information shall follow explicitly defined integrity-preserving rules and shall not be treated as unauthorized tampering.

### FR-2 — Query Audit Events

The service shall provide an API for authorized users to query audit events.

Queries shall support filtering by:

- `actorId`;
- `eventType`;
- `resourceType`;
- `resourceId`; and
- time range.

The time-range filter shall use the authoritative server-recorded timestamp (`recordedAt`).

The API shall support pagination for potentially large result sets.

The pagination mechanism shall be selected during architecture design based on consistency and performance requirements.

### FR-3 — Verify Audit History

The service shall provide:

`GET /audit/verify`

The verification response shall provide:

1. whether the audit chain is intact; and
2. if the chain is not intact, the first detected inconsistency and its violation type.

Verification shall detect, where applicable:

- modified event content;
- broken hash links;
- missing records;
- unexpected insertion or reordering;
- invalid integrity evidence;
- unauthorized tail truncation; and
- unauthorized historical rewriting within the documented threat model.

Legitimate archived and redacted records shall not be reported as integrity violations solely because they have undergone an authorized retention or redaction operation.

Verification shall not expose sensitive payload values unnecessarily.

### FR-4 — Integrity Anchoring / Checkpoints

The solution shall provide a mechanism that addresses detection of unauthorized rewriting of the complete historical chain.

The exact checkpoint, signing, anchoring, key-management, and external-evidence mechanisms shall be finalized during architecture and cryptographic design.

The threat model shall explicitly identify the attacker capabilities this mechanism is intended to address.

### FR-5 — Retention

The service shall support retention processing according to a configurable retention policy.

The retention window shall be evaluated using the authoritative server-recorded timestamp (`recordedAt`).

Retention processing shall:

- identify records eligible for retention processing;
- preserve the integrity semantics of the audit history;
- make retained/archived state distinguishable from active records; and
- allow verification to remain meaningful after retention processing.

The exact archive representation and datastore implementation shall be finalized during design.

### FR-6 — Redaction

An authorized administrator shall be able to request redaction of specified sensitive fields within an audit event.

A redaction shall:

- remove or replace the sensitive value according to the final integrity-preserving design;
- preserve verification of the audit history;
- record the redaction reason; and
- produce an auditable record of the redaction operation.

Redaction is an authorized privacy operation and shall be distinguished from unauthorized tampering.

The final engineering documentation shall describe the selected redaction approach, its trade-offs, and its limitations.

The exact cryptographic commitment/redaction mechanism shall be finalized during the integrity and privacy design review.

### FR-7 — Export

The service shall support exporting **all audit records matching**:

- a specified `actorId`; or
- a specified `resourceId`.

An export shall include sufficient integrity information to establish that the included records belong to the expected audit history.

The exported bundle shall be independently verifiable without requiring the recipient to trust the live service.

The exact export format, signing mechanism, provenance evidence, and completeness checks shall be finalized during design.

### FR-8 — Regulatory Access Audit / Scenario C

The system shall support regulatory auditing of access to client account data.

The provided requirement is intentionally under-specified and shall be clarified before finalizing the Scenario C implementation scope.

The developer's initial clarification questions are listed in Section 8. These questions are intended for requirements brainstorming and Claude-assisted challenge; they are not treated as answered stakeholder requirements.

No specific interpretation of "access" shall be treated as finalized until the Scenario C clarification process is completed.

## 5. Non-Functional Requirements

### NFR-1 — Integrity

Append-only and tamper-evident behavior shall not depend solely on application-level API behavior.

The final implementation shall include appropriate datastore-level protections against unauthorized modification or deletion.

This is a developer-derived engineering control supporting the assignment's integrity objective.

### NFR-2 — Security

The implementation shall follow least-privilege principles.

At minimum:

- application credentials shall have only the database privileges required by the application;
- privileged operational actions shall require appropriate authorization;
- secrets and cryptographic private keys shall not be committed to source control;
- sensitive values shall not unnecessarily appear in application logs; and
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

## 6. Assumptions

1. The initial implementation uses a single logical audit history rather than multiple independent tenant chains.
2. Horizontal write scaling and cross-region replication are outside the initial implementation scope.
3. A production deployment would use an appropriate managed identity and secret/key-management solution; local development may use controlled development credentials.
4. Audit event payloads contain JSON-safe structured data.
5. Production authentication and authorization would integrate with an organizational identity provider or equivalent mechanism.
6. The initial implementation does not provide client-side idempotency keys for retry deduplication.
7. The final implementation will document prototype limitations where behavior is intentionally narrower than a production deployment.

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
- external regulatory timestamping infrastructure; and
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
| Simple hash chains may not detect complete rewrites | False confidence in historical integrity | Perform explicit cryptographic/integrity design review |
| Concurrent appends may create ordering or chain-integrity problems | Corrupted or inconsistent audit history | Define and test a serialized append strategy |
| Retention may conflict with verification | Legitimate archival could appear as tampering | Design retention and verification together |
| Redaction may conflict with immutability | Sensitive data removal could invalidate integrity | Define integrity-preserving redaction semantics before implementation |
| Export may omit necessary integrity evidence | Recipients cannot independently verify evidence | Define export provenance, completeness, and verification rules |
| Privileged database access may bypass application controls | Unauthorized modification of audit records | Enforce least privilege and test direct datastore tampering |
| Prototype security assumptions may differ from production | Production deployment may require additional controls | Explicitly document authentication, key management, scaling, and deployment limitations |
| No external timestamping authority in prototype | Complete rewrite detection may depend on the chosen trust boundary | Explicitly document attacker model, trust assumptions, and limitations |

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
| Query | API tests covering filters and pagination |
| Hash-chain integrity | Unit/integration/property tests and verification scenarios |
| Concurrent writes | Concurrency tests demonstrating a consistent chain |
| Rewrite/tamper detection | Controlled datastore modification and verification demonstration |
| Retention | Retention execution plus post-retention verification |
| Redaction | Redaction execution plus integrity and auditability verification |
| Export | Export generation plus standalone verification |
| Scenario C | Clarified interpretation, documented scope, implementation evidence, and explicit scope-outs |
| Security | Authorization/privilege tests and security review |
| Quality | Linting, automated tests, integration validation, and performance measurements |
| Documentation | Setup, architecture, scenarios, assumptions, limitations, trade-offs, and engineering summary |
| AI-assisted development | Meaningful AI usage and decision traceability with developer sign-off |

## 13. Requirement Baseline Status

This document represents the **developer-authored draft requirements baseline** established before substantive AI-assisted design and implementation.

The `Source` classifications distinguish assignment-required behavior from developer-derived engineering requirements.

Requirements requiring technical design decisions are intentionally not finalized here. Those decisions will be evaluated through focused engineering analysis, with the developer retaining final responsibility for acceptance or rejection.

Scenario C remains intentionally open until its business meaning and implementation boundary are clarified through the documented requirements-brainstorming process.
