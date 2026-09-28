# AI Usage Log

This log records how I used AI on this project: what I asked, what I accepted, modified or rejected, and why.
I own every decision and every line of code in this repository.

## Tool

**Claude Code** (Claude Opus 5.5), used for understanding the brief, requirements, planning, design,
implementation, tests, debugging and documentation. All AI-drafted material is reviewed and rewritten by me
before it's committed.

## Rules

1. No secrets or real personal data in prompts.
2. I review every diff before accepting it.
3. Hashing, verification, redaction, auth and schema changes need my explicit sign-off.
4. I make all commits myself, under my own Git identity.
5. All AI-assisted changes must pass lint, type checks, tests and security scans.

## Entries

### 2026-09-28 — Requirements review and Event Model / API contract decisions

**Date/Time:** 2026-09-28, 08:00–08:44 UTC (from session timestamps: requirements review requested at 08:00;
decisions and requirements update plan approved at 08:44).

**Activity:** Requirements analysis and API-contract design (documentation only).

**What I asked:** I asked Claude to review `docs/requirements.md` against the assignment and report gaps,
ambiguities, technical risks and Scenario C clarification points without changing any files. I then asked for
a focused discussion of the event model and API contract, covering HTTP/REST conventions, with options,
trade-offs and a recommendation for each consequential decision.

**What the AI produced:**

- A requirements review grouped into gaps, ambiguities, design risks, Scenario C points, items clear enough to
  proceed, and recommended discussion checkpoints. Key findings: the hash format must account for redaction
  before Scenario A code is written; export completeness cannot be proven by a hash chain alone; datastore-level
  append-only protection conflicts with retention, redaction and the tamper demonstration; tail-truncation and
  full-rewrite detection need a trust anchor outside the database; Scenario C has several distinct readings.
- An event model and API contract analysis with eleven decisions (D1–D11), each tagged by source (assignment,
  existing requirement, API convention, or new decision) and with a recommendation.
- A proposed update plan for `docs/requirements.md`, listing changed sections and deferred items.

**What I decided:**

- Accepted D1–D9 and D11 as recommended: `timestamp` as the optional caller-supplied occurrence time (null when
  omitted) alongside server-assigned `recordedAt`; `from`/`to` filter on `recordedAt` only; future-skew
  rejection (configurable, default 5 minutes, no lower bound); independent AND-combined filters with resource
  IDs scoped by type; opaque cursor pagination (default 50, max 200, out-of-range rejected, no total count);
  fixed ascending `sequence` order; server-assigned `recordedBy` for the authenticated caller; rejection of
  unknown body fields and query parameters; UUID `id` plus integer `sequence`; RFC 9457 error responses without
  echoed input values; authenticated `/audit/verify` returning 200 for both intact and broken chains.
- Modified D10: kept the principle of bounded, validated input but left exact numeric limits and patterns out of
  the requirements baseline as implementation constraints.
- Confirmed the half-open time range and `GET /audit/events/{id}` as the target of the `Location` header.
- Deferred to later discussions rather than decided here: storage representation of the caller-supplied
  `timestamp`; whether `recordedBy` is hashed; the verification response structure (integrity); `sequence`
  assignment (concurrency); authentication mechanism and `recordedBy` format (security); visibility of archived
  and redacted records and export pairing (retention/redaction/export).
- Required that API conventions stay distinguished from assignment and developer functional requirements;
  they are recorded separately in NFR-7.

**Rationale:**

- Accepted decisions: the recommendations kept the assignment's terminology (`timestamp`), made time filtering
  and ordering depend only on server-controlled values (`recordedAt`, `sequence`), gave stable pagination under
  concurrent appends, separated the business actor from the authenticated caller, and prevented sensitive input
  from being echoed in errors. Unknown query parameters are rejected because silently ignoring an unrecognized
  audit filter could return a broader result than intended.
- D10 modification: exact numeric limits and patterns are engineering constraints to be finalized during
  implementation/design, not requirements; including them would overload the baseline.
- Deferrals: each deferred item depends on a design discussion that has not yet taken place (integrity,
  concurrency, security, retention/redaction/export), so deciding it here would pre-empt that discussion.
- API conventions are kept in NFR-7 so they are not mistaken for assignment requirements or new functional
  behavior.

**Result:** `docs/requirements.md`: §3 rows 1–3 revised and row 16 added; FR-1, FR-2 and FR-3 extended; NFR-2
extended; NFR-7 (API Contract Conventions) added; assumption 8, one risk row and the query and API-contract
validation rows added. The event model and API contract are now decision-ready for implementation, with the
deferred items listed above recorded as open in the requirements baseline.

**Validation:** No application code was changed, so no tests or quality checks apply. Validation at this stage
is my review of the requirements diff for consistency with the assignment and the decisions above.

**Sign-off:** I approved D1–D9 and D11 as recommended, D10 as modified, the half-open time range,
`GET /audit/events/{id}`, the `timestamp` deferral and the requirements update plan on 2026-09-28 at 08:44 UTC.

### 2026-09-28 — Focused Discussion 2: integrity, cryptographic design and trust model

**Date/Time:** 2026-09-28, 09:27–09:49 UTC (from session timestamps: discussion requested at 09:27; revised analysis
requested at 09:41; decisions approved at 09:49).

**Activity:** Integrity and cryptographic design discussion (documentation only), followed by explicit developer
approval.

**What I asked:** I asked Claude to analyze hash input, canonicalization, the hash algorithm, chain semantics,
append concurrency, verification, the trust model, and the integrity implications of retention, redaction and
export, giving options and recommendations without deciding for me. After reviewing that, I asked Claude to
revisit six areas: hash coverage, canonicalization, sequence/genesis, concurrency, verification and redaction.

**What the AI produced:**

- An initial analysis (I1–I12). Key findings: a plain public hash chain cannot detect a full rewrite, tail
  truncation or forged appends by an attacker with database write access; salted per-value commitments keep
  `contentHash` stable under redaction, while an unsalted hash would let short redacted values be recovered by
  brute force; export integrity can be proven but completeness can only be attested.
- A revised analysis that:
  - corrected its earlier classification of "stop at first violation" as an assignment requirement (the
    assignment requires reporting the first violation, not stopping);
  - resolved an inconsistency about record identifiers in the verify response;
  - classified each proposed input restriction as required for hashing, required by PostgreSQL, defensive, or
    unnecessary;
  - found that an exclusive table lock would require UPDATE/DELETE/TRUNCATE privileges that conflict with
    append-only permissions.

**What I decided:**

- Accepted as recommended: I1 (three-hash structure), I3 (UTC microsecond `timestamp`) and I5 (SHA-256, lowercase
  hex, `audit-log/v1` domain labels).
- Accepted in principle: I9 (Ed25519-signed checkpoints outside the database), I11 (retention preserves chain
  evidence) and I12 (export integrity versus completeness).
- Rejected: I9a (per-record signatures).
- Approved after revision:
  - I2 (hash coverage), adding that `recordedBy` must be a stable, non-secret service identifier;
  - I6 (64-zero genesis, no chain ID, authenticated retention boundary);
  - I7 and I7a (advisory lock, clamped database clock, `UNIQUE(sequence)` and `UNIQUE(previous_hash)`, no
    foreign key);
  - I8b and I8c (exposure rules and the minimal v1 response);
  - I10a (per-value salted commitments rather than top-level commitments) and I10b (salt and storage rules,
    payload-only scope).
- Modified from the initial recommendation:
  - I4 now uses a maintained RFC 8785 library instead of an in-house canonicalizer, subject to an adoption check,
    and drops the integer-only, fraction and exponent restrictions (I4a–c). When reviewing the documentation diff,
    I clarified that no in-house or integer-only fallback is authorized: if no maintained library can be adopted
    without violating the approved requirements, implementation stops for my review and a new explicit decision;
  - I8a now scans the full chain and reports `firstViolation` plus `violationCount`, instead of stopping at the
    first violation.
- Deferred:
  - I9b (checkpoint timing), plus the checkpoint lifecycle, format, storage mechanics and key management;
  - the retention model, the redaction API and security, and the export bundle format (Focused Discussion #3);
  - the authentication mechanism, `recordedBy` format and database roles (security design).

**Rationale:**

- Restrictions are imposed only where deterministic hashing or PostgreSQL storage requires them, not for
  implementation convenience.
- A maintained library lowers the correctness risk of number serialization and supports reviewer confidence.
- `UNIQUE(previous_hash)` is kept because a fork in an append-only store would be permanent. A `previous_hash`
  foreign key is excluded because retention can remove older records.
- Per-value commitments let individual nested values be redacted while the original `contentHash` stays stable and
  the remaining values stay verifiable.
- Signed checkpoints address rewrite and truncation without per-record signatures or external infrastructure.
- A chain ID adds complexity that signed checkpoints make unnecessary.
- Deferred items belong to discussions that have not yet taken place.

**Result:** `docs/requirements.md`: §3 rows 2, 4–9, 11 and 13 revised; FR-1 input restrictions and `recordedBy`
rule added; FR-2 deferral replaced; FR-3 verification behavior, v1 response, violation types and exposure rules
added; FR-4 direction, threat model and limitation recorded; FR-5, FR-6 and FR-7 integrity principles added;
NFR-1 integrity design added; assumption 9, one out-of-scope item, risk rows and validation rows added; §13 source
classifications and open items updated.

**Validation:** No application code was changed, so no tests or quality checks apply. Validation at this stage is
my review of the design analysis before approval and of the requirements diff for consistency with the assignment
and the decisions above.

**Sign-off:** I accepted I1, I3 and I5, accepted I9, I11 and I12 in principle, rejected I9a and deferred I9b by
09:41 UTC, and approved I2, I4a–c, I6, I7, I7a, I8a–c, I10a and I10b on 2026-09-28 at 09:49 UTC.

### 2026-09-28 — Focused Discussion 3: retention, redaction and export

**Date/Time:** 2026-09-28, 10:15–11:31 UTC (from session timestamps: discussion requested at 10:15; first decision
set given at 10:30; remaining API decisions requested at 10:34; N1–N15 dispositions given at 11:29; final decision
set approved at 11:31).

**Activity:** Retention, redaction and export design discussion (documentation only), followed by two reconciliation
rounds and explicit developer approval.

**What I asked:** I asked Claude to analyze retention/archival, structured redaction and bulk export on top of the
approved integrity design, comparing options without deciding for me. I then asked Claude to reconcile my
dispositions against Discussions 1 and 2, and to resolve the remaining API and design questions (N1–N15).

**What the AI produced:**

- An initial analysis comparing logical archive, physical deletion with a signed boundary, and a payload purge that
  keeps the chain intact. Other findings:
  - redacted values would need a per-value storage design;
  - signed export manifests are needed, because recomputed hashes alone do not show a bundle is unaltered;
  - pre-signing verification is needed, to avoid signing tampered data;
  - public callers could forge retention or redaction authorization events through the append API.
- A reconciliation of my first decision set. It withdrew Claude's earlier proposal to put the administrator's
  identity in the redaction event's `actorId`, which conflicted with the approved `actorId`/`recordedBy`
  distinction.
- An API reconciliation (N1–N15) covering archived visibility, the redacted-value representation, redaction and
  export status behavior, export scope, verification scope before signing, the manifest, the reason field, and the
  relationship between export and checkpoints. It found that full-chain verification before signing is the only
  option that protects the completeness claim.

**What I decided:**

- Approved:
  - R1 (payload-purge retention), R2 (retention events), R5 (resumable purge);
  - X1 (separate per-value storage), X3 (JSON Pointer addressing), X4 (separate redaction event), X5 (atomic
    redaction);
  - E1 (export scope), E2 (snapshot and `asOfSequence`), E4 (per-record evidence), E7 (no signing of unverified
    data), E8 (standalone verifier);
  - N1–N6, N8–N11, N13 and N14.
- Approved in principle: E5 and N12 (signed manifest structure and signing concept).
- Modified:
  - R3: verification from genesis; `PAYLOAD_VALUE_MISSING` accepted in principle, with its authorization rule left
    open.
  - R4: archived visibility, reconciled with Discussion 1 before any API naming was accepted.
  - R6: configurable window and batch size, with no role named.
  - X2: commitment properties only, with no new canonicalization rule.
  - X6: the missing-value principle only.
  - X7: no meaningless repeat events, with the status reconciled later.
  - X9: distinguish redacted values from `null`, with the representation reconciled later.
  - E3: bounded, with no size number in the baseline.
  - E6: signing in principle, with key questions left open.
  - E9: status principles, with the mapping reconciled later.
  - C1: the principle only, with no enforcement mechanism.
- Deferred:
  - X8 and E10: roles, separation of duties, export auditing, `GET` versus `POST`, client-data access rules.
  - N7: whether system events can be redacted.
  - N15: the retention trigger, to implementation planning.
  - The export signature algorithm, key choice and key lifecycle, storage and distribution.
  - The C1 enforcement mechanism, internal identity and system-event field mapping.

**Rationale:**

- The payload purge meets the retention requirement while keeping the events table strictly append-only and
  verifiable from genesis, without depending on the deferred checkpoint lifecycle.
- Recording retention and redaction as chain events makes authorized removals auditable without updating immutable
  records.
- Values are rendered as `null` inside the preserved structure, with `redactedPaths` and `archived`, which keeps
  `payload` a JSON object and distinguishes redacted values from genuine `null` values.
- Exports always include archived records, so the completeness claim covers the full selected history.
- Full-chain verification before signing protects the completeness claim, at the accepted cost that a broken chain
  blocks exports.
- Security-dependent choices are deferred rather than fixed early. These include identity, roles, the protection of
  system events, and keys.

**Result:** `docs/requirements.md`:

- §3 rows 9 and 11–13 revised;
- FR-1 system-event principles added;
- FR-2 archived visibility, cursor filter binding and record representation added;
- FR-3 updated for verification from genesis and for `PAYLOAD_VALUE_MISSING` in principle, with its rule
  unresolved;
- FR-5 retention model, FR-6 redaction design and FR-7 export design added;
- NFR-1 storage note updated;
- out-of-scope items, risk rows and validation rows added;
- §13 open items replaced with the remaining security, checkpoint/key and implementation items.

**Validation:** No application code or tests were changed. Validation at this stage is my review of the design
analysis and reconciliations before approval, and of the requirements diff for consistency with the assignment and
with Discussions 1 and 2.

**Sign-off:** I gave my first Discussion 3 dispositions at 10:30 UTC and the N1–N15 dispositions at 11:29 UTC, and
approved the final reconciled Discussion 3 decision set on 2026-09-28 at 11:31 UTC.

### 2026-09-28 — Focused Discussion 4: security and Scenario C

**Date/Time:** 2026-09-28, 11:56–12:11 UTC (from session timestamps: discussion requested at 11:56; S1–S26
dispositions given at 12:07; C-1 and C-2 decided at 12:11).

**Activity:** Security and Scenario C design discussion (documentation only), followed by a reconciliation of my
decision set and explicit developer decisions.

**What I asked:** I asked Claude to analyze authentication, authorization, the protection of system events,
`actorId`/`recordedBy` usage, redaction authorization, redaction of system events, missing-value authorization,
the meaning of "access" in Scenario C, a prototype boundary for Scenario C, export authorization and auditing,
signing keys and security failure behavior, without deciding for me. I then asked Claude to reconcile my
dispositions against Discussions 1–3.

**What the AI produced:**

- An analysis and decision matrix (S1–S26), including:
  - options for authentication and for preventing impersonation of system events;
  - a capability model;
  - field mappings for system events;
  - a proposed rule for authorizing missing values;
  - interpretations of "access", separating access to business data from access to the audit log itself;
  - stakeholder questions, a draft clarified statement and assumptions SC-A1–SC-A8;
  - options for export auditing and signing keys.
- A key finding: no mechanism stops an attacker with database write access from forging authorizing events beyond
  the existing checkpoint window, so the reserved namespace is aimed at public callers.
- A reconciliation that found my decision set consistent with Discussions 1–3, with two dependencies:
  - C-1: the Scenario C validation would have rejected redaction events that inherit `CLIENT_ACCOUNT` fields;
  - C-2: how export audit events fill their identifying fields was not yet decided.

**What I decided:**

- Approved: S1–S4 (API keys, principal-based `recordedBy`, unauthenticated health endpoints, capability-based
  authorization), S6 and S7 (reserved namespace, `422`), S10–S12 (redaction authorization, separation of duties as a
  production requirement, system events not redactable), S17, S18, S20 (`POST` export), S25 and S26.
- Modified:
  - S5: the role model is a prototype security boundary, not an assignment requirement or a production design.
  - S8: redaction events inherit the target's identifying fields, with the operator in `recordedBy`; retention
    events' resource identity is left as a design detail.
- Approved in principle: S13 and S14 (missing-value authorization, offline verifier check), S19 (export audit
  event, `503` on failure), S21 (`requestedBy` in the manifest, recorded as a change to the Discussion 3 manifest
  direction), S22 (Ed25519 for exports, with the `cryptography` dependency to be approved during implementation
  planning), S24 (`keyId` fingerprint and rotation design).
- Approved as a prototype clarification and prototype assumptions: S15 and S16. The Scenario C interpretation of
  "access" and SC-A1–SC-A8 are recorded separately from the assignment's confirmed requirement. Global regulator
  access, denied-attempt auditing, per-read chain events, a specific regulation and a retention period are not
  presented as confirmed requirements.
- Deferred: S9 (internal identity, which depends on the retention trigger) and S23 (separate checkpoint and export
  keys).
- Resolved the reconciliation dependencies:
  - C-1: the `CLIENT_ACCOUNT` validation applies only to events submitted through the public API; reserved system
    events are exempt.
  - C-2: export audit events inherit their identifying fields from the export scope, with fixed server-defined
    values for fields the scope does not supply.

**Rationale:**

- The prototype needs a clear, testable authorization boundary without enterprise identity infrastructure. The
  role model is therefore labeled a prototype boundary.
- A reserved namespace blocks public callers from impersonating system events without changing hash coverage.
- Inheriting identifying fields keeps `actorId` as the business actor and makes redaction and export events appear
  in exports of the affected actor or resource.
- Exports are recorded because they are bulk disclosures of audit data. That side effect is why the method is
  `POST`.
- Scenario C assumptions are kept separate from the assignment's wording, because the requirement is deliberately
  under-specified.

**Result:** `docs/requirements.md`:

- §2 and §3 row 3 updated;
- FR-1 authentication, reserved namespace, system-event fields and the Scenario C validation reference added;
- FR-2 to FR-5 capability references and the FR-3 missing-value rule added;
- FR-6 redaction security, and FR-7 export security, signing, `requestedBy` and `POST`, added;
- FR-8 rewritten with the confirmed requirement, the prototype clarification, the assumptions, the scope and the
  production considerations;
- NFR-2 authentication, authorization and denied-attempt handling added;
- assumption 10, out-of-scope items, two Scenario C questions, risk rows and validation rows added;
- §13 open items updated.

**Validation:** No application code or tests were changed. Validation at this stage is my review of the analysis and
reconciliation before deciding, and of the requirements diff for consistency with the assignment and with
Discussions 1–3.

**Sign-off:** I gave the S1–S26 dispositions on 2026-09-28 at 12:07 UTC and decided C-1 and C-2 at 12:11 UTC.
