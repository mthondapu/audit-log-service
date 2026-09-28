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

### 2026-09-28 — Architecture and design planning

**Date/Time:** 2026-09-28, 12:27–12:56 UTC and the documentation work that followed (from session timestamps:
architecture analysis requested at 12:27; reconciliation requested at 12:39; final decisions given and artifacts
requested at 12:56).

**Activity:** Developer-led, AI-assisted architecture analysis, reconciliation, and creation of the architecture
documentation (no application code).

**Tool:** Claude Code (Claude Opus 5.5).

**What I asked:** I asked Claude to propose an architecture that satisfies the requirements baseline, then to
reconcile it against my decisions, and finally to write `docs/architecture.md`, nine ADRs, and five Draw.io diagrams
reflecting only the approved decisions.

**What the AI produced:**

- An architecture analysis covering components, flows, a logical data model, integrity and security mapping,
  diagrams, ADR candidates, and a decision list (AD-1 to AD-12). Key findings:
  - storing individual payload values as JSONB could change number representation and break commitment
    verification;
  - the HTTP status for redacting a system event was undefined;
  - exports lacked retention evidence for offline authorization of archived values;
  - the truncation and full-rewrite demonstrations depend on checkpoint creation.
- A reconciliation that corrected the analysis:
  - authorization is required before resource lookup, not necessarily before body validation;
  - the offline verifier is independently runnable, not independently implemented;
  - three separate database privilege boundaries;
  - `ALTER TABLE ... DISABLE TRIGGER` removed from the architecture.

  It also confirmed that `recordedAt` clamping was already approved in Discussion 2 (I7).
- The documentation artifacts listed under Result.

**What I decided:**

- Approved: AD-1 (modular monolith, shared integrity library, separate verifier and tamper tooling), AD-2
  (canonical JSON text value storage), AD-5 (retention via `POST /audit/retention-runs`, operator as `recordedBy`,
  no internal identity), AD-6 (`409` for redacting a system event), AD-8 (API-key configuration file outside the
  database), AD-9 (archived boundary derived from the chain), AD-11 (SQLAlchemy 2.x Core), and AD-12 (dependency
  gates before the integrity and signing code; no in-house RFC 8785).
- Approved with details deferred: AD-3 (explicit signed checkpoints outside the database), AD-10 (resource-oriented
  endpoint direction).
- Approved in principle: AD-4 (three privilege boundaries), AD-7 (retention evidence in exports).
- RB-1: checkpoints are created by an authorized CLI requiring `checkpoint:create`, not a public endpoint.
- RB-2: retention runs are synchronous and bounded. `201` when a new event is recorded and its bounded purge
  completes; `200` when nothing is eligible, with no event; an error when the bound cannot be met; resumable by later
  runs; no asynchronous jobs.
- RB-3: retention evidence must be inside the signed export manifest.
- Main diagrams use Draw.io, not Mermaid.

**Rationale:** Keep the prototype simple (one service, one database), keep integrity logic testable and shared,
keep trust anchors and tamper tooling outside the normal application path, and leave production concerns and
unfinished details explicitly deferred.

**Result:**

- Created `docs/architecture.md`.
- Created ADRs 0001–0009 under `docs/adr/`.
- Created five Draw.io diagrams under `docs/diagrams/`: system context, component architecture, audit append and
  integrity sequence, export and independent verification, and retention and redaction.
- `docs/requirements.md` was not changed. Requirements affected by these decisions were reported to me for a
  separate decision.

**Validation:**

- **Automated checks (by Claude):** all five `.drawio` files parse as well-formed XML, with no duplicate cell IDs and
  no dangling references; all relative links in `architecture.md` and the ADRs resolve; a search found no
  contradicting wording (for example `DISABLE TRIGGER`, Mermaid, or a claim that authorization must precede body
  validation).
- **Not yet done:** the diagrams have not been visually inspected in diagrams.net. No application code or tests
  exist or were changed.
- **Developer review:** of the documentation and diagrams, pending.

**Sign-off:** I gave the final architecture decisions (AD-1 to AD-12, RB-1 to RB-3) on 2026-09-28 at 12:56 UTC.
Review of the resulting documentation is pending.

### 2026-09-28 — Architecture follow-up decisions, requirements reconciliation and documentation review

**Date/Time:** 2026-09-28, 13:08–14:00 UTC (from session timestamps:
- follow-up decisions given at 13:08;
- diagram update requested at 13:20;
- requirements reconciliation requested at 13:47;
- FR-1/FR-2 clarification at 13:50;
- read-only consistency review at 13:51;
- consistency corrections at 13:54;
- pre-commit review at 13:57;
- this log entry requested at 14:00.)

**Activity:** Developer-led, AI-assisted follow-up to the architecture work: recording approved decisions, updating
diagrams, reconciling the requirements baseline, and reviewing the documentation for consistency. No application
code.

**Tool:** Claude Code (Claude Opus 5.5).

**What I asked:** I asked Claude to:

- record my decisions on the open review items in the architecture documentation and ADRs;
- update the two affected diagrams;
- reconcile `docs/requirements.md` with the approved decisions using minimal edits;
- clarify two requirement statements;
- run read-only consistency and pre-commit reviews;
- apply the corrections those reviews identified.

**What the AI produced:**

- Wording updates to `docs/architecture.md` (§10, §12, §13, §19, §21) and ADRs 0005, 0006 and 0007 recording my
  decisions below.
- Updates to `docs/diagrams/retention-redaction.drawio` (resumed-purge path, `422` validation step, `503` outcome,
  distinct `201` and `200` outcomes) and `docs/diagrams/export-independent-verification.drawio` (supplied
  checkpoint files, checkpoint signature verification, use of the trusted checkpoint, and the verifier's
  independence from the service, database, credentials and network).
- A minimal reconciliation of `docs/requirements.md`, covering:
  - FR-1: no separate internal identity;
  - FR-4: checkpoint CLI, verification before signing, refusal on failure;
  - FR-5: the synchronous, bounded, resumable retention statuses;
  - FR-6: `409` for redacting a system event;
  - FR-7: signed retention evidence, and checkpoint use by the verifier;
  - NFR-1: database privilege boundaries;
  - NFR-2: API-key configuration outside the database;
  - §12 and §13 updated accordingly.

  Genuinely deferred items were kept deferred.
- Two FR clarifications:
  - FR-1: a retention event is recorded only when a new boundary is established, and resuming a purge creates no
    event;
  - FR-2: archived state comes from the committed retention event, while physical purge may still be in progress
    or resume.
- A read-only consistency review that found four stale wordings:
  - architecture §7 (archived state);
  - two diagram labels describing the checkpoint CLI as reading only the chain head;
  - the NFR-1 foreign-key rationale.

  It also noted that the `CLAUDE.md` documentation list and the FR-6 endpoint-path deferral lag the approved
  direction.
- Corrections for the four stale wordings. While editing one diagram label, Claude introduced an XML formatting
  error; validation detected it and Claude fixed it before reporting.
- A read-only pre-commit review that confirmed:
  - all expected files are present;
  - the diagrams are well-formed;
  - `docs/assignment.md` is excluded and was never committed;
  - no application code exists.

  It also identified that this log did not yet cover the work above.

**What I decided:**

- Retention: a run with no newly eligible records resumes an unfinished purge without creating another retention
  event. It returns `200` when the resumed purge completes, `200` when nothing is eligible and no purge is
  unfinished, `422` for invalid request, configuration or input, and `503` when the configured bound prevents
  completion; the work remains resumable. `201` is kept for a new retention event whose purge completes.
- Checkpoint CLI: before creating and signing a checkpoint, it verifies the chain and refuses to sign if
  verification fails.
- Offline verifier: it can load supplied checkpoint artifacts, verify their signatures, and use the trusted
  checkpoint during export verification, while remaining independently runnable.
- I approved the requirements reconciliation scope, the FR-1/FR-2 clarifications and the four consistency
  corrections. I chose to keep the FR-6 endpoint-path deferral and to leave `CLAUDE.md` unchanged.

**Rationale:**

- Resumable, bounded retention must never report success for incomplete work or create redundant events.
- A checkpoint must never be created over a chain that is already known to be bad.
- Offline verifiers need the trusted checkpoint to verify independently.
- Requirements, architecture, ADRs and diagrams should agree before the documentation is committed.

**Result:**

- Updated: `docs/architecture.md`, ADRs 0005–0007, the two diagrams listed above, and `docs/requirements.md`.
- Label corrections in `docs/diagrams/system-context.drawio` and `docs/diagrams/component-architecture.drawio`.
- No application code exists or was changed.

**Validation:**

- **Automated checks (by Claude):** all five diagrams parse as well-formed XML with no duplicate cell IDs or
  dangling references; links in `architecture.md` and the ADRs resolve; `git diff --check` reports no whitespace
  errors; stale-wording searches found no remaining occurrences outside historical log text.
- **Developer review:** I visually inspected the two diagrams updated at 13:20 and reported that they look good.
  The two label-only edits made at 13:54 have not been separately re-inspected.
- **Git:** Claude did not stage, commit, push or alter Git history. I perform all Git operations.

**Sign-off:** I gave the follow-up decisions on 2026-09-28 at 13:08 UTC and approved each later step as requested
above. My final review of the combined documentation diff before committing is pending.

### 2026-09-28 — Implementation readiness and offline checkpoint anchoring (L-D1)

**Date/Time:** 2026-09-28, 14:06–14:20 UTC (from session timestamps: implementation-readiness analysis requested at
14:06; L-D1 analysis requested at 14:11; Approach B approved and documentation update requested at 14:20).

**Activity:** Developer-led, AI-assisted read-only implementation-readiness analysis, analysis of one open design
gap (L-D1), and documentation of the developer's decision. No application code.

**Tool:** Claude Code (Claude Opus 5.5).

**What I asked:** I asked Claude to assess implementation readiness without changing anything, then to analyze
L-D1 neutrally, without ranking or recommending an approach. After deciding, I asked Claude to record my decision
in the affected documentation.

**What the AI produced:**

- An implementation-readiness report: overall status "ready with gates" (the RFC 8785 library and `cryptography`
  gates), a proposed phase sequence, and a first slice (scaffolding plus strict input validation). It identified
  open items L-D1 to L-D4. L-D1 is the gap in how the offline verifier uses a supplied checkpoint whose sequence is
  neither `asOfSequence` nor an included record's sequence.
- A neutral comparison of two approaches for L-D1:
  - A: hash-only chain-link evidence in exports;
  - B: use a checkpoint only when it can be directly anchored to signed export evidence.

  It covered evidence, verification, scope, size, completeness, signature interaction, required document changes,
  and security or privacy. It also noted that a checkpoint created after an export cannot match that export's
  `asOfSequence`, because the export audit event is appended above it.
- Documentation updates recording the decision:
  - `docs/requirements.md` (FR-7 verifier behavior, §12 Export row);
  - `docs/architecture.md` (§12 artifacts, §13 offline verifier);
  - ADR-0006 (a new L-D1 subsection with rationale and consequences);
  - ADR-0007 (verifier behavior, no bridging evidence, alternative not adopted);
  - `docs/diagrams/export-independent-verification.drawio`: checkpoint path showing signature verification, an
    "anchorable?" decision, comparison, and a "not applicable / insufficient evidence" outcome.

**What I decided:**

- I approved Approach B. The offline verifier verifies a supplied checkpoint's signature and uses it only when it
  can be directly anchored: at `asOfSequence` against the signed `asOfRecordHash`, or at an included record's
  sequence against that record's signed and recomputed `recordHash`.
- Otherwise it reports "not applicable / insufficient evidence", which is not a chain-integrity failure, and all
  other export checks continue.
- No intervening chain-link evidence is added to exports, and no request parameter selects a checkpoint or range.
- The export scope model, the service-side verification before signing, and the signed manifest's role as the
  authoritative signed export evidence are unchanged.

**Rationale:** Approach B keeps export scope and size unchanged, discloses nothing about out-of-scope records, and
relies only on evidence the signed manifest already provides.

**Result:** Updated:

- `docs/requirements.md`
- `docs/architecture.md`
- `docs/adr/0006-checkpoint-trust-anchor.md`
- `docs/adr/0007-signed-exports.md`
- `docs/diagrams/export-independent-verification.drawio`
- this log

No application code exists or was changed.

**Validation:**

- **Automated checks (by Claude):** the modified diagram parses as well-formed XML with no duplicate cell IDs or
  dangling references; documentation links resolve; `git diff --check` reports no whitespace errors.
- **Pending:** visual inspection of the updated diagram and review of the diff by me.
- **Git:** Claude did not stage, commit, push or alter Git history.

**Sign-off:** I approved Approach B for L-D1 on 2026-09-28 at 14:20 UTC. My review of the resulting documentation
changes is pending.

### 2026-09-28 — API path design (L-D2)

**Date/Time:** 2026-09-28, 14:27–14:31 UTC (from session timestamps: L-D2 analysis requested at 14:27; decisions
given at 14:31).

**Activity:** Developer-led, AI-assisted analysis of the API paths for consistency with the approved requirements,
followed by documentation of the developer's decisions. No application code.

**Tool:** Claude Code (Claude Opus 5.5).

**What I asked:** I asked Claude to analyze each approved API path (resource, method semantics, purpose, how far
it is decided, and remaining ambiguity) without changing anything, then to record my decisions.

**What the AI produced:**

- An analysis finding the paths consistent and free of naming conflicts. It identified two items:
  - `requirements.md` still described the redaction and retention paths as open;
  - a retention-run `201 Created` had no defined `Location`. Under RFC 9110 the created resource would then
    default to `/audit/retention-runs`, which is not a resource.
- Documentation updates recording the decisions:
  - `docs/requirements.md`: FR-5 endpoint and `201` `Location`; the FR-6 path; the FR-7 path; the §12 Retention
    row; removal of the §13 path item;
  - `docs/architecture.md`: §5 paths marked final; §10 `201` `Location`;
  - `docs/adr/0005-retention-and-archived-boundary.md`: the `201` `Location`;
  - `docs/diagrams/retention-redaction.drawio`: the `201` label.

**What I decided:**

- L-D2a: `POST /audit/events/{id}/redactions`, `POST /audit/exports` and `POST /audit/retention-runs` are final
  paths.
- L-D2b (Option 1): a retention-run `201 Created` includes `Location: /audit/events/{retentionEventId}`, because
  the retention system event is the persisted resource the operation creates. There is no retention-run resource or
  table, and no GET endpoint for runs.
- Unchanged:
  - the approved retention statuses (`201`, `200`, `422`, `503`);
  - redaction's `201` with `Location`;
  - `GET /audit/verify`.

  The retention response schema and the export bundle and manifest schema remain deferred. No endpoints, query
  parameters, versioning or trailing-slash changes were added.

**Rationale:** Option 1 mirrors the approved redaction behavior and gives the `201` a real, readable resource.

**Result:** the five files listed above and this log were updated. No application code exists or was changed.

**Validation:**

- **Automated checks (by Claude):** the modified diagram parses as well-formed XML with no duplicate cell IDs or
  dangling references; `git diff --check` reports no whitespace errors; no wording describing these paths as open
  remains.
- **Pending:** visual inspection of the updated diagram and review of the diff by me.
- **Git:** Claude did not stage, commit, push or alter Git history.

**Sign-off:** I approved L-D2a and L-D2b on 2026-09-28 at 14:31 UTC. My review of the resulting documentation
changes is pending.

### 2026-09-28 — API-key configuration and application settings (D3)

**Date/Time:** 2026-09-28, 14:39–14:42 UTC (from session timestamps: D3 analysis requested at 14:39; decisions
given at 14:42).

**Activity:** Developer-led, AI-assisted analysis of the concrete design for API-key configuration and application
settings, followed by documentation of the developer's decisions. No application code.

**Tool:** Claude Code (Claude Opus 5.5).

**What I asked:** I asked Claude to analyze the configuration source, API-key representation, secret handling, the
settings library, startup validation, runtime reload, testing, and security implications without changing
anything, separating what was already decided from what D3 needed to decide. I then asked Claude to record my
decisions.

**What the AI produced:**

- An analysis comparing TOML, JSON, and YAML, and three ways of supplying settings. It found:
  - plain Pydantic v2 is sufficient, and `pydantic-settings` and `PyYAML` are outside the approved stack;
  - unsalted SHA-256 key hashing is only adequate for high-entropy, machine-generated keys;
  - a committed example file should use placeholders that fail validation.
- Documentation updates recording the decisions:
  - ADR-0008: a new D3 subsection, plus consequences and alternatives;
  - `docs/architecture.md`: the §4 Configuration row, the §6 Configuration bullet, and §21 deferred details;
  - `docs/requirements.md`: NFR-2 authentication, a new API-key configuration block, and the §13 open items.

**What I decided:**

- D3a: TOML via the standard library's `tomllib`; no YAML or other parser dependency.
- D3b: environment variables for scalar and secret settings and for the paths to structured configuration; separate
  mounted TOML files for the API-key configuration and for the Scenario C vocabulary and required keys.
- D3c: plain Pydantic v2 validation; no `pydantic-settings` or other settings dependency.
- D3d:
  - each principal has exactly one approved prototype role, with no arbitrary capability lists; the approved
    role-to-capability mapping stays authoritative;
  - one or more lowercase hexadecimal SHA-256 key hashes per principal;
  - raw keys machine-generated with at least 128 bits of entropy (applying to the raw key, not the digest), and
    never persisted in PostgreSQL, Git, or logs;
  - constant-time comparison.
- D3e: the service and CLI fail fast on the listed configuration errors, without echoing raw keys or hash values.
- D3f: load once at startup; restart to apply changes; no hot reload.
- D3g: deterministic fake keys with hashes computed in fixtures; tests that raw keys and Authorization headers are
  not logged; an example configuration with intentionally invalid placeholders; real and demo credentials in
  gitignored locations.
- Kept deferred: exact environment-variable names and paths, how the CLI is presented with the operator's
  credential, the principal-ID pattern, the Scenario C vocabulary names, `.gitignore` details, and the demo-key
  generation mechanism.

**Rationale:** use the approved stack without new dependencies, keep the approved role model authoritative, fail
safely on bad configuration, and keep secrets out of the repository, the database, and logs.

**Result:** Updated:

- `docs/adr/0008-authentication-and-authorization.md`
- `docs/architecture.md`
- `docs/requirements.md`
- this log

No application code, configuration files, or `.gitignore` rules exist or were created.

**Validation:**

- **Automated checks (by Claude):** `git diff --check` reports no whitespace errors; relative links resolve; no
  stale "configuration layout" wording remains outside the narrowed deferred items.
- **Pending:** my review of the diff.
- **Git:** Claude did not stage, commit, push or alter Git history.

**Sign-off:** I approved the D3 decisions on 2026-09-28 at 14:42 UTC. My review of the resulting documentation
changes is pending.

### 2026-09-28 — Security and authentication architecture (D4)

**Date/Time:** 2026-09-28, 14:45–14:50 UTC (from session timestamps: D4 analysis requested at 14:45; decisions
given at 14:50).

**Activity:** Developer-led, AI-assisted review of the remaining security and authentication items for
implementation, followed by documentation of the developer's decisions. No application code.

**Tool:** Claude Code (Claude Opus 5.5).

**What I asked:** I asked Claude to review twelve security areas against the existing documents, separating what
was already decided from what remained open, and checking for contradictions, without changing anything. I then
asked Claude to record my decisions.

**What the AI produced:**

- An analysis finding the security model largely decided, with no substantive contradictions. It identified:
  - `WWW-Authenticate` was specified only in architecture §19;
  - the handling of malformed credentials was unspecified;
  - the order of validation checks was left as an implementation choice;
  - the checkpoint CLI's database access was undocumented;
  - transport security (TLS) was not mentioned anywhere;
  - FR-6's reference to an "internal or system identity" was stale after AD-5.
- Documentation updates recording the decisions:
  - `docs/requirements.md`: FR-6 wording; NFR-2 blocks for authentication failures, check order, and CLI database
    access; a transport risk row in §10; the §12 Authentication and Authorization rows;
  - `docs/architecture.md`: §6 Ordering and Failures, a §14 CLI access row, the §19 `401` row, and a §20
    limitation;
  - ADR-0008: check order, authentication failures, transport, and two alternatives;
  - ADR-0009: the CLI's read-only access.

**What I decided:**

- D4-a: every authentication failure returns `401` with `WWW-Authenticate: Bearer` and the same Problem Details
  structure. This covers a missing header, a non-Bearer scheme, an empty or malformed token, multiple headers, and
  unknown credentials.
- D4-b: fixed order — authenticate, authorize, validate the request, look up resources.
- D4-c: the checkpoint CLI uses read-only database access; exact role names and grants remain implementation
  details.
- D4-d: plain HTTP is documented as a prototype and local limitation, with TLS/HTTPS as a production
  consideration and no prototype TLS requirement.
- The FR-6 wording cleanup.
- Kept deferred:
  - how the CLI is presented with the operator's credential;
  - exact database role names and grants;
  - the logging format;
  - RFC 6750 granular error distinctions;
  - prototype TLS implementation.

**Rationale:**

- A uniform `401` gives callers no hint about why authentication failed.
- A fixed order makes statuses deterministic and gives unauthorized callers no validation feedback.
- Read-only CLI access follows least privilege.
- Documenting the transport limitation closes a visible gap without adding scope.

**Result:** Updated:

- `docs/requirements.md`
- `docs/architecture.md`
- `docs/adr/0008-authentication-and-authorization.md`
- `docs/adr/0009-database-privileges-and-tamper-boundary.md`
- this log

No application code, dependencies, or diagrams were changed.

**Validation:**

- **Automated checks (by Claude):** `git diff --check` reports no whitespace errors; relative links resolve; stale
  D4 wording searches found no remaining occurrences.
- **Pending:** my review of the diff.
- **Git:** Claude did not stage, commit, push or alter Git history.

**Sign-off:** I approved D4-a to D4-d and the FR-6 cleanup on 2026-09-28 at 14:50 UTC. My review of the resulting
documentation changes is pending.

### 2026-09-28 — Phase 0: project scaffolding

**Date/Time:** 2026-09-28, 15:03–15:08 UTC (from session timestamps: Phase 0 requested at 15:03; review decisions
given at 15:08).

**Activity:** Developer-led, AI-assisted project scaffolding and tooling. No application or business functionality.

**Tool:** Claude Code (Claude Opus 5.5).

**What I asked:** I asked Claude to create the minimum Python project structure using the approved stack, with
uv, Python 3.13, and tooling configuration. I excluded the RFC 8785 library, `cryptography`, `pydantic-settings`,
and YAML, and anything beyond scaffolding.

**What the AI produced:**

- `pyproject.toml`, containing:
  - runtime dependencies `fastapi`, `uvicorn`, `pydantic` (<3), `sqlalchemy` (<3), `alembic`, and
    `psycopg[binary]` (<4);
  - a dev group with `pytest`, `pytest-cov`, `hypothesis`, `httpx`, `ruff`, `pyright`, `bandit`, and `pip-audit`;
  - the `uv_build` backend;
  - Ruff configuration (excluding Markdown, so documentation code blocks are not reformatted), strict Pyright,
    pytest, coverage (branch, no threshold), and Bandit.
- `uv.lock` and `.python-version` (3.13).
- A `src/audit_log_service` package containing only a docstring.
- A single package-import smoke test.
- `compose.yaml`: a local PostgreSQL service bound to localhost. The password must come from the environment and
  fails if unset.
- `.env.example`, with an empty password.
- `.gitignore` safety-net rules for real API-key configuration, demo credentials, key material, and local secrets.

**What I decided:**

- Approved: the package name `audit_log_service`; `psycopg[binary]` for the prototype; the `.gitignore` patterns
  (which do not finalize the deferred D3 paths); the smoke test; no coverage threshold yet.
- Modified: the Compose configuration now uses the neutral default `postgres` user instead of a name implying the
  deferred database role design. It remains bound to localhost.

**Rationale:** Establish a minimal, validated toolchain on the approved stack without pre-empting deferred
decisions or dependency gates.

**Result:**

- Created `pyproject.toml`, `uv.lock`, `.python-version`, `src/audit_log_service/__init__.py`,
  `tests/test_package.py`, `compose.yaml`, and `.env.example`.
- Modified `.gitignore` and this log.
- No endpoints, authentication, authorization, schema, migrations, integrity code, or configuration loader were
  implemented.
- No credentials or usable secrets were created.

**Validation (performed by Claude, results as observed):**

- `uv lock --check` and `uv sync --locked` succeeded.
- `ruff format --check` and `ruff check` passed.
- `pyright` reported 0 errors.
- `pytest --cov` reported 1 passed.
- `bandit` found no issues.
- `pip-audit` on the locked requirements found no known vulnerabilities.
- `docker compose config --quiet` passed with a dummy password, and failed as intended without one.
- `git diff --check` reported no whitespace errors.

**Git:** Claude did not stage, commit, push or alter Git history.

**Sign-off:** I reviewed the scaffold and gave the decisions above on 2026-09-28 at 15:08 UTC. My review of the
final changes before committing is pending.

### 2026-09-28 — Phase 1: configuration loading, authentication and authorization foundation

**Date/Time:** 2026-09-28, from 15:21 UTC (from session timestamps: Phase 1 requested at 15:21; my answers to
Claude's clarifying questions recorded at 15:23).

**Activity:** Developer-led, AI-assisted implementation of the configuration-loading and security foundation, with
unit tests. No database, API endpoints, or integrity functionality.

**Tool:** Claude Code (Claude Opus 5.5).

**What I asked:**

- A TOML and Pydantic v2 configuration loader with fail-fast validation.
- Bearer API-key authentication with constant-time comparison and a uniform `401`.
- Capability-based authorization.
- Problem Details for authentication and authorization failures.
- Safe example configuration files, unit tests, and the validation suite.

**Clarifications before coding.** Before writing code, Claude stopped and asked about one conflict and three open
points. My answers:

- My brief said `events:verify`, but the approved documents say `chain:verify`. I chose the documented
  `chain:verify`.
- The principal-ID pattern had been deferred. I chose `^[a-z][a-z0-9._-]{0,63}$`, now recorded in the
  documentation.
- I chose to include a minimal Scenario C vocabulary loader. Its structure is a `resource_type` plus `event_types`
  entries, each with a `name` and `required_payload_keys`; the vocabulary names stay deferred.
- Loaders take an explicit file path; environment-variable names stay deferred.

**What the AI implemented:**

- `security/capabilities.py`: the approved capabilities and the authoritative role-to-capability mapping.
- `config/errors.py`, `config/toml_file.py`: fail-fast TOML reading with `tomllib`.
  - Error messages never echo file content or configured values.
  - Python 3.13's `TOMLDecodeError` has no line or column attributes, so the position is read from the parser
    message's suffix.
- `config/api_keys.py`: the API-key loader. It rejects:
  - unknown fields, duplicate principals, and duplicate hashes (within or across principals);
  - invalid hashes and unknown roles;
  - principals without keys, no principals, and invalid principal IDs.

  It produces immutable configured principals with digest bytes.
- `config/vocabulary.py`: the minimal Scenario C vocabulary loader.
- `security/authentication.py`: Bearer extraction.
  - Exactly one Authorization header is accepted, the scheme is case-insensitive, and the header must have exactly
    two parts.
  - The presented key is hashed with SHA-256 and compared with every configured digest using
    `hmac.compare_digest`, without stopping early.
  - Every failure raises the same detail-free error.
- `security/authorization.py`: `require_capability`, plus a helper that authenticates, then authorizes.
- `problem_details.py`:
  - a uniform `401` with `WWW-Authenticate: Bearer`, and a `403`;
  - RFC 9457 bodies with `type` `about:blank`, fixed text, and an optional `requestId`.
- Example files:
  - `config/api-keys.example.toml`, whose placeholders intentionally fail validation;
  - `config/client-account-vocabulary.example.toml`, with illustrative names.
- Tests (101 new, 102 in total, including the existing smoke test):
  - configuration validation, including checks that no secrets are echoed;
  - authentication failure cases, multiple headers, and a constant-time comparison call count;
  - a no-logging check;
  - a Hypothesis property test;
  - the full role-by-capability matrix, redaction restricted to administrators, and check order;
  - the Problem Details structure;
  - the behavior of the example files.

**Documentation updates:** the principal-ID pattern recorded in `requirements.md` (NFR-2) and `architecture.md` §6
and ADR-0008, and removed from the deferred lists in `requirements.md` §13, `architecture.md` §21 and ADR-0008. The
vocabulary file structure recorded in `architecture.md` §16.

**Deviations and issues:** none from the approved documents. The capability name follows the documents rather than
my brief, as I chose. No dependencies were added.

**Validation (performed by Claude, results as observed):**

- `uv lock --check` and `uv sync --locked` succeeded.
- `ruff format --check` and `ruff check` passed.
- `pyright` (strict) reported 0 errors.
- `pytest --cov` reported 102 passed, with 100% statement and branch coverage.
- `bandit` found no issues.
- `pip-audit` found no known vulnerabilities.
- Both example files parse with `tomllib`.
- `git diff --check` reported no whitespace errors.

**Git:** Claude did not stage, commit, push or alter Git history.

**Review fixes (requested 2026-09-28 at 15:35 UTC, from session timestamps).** After a review of the Phase 1
implementation, I asked for these fixes only:

- `ConfiguredPrincipal.key_digests` is excluded from the default `repr`, so printing a configuration never exposes
  key hashes. The stored value and authentication behavior are unchanged.
- Authorization parsing now accepts exactly `Bearer <token>`: one ASCII space, a case-insensitive scheme, and a
  non-empty token with no whitespace. Tabs, repeated spaces, and leading or trailing whitespace are malformed. Every
  failure still raises the same detail-free error. This replaces the earlier "exactly two parts" split.
- The Hypothesis property test now runs against a non-empty configuration of obviously fake keys, built inside the
  test, instead of an empty configuration.
- `architecture.md` §16 now states the vocabulary name rules: non-empty, no leading or trailing whitespace, no ASCII
  control characters.
- **Note for the API phase:** the API layer must pass **all** received Authorization header values to
  `authenticate` (for example, through a header API that returns every value as a list), so that rejecting multiple
  Authorization headers stays enforceable.

Validation after the fixes (performed by Claude, results as observed): `uv lock --check` and `uv sync --locked`
succeeded; `ruff format --check` and `ruff check` passed; `pyright` (strict) reported 0 errors; `pytest --cov`
reported 115 passed, with 100% statement and branch coverage; `bandit` found no issues; `pip-audit` found no known
vulnerabilities; `git diff --check` reported no whitespace errors. No dependencies were added.

**Sign-off:** I answered the four clarifying questions and requested the review fixes above. My review and sign-off
of the Phase 1 implementation are pending.

### 2026-09-28 — Phase 2: RFC 8785 and Ed25519 dependency gates

**Date/Time:** 2026-09-28, from 15:49 UTC (from session timestamps: Phase 2 requested at 15:49; my numeric-domain
decision given at 15:58).

**Activity:** Developer-led, AI-assisted dependency gates for canonicalization and signing. No integrity, signing,
database, or API functionality.

**Tool:** Claude Code (Claude Opus 5.5).

**What I asked:** evaluate and adopt an established RFC 8785 (JCS) library and the `cryptography` package for
Ed25519, prove each against the approved requirements with focused tests, and stop on any incompatibility with the
approved requirements rather than work around it.

**What the AI did:**

- **RFC 8785 library evaluation.**
  - Candidates:
    - `rfc8785` (Trail of Bits);
    - `jcs`, whose last release was in 2022;
    - `canonicaljson`, which implements Matrix canonical JSON, not RFC 8785.
  - `rfc8785` was the only candidate to pass the adoption check. It is Apache-2.0, and its repository is active and
    not archived.
  - It matches the RFC's published examples:
    - the Section 3.2.4 sample bytes;
    - the Section 3.2.3 property-sorting sample;
    - every finite number sample in Appendix B.
  - It rejects NaN and infinities, integers outside ±(2^53−1), unpaired surrogates, and non-JSON types.
- **Conflict found.** A Hypothesis round-trip property test failed on `9007199254740992.0`. RFC 8785 writes
  whole-number doubles between 2^53 and 10^21 as plain integer digits. FR-1 then accepted such values in fraction or
  exponent notation, but their canonical text reads back as an integer outside the ±(2^53−1) integer domain. The
  library's output is correct RFC 8785, so changing library would not help. Claude stopped, did not narrow the test,
  and presented three options:
  1. bound every number to ±(2^53−1) by numeric value, whatever its notation;
  2. reject only whole numbers from 2^53 up to 10^21;
  3. keep FR-1 unchanged and require every verifier to parse numbers as doubles or never re-parse canonical text.
- **Ed25519 evaluation** with `cryptography` 50.0.1:
  - key generation, and deterministic 64-byte signatures;
  - rejection of a modified message, a modified, truncated, or extended signature, and another key's signature;
  - raw and PEM public-key round trips;
  - in-memory PKCS#8 private-key loading;
  - the RFC 8032 TEST 2 vector, verified using only its public key, message, and signature;
  - signing RFC 8785 canonical bytes.

  All test keys are ephemeral and generated in memory.

**My decision:** I approved option 1 (at 15:58 UTC). Every accepted JSON number, whether written as an integer, a
fraction, or in exponent notation, must have a numeric value within ±(2^53−1); values outside the range, such as
`9007199254740992`, `9007199254740992.0`, `1e16`, `1e21`, or `1e300`, are rejected. There is no exception for RFC
8785's 10^21 formatting boundary. This is an application-level restriction of the service, not a requirement of RFC
8785. I also instructed that `rfc8785>=0.1.4,<0.2` and `cryptography>=50.0.1` be kept.

**Dependencies adopted:** `rfc8785>=0.1.4,<0.2` and `cryptography>=50.0.1`, which bring in `cffi` and `pycparser`
through `uv.lock`. No other dependencies were added.

**Tests (90 new, 205 in total):**

- `tests/unit/dependency_gates/test_rfc8785_gate.py` (75 tests):
  - the RFC samples;
  - key ordering and nested structures;
  - booleans versus integers;
  - integer bounds, non-finite numbers, surrogates, and non-JSON types;
  - boundary tests for the numeric domain in integer, fraction, and exponent notation. Before sign-off I asked for
    two explicit cases showing that the check applies to the IEEE-754 double value: `9007199254740991.4` is
    accepted (it rounds to 2^53−1) and `9007199254740991.5` is rejected (it rounds to 2^53). A matching sentence was
    added to FR-1;
  - a property test that every accepted value survives canonicalization, parsing under the FR-1 number rules, and
    canonicalization again with identical bytes;
  - a property test that the canonical text of any out-of-domain number is rejected.

  The FR-1 number parse used by these tests is a reference helper in the test file. The service's request validator
  belongs to the API phase.
- `tests/unit/dependency_gates/test_ed25519_gate.py` (15 tests): the Ed25519 checks above.

**Documentation updates:**

- `requirements.md`: the FR-1 numeric-domain rule and its rationale; the canonicalization and signing notes; the
  resolved gate items removed from §13.
- `architecture.md`: the component table; a canonicalization and numeric-domain note in §8; the resolved gate item
  removed from §21.
- ADR-0002: the numeric-domain decision and the library adoption outcome.
- ADR-0006 and ADR-0007: the signing dependency outcome, with its deferred-list item removed.

**Limitations and deferred items:**

- An unpaired surrogate in an object key raises `UnicodeEncodeError` rather than the library's
  `CanonicalizationError`. Both are `ValueError`, and FR-1 validation rejects surrogates first.
- Still deferred:
  - domain-label strings, hash encodings, and the commitment encoding;
  - checkpoint and manifest schemas;
  - the public-key serialization format for artifacts;
  - signing-key storage and lifecycle.

**Validation (performed by Claude, results as observed):**

- `uv lock --check` and `uv sync --locked` succeeded.
- `ruff format --check` and `ruff check` passed.
- `pyright` (strict) reported 0 errors.
- `pytest --cov` reported 205 passed, with 100% statement and branch coverage.
- `bandit` found no issues.
- `pip-audit` found no known vulnerabilities.
- `git diff --check` reported no whitespace errors.

**Git:** Claude did not stage, commit, push or alter Git history.

**Sign-off:** I approved option 1 for the numeric domain as recorded above. My review and sign-off of the Phase 2
implementation are pending.
