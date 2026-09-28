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
