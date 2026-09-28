# Claude Code Instructions

## Project

Audit Log Service — a tamper-evident, append-only audit log service.

The project follows a **developer-led, AI-assisted software engineering workflow**. The developer makes final decisions and approves implementation and validation.

## Stack

Use the established project stack:

- Python 3.13
- FastAPI
- Uvicorn
- Pydantic v2
- PostgreSQL
- SQLAlchemy 2.x
- Alembic
- psycopg 3
- pytest
- pytest-cov
- Hypothesis
- httpx
- Ruff
- Pyright
- Bandit
- pip-audit
- uv
- Docker / Docker Compose where required

Do not replace the core stack or add dependencies without a clear engineering reason and developer approval.

## Requirements

Use `docs/assignment.md` as the primary assignment reference and `docs/requirements.md` as the developer-authored requirements baseline.

If `docs/assignment.md` and `docs/requirements.md` conflict, stop and ask the developer before proceeding.

Do not copy text from `docs/assignment.md` into committed files; describe requirements in your own words.

Before implementing behavior that is materially ambiguous or consequential:

1. Identify the ambiguity or risk.
2. Present relevant alternatives and trade-offs.
3. Discuss the issue with the developer.
4. Implement the developer-approved decision.

Do not invent requirements or silently finalize consequential assumptions.

The assignment document is reference material only. Do not modify its intended requirements to fit an implementation.

## Development Workflow

Work incrementally:

1. Understand the requirement.
2. Plan the smallest appropriate change.
3. Implement the approved behavior.
4. Review the resulting diff.
5. Add or update relevant tests.
6. Run applicable quality checks.
7. Report validation accurately.

For routine implementation work within an approved design, proceed without unnecessary approval loops.

When a requirement is unclear but does not materially affect security, integrity, correctness, scope, or reviewer expectations, use established engineering practice and document the assumption where appropriate.

## Audit Integrity

The audit log is append-only through the normal application API.

- Do not expose update or delete operations for audit records.
- Keep hashing, canonicalization, chain, and verification logic independently testable.
- Keep privileged datastore operations used for controlled tampering demonstrations separate from the normal application path.
- Do not use the normal application API to perform datastore tampering demonstrations.
- Do not unnecessarily log sensitive audit payload values.
- Do not weaken integrity controls for implementation convenience.

Changes affecting cryptographic integrity, hash-chain semantics, append ordering, concurrency, verification, retention, redaction, or export integrity require developer review.

## Security

Treat security-sensitive behavior explicitly.

Pay particular attention to:

- Authentication and authorization boundaries.
- Input validation.
- Sensitive data handling.
- Database permissions.
- Secrets and credentials.
- Error responses and information disclosure.
- Resource and query limits.
- Audit-log integrity.

Never place secrets, credentials, tokens, or real personal data in source code, tests, prompts, or committed configuration.

## High-Impact Decisions

Require developer review before implementation when a decision materially affects:

- Timestamp and event-time semantics.
- Audit-event semantics.
- Hash-chain semantics.
- Canonical serialization.
- Hash input/envelope definition.
- Genesis and chain-order semantics.
- Append ordering and concurrency control.
- Append-only enforcement.
- Verification behavior.
- Authentication and authorization boundaries.
- Actor/principal semantics.
- Idempotency and retry behavior.
- Pagination semantics.
- Retention and archival semantics.
- Redaction and integrity semantics.
- Export scope, completeness, and verification.
- Scenario C interpretation and scope.

Claude may analyze alternatives and trade-offs, but the developer makes the final decision.

## Testing

Tests should verify requirements and important failure modes.

Where applicable, include:

- Unit tests.
- Integration tests.
- API tests.
- Database tests.
- Security tests.
- Integrity and tamper tests.
- Concurrency tests.
- Performance/query validation.

Integrity tests must cover modification, middle deletion, insertion, reordering, and tail truncation. A plain hash chain cannot detect tail truncation; test it against the approved trust mechanism.

Do not claim a test or quality check was executed unless it was actually executed.

## Scenario C

Treat ambiguous access semantics as requiring clarification before implementation.

Consider, where relevant:

- What constitutes access.
- Authenticated principal versus business actor.
- Successful versus denied access.
- Reads, writes, and exports.
- System-to-system access.
- Data boundaries.
- Required evidence.
- Retention.
- Authorization scope.

The developer makes the final interpretation and implementation-scope decision.

Document the clarified requirement statement, assumptions, implemented scope, and scope-outs.

## Documentation

Use existing project documentation before creating new files.

Current documentation and reference material:

- `README.md` — project overview and usage.
- `ATTESTATION.md` — project attestation.
- `docs/assignment.md` — local copy of the provided assignment; do not commit or push.
- `docs/requirements.md` — developer-authored requirements baseline.
- `docs/ai-usage-log.md` — meaningful AI-assisted engineering traceability.
- `CLAUDE.md` — Claude Code project instructions.

Create additional documentation only when it has a clear engineering purpose.

Use conventional locations and names for additional documentation.

Required later: architecture overview, testing approach and limitations, and engineering summary.

## AI Usage

Record meaningful AI-assisted engineering work in `docs/ai-usage-log.md`.

The log should capture substantive:

- Requirements analysis.
- Consequential decisions.
- Significant implementation.
- Debugging.
- Security review.
- Refactoring.
- Testing.
- Documentation work.

Claude drafts entries at the time of the work; the developer reviews them.

Do not fabricate AI contributions, developer decisions, validation results, tests, or historical interactions.

The AI usage log is an engineering traceability record, not a transcript of every interaction.

## Repository Structure

Follow conventional software-engineering structure and naming.

Do not create directories or files merely for documentation or convention.

When the implementation structure is established, keep code, tests, migrations, scripts, and documentation in clearly separated, conventional locations.

Before introducing a new artifact:

1. Check whether an existing file or directory already serves the purpose.
2. Confirm that the new artifact has a distinct engineering purpose.
3. Use a conventional location and professional naming.
4. Avoid redundant or unnecessary project artifacts.

## Git

The developer controls Git history.

Claude may inspect Git state, review diffs, and suggest commit messages, but must not independently commit or push.

Before a commit:

1. Review changed files and the diff.
2. Confirm no unintended files are included.
3. Run applicable validation.
4. Confirm documentation and AI-log changes are accurate.
5. The developer commits the coherent logical change under the developer's Git identity.

Prefer meaningful, coherent commits over excessive commits for trivial changes.

The local `docs/assignment.md` file is intentionally excluded through `.git/info/exclude` and must never be added to a commit.

## Change Scope

Keep changes focused.

When implementing a requirement:

- Change only what is necessary.
- Avoid unrelated refactoring.
- Avoid speculative features.
- Avoid unnecessary dependencies.
- Avoid premature abstractions.
- Preserve existing behavior unless the approved change requires otherwise.

If unrelated issues are discovered, identify them separately rather than silently expanding the scope.

## Decision and Discussion Style

Use focused engineering discussions for consequential uncertainty.

When discussion is warranted:

1. State the issue clearly.
2. Explain the relevant technical considerations.
3. Present reasonable alternatives where applicable.
4. Explain important trade-offs and risks.
5. Identify what requires developer approval.
6. Proceed after the developer's decision.

For routine engineering work, proceed directly within the approved design.

Do not repeatedly ask for approval for ordinary implementation details.

Do not manufacture ambiguity or disagreement merely to create an AI discussion.

Do not reopen decisions without a concrete reason, such as:

- A new requirement.
- New implementation evidence.
- A test failure.
- A security issue.
- A discovered contradiction.
- A material change in scope.

Once a consequential decision has been made and documented, treat it as closed unless new evidence requires reconsideration.
