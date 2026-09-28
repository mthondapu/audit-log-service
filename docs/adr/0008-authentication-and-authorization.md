# ADR-0008: Authentication and authorization

- **Status:** Accepted
- **Date:** 2026-09-28
- **Decision owner:** Developer (Focused Discussion #4, decisions S1–S7, S10, S18, S25, S26; AD-8)

## Context

The audit APIs require authenticated callers with clearly separated privileges. The prototype must not depend on enterprise identity infrastructure. `recordedBy` must be a stable, non-secret identifier of the caller.

## Decision

- **Static API keys** presented as Bearer credentials. Only SHA-256 hashes are stored, and credentials are compared in constant time. Raw keys are never committed.
- **Configuration** lives in a mounted file outside the database, containing key hashes, non-secret principal IDs, and capabilities or roles. A database writer cannot grant itself credentials.
- **Principal ID** becomes `recordedBy`.
- **Capability-based authorization** is enforced at the API/service boundary, **before resource lookup**. Its order relative to body validation is an implementation choice.
- **Prototype roles.** These are a prototype security boundary, not an assignment requirement or enterprise RBAC:
  - writer → `events:write`;
  - auditor and regulator → `events:read`, `chain:verify`, `export:create`;
  - administrator → `events:read`, `events:redact`, `retention:run`, `checkpoint:create`.
- **Unauthenticated endpoints.** `/health/live` and `/health/ready`; `/docs` and `/openapi.json` are public in the prototype only.
- **Reserved system-event namespace.** Enforced by the service layer; a public caller submitting a reserved type receives `422`.
- **Denied attempts.** Logged operationally, never appended to the chain.

## Consequences

- The boundary is explicit and testable, and could be replaced by an identity provider later.
- Compromise of a key allows actions within its capabilities, attributed via `recordedBy`.
- Writers cannot read the audit log; administrators cannot export.

## Alternatives considered

- **Locally issued JWTs:** add token issuance and expiry handling for little benefit.
- **Mutual TLS:** heavy for a local prototype.
- **OIDC identity provider:** out of scope (requirements §7).
- **API keys stored in the database:** rejected, so that a database writer cannot create credentials.

## References

- [architecture.md](../architecture.md) Sections 5, 6, 17
- [requirements.md](../requirements.md) FR-1, NFR-2
