# ADR-0001: Modular monolith and shared integrity library

- **Status:** Accepted
- **Date:** 2026-09-28
- **Decision owner:** Developer (architecture decision AD-1)

## Context

The service must record, query, verify, redact, retain, and export audit events with strong integrity guarantees, while remaining a runnable local prototype. The requirements need a single serialized audit chain, exports that can be verified without the live service, and privileged tamper demonstrations that stay outside the normal application path.

## Decision

- Build a **modular monolith**: one FastAPI service and one PostgreSQL database, with clear internal module boundaries (API, security, request validation, services, persistence, signing, configuration, observability).
- Implement canonicalization, hashing, commitments, chain verification, missing-value authorization, and manifest checks in a **dependency-light integrity library** with no web framework or database dependencies.
- Share that library between the service, the checkpoint CLI, and the **offline export verifier**. The verifier is independently runnable and independently verifiable without the live service or database; it is not described as an independent implementation, because it shares the library.
- Keep **tamper-demonstration tooling** separate and privileged, outside the application's trust boundary.
- Do not introduce microservices.

## Consequences

- A single integrity implementation keeps service verification and offline verification consistent, and it can be tested in isolation.
- A defect in the shared library would affect the service and the verifier alike. RFC 8785 test vectors, property tests, and a documented verification algorithm that others can reimplement mitigate this.
- One deployable service with one database keeps the serialized append simple and avoids network hops in the critical path.

## Alternatives considered

- **Microservices** (for example, separate ingestion, verification, and export services): rejected; the single serialized chain gains nothing from distribution and becomes harder to reason about.
- **Duplicated verification logic** in the verifier: rejected; two implementations risk divergence without adding assurance, unless written and reviewed independently.

## References

- [architecture.md](../architecture.md) Sections 1, 2, 4
- [requirements.md](../requirements.md) FR-7 (standalone verifier), NFR-4
