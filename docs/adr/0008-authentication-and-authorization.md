# ADR-0008: Authentication and authorization

- **Status:** Accepted
- **Date:** 2026-09-28
- **Decision owner:** Developer (Focused Discussion #4, decisions S1–S7, S10, S18, S25, S26; AD-8; D3; D4)

## Context

The audit APIs require authenticated callers with clearly separated privileges. The prototype must not depend on enterprise identity infrastructure. `recordedBy` must be a stable, non-secret identifier of the caller.

## Decision

- **Static API keys** presented as Bearer credentials. Only SHA-256 hashes are stored, and credentials are compared in constant time. Raw keys are never committed.
- **Configuration** lives in a mounted file outside the database, so a database writer cannot grant itself credentials. See "API-key configuration and application settings (D3)" below.
- **Principal ID** becomes `recordedBy`.
- **Capability-based authorization** is enforced at the API/service boundary, **before resource lookup**.
- **Check order (D4).** Authenticate (`401`), then authorize (`403`), then validate the request (`400`/`422`), then look up resources (`404`/`409`). The order is fixed, so status precedence is deterministic.
- **Authentication failures (D4).** Every authentication failure returns `401 Unauthorized` with `WWW-Authenticate: Bearer` and the same Problem Details structure. This covers a missing Authorization header, a non-Bearer scheme, an empty or malformed token, multiple Authorization headers, and unknown credentials.
- **Transport (D4).** The prototype serves plain HTTP for local use; TLS/HTTPS is a production consideration, not a prototype requirement.
- **Prototype roles.** These are a prototype security boundary, not an assignment requirement or enterprise RBAC:
  - writer → `events:write`;
  - auditor and regulator → `events:read`, `chain:verify`, `export:create`;
  - administrator → `events:read`, `events:redact`, `retention:run`, `checkpoint:create`.
- **Unauthenticated endpoints.** `/health/live` and `/health/ready`; `/docs` and `/openapi.json` are public in the prototype only.
- **Reserved system-event namespace.** Enforced by the service layer; a public caller submitting a reserved type receives `422`.
- **Denied attempts.** Logged operationally, never appended to the chain.

### API-key configuration and application settings (D3)

**Format and settings.**

- The API-key configuration is a separate mounted TOML file outside the database, parsed with the standard library's `tomllib`.
- Other structured configuration, such as the Scenario C vocabulary and required keys, is in its own separate TOML file.
- Scalar and secret settings, and the paths to the structured files, come from environment variables.
- Settings are validated with plain Pydantic v2. No YAML parser, `pydantic-settings`, or other configuration dependency is added.

**API-key entries.**

- Each principal has a non-secret principal ID and exactly **one approved prototype role**. The approved role-to-capability mapping above is authoritative; the file cannot list arbitrary capabilities.
- Principal IDs match `^[a-z][a-z0-9._-]{0,63}$` (developer decision during Phase 1).
- A principal may have one or more key hashes, to support rotation. Each hash is a lowercase hexadecimal SHA-256 digest.
- Raw API keys must be machine-generated with at least 128 bits of entropy. This applies to the raw key, not to the SHA-256 digest.
- Raw API keys are never persisted in PostgreSQL, Git, or logs.

**Authentication.** The service hashes the presented key and compares it with the configured hashes in constant time. A match resolves the principal ID (which becomes `recordedBy`) and the role's capabilities.

**Startup validation.** The service and the CLI fail fast when the configuration is:

- missing or unreadable;
- malformed TOML;
- carrying unknown fields;
- defining a duplicate principal ID or a duplicate key hash;
- using an invalid SHA-256 hash format;
- naming an unknown role or capability;
- leaving a principal with no keys;
- defining no principals; or
- using an invalid or empty principal ID.

Errors may identify the file, principal, and field, but never echo raw keys or hash values.

**Reload.** Configuration is loaded once at startup, and changes require a restart. There is no hot reload.

**Tests and demo material.**

- Tests use deterministic fake API keys whose hashes are computed in fixtures, and require no real secrets.
- Tests check that raw keys and Authorization headers are not logged.
- A committed example configuration may contain intentionally invalid placeholders, so it cannot be deployed with a known credential.
- Real and demo credentials belong in gitignored locations.

**Environment variables (Phase 5 decision D2):**

- `AUDIT_LOG_DATABASE_URL`: the service's database URL, for a login user that is a member of `audit_log_app`, never the migration owner;
- `AUDIT_LOG_API_KEYS_FILE`: the API-key configuration file;
- `AUDIT_LOG_VOCABULARY_FILE`: the Scenario C vocabulary file;
- `AUDIT_LOG_TIMESTAMP_SKEW_SECONDS`: the allowed future skew of a caller `timestamp`, default 300.
- `AUDIT_LOG_RETENTION_WINDOW_SECONDS`, `AUDIT_LOG_RETENTION_BATCH_SIZE`, `AUDIT_LOG_RETENTION_MAX_BATCHES`: retention settings (Phase 9; see requirements FR-5).
- `AUDIT_LOG_CHECKPOINT_STORE_DIR` and `AUDIT_LOG_CHECKPOINT_PUBLIC_KEY_FILE`: the checkpoint store and the trusted checkpoint public key; required (Phase 10; see requirements FR-4).
- `AUDIT_LOG_EXPORT_SIGNING_KEY_FILE` (optional; exports return `503` without it), `AUDIT_LOG_EXPORT_MAX_RECORDS`, and `AUDIT_LOG_EXPORT_MAX_BYTES`: export settings (Phase 11; see requirements FR-7). The export key may not be the checkpoint key pair.

**Checkpoint CLI (Phase 10, decisions CP2 and CP3):** the CLI uses `AUDIT_LOG_CHECKPOINT_DATABASE_URL` (a read-only login), `AUDIT_LOG_API_KEYS_FILE`, `AUDIT_LOG_CHECKPOINT_STORE_DIR`, and `AUDIT_LOG_CHECKPOINT_SIGNING_KEY_FILE`. The operator's raw API key is read from stdin, without echo on a terminal, and never from arguments or environment variables. It is matched by the same constant-time digest comparison as a Bearer key (`authenticate_api_key`); the Authorization-header parsing is not reused. Every authentication failure gives the same message, and `checkpoint:create` is required before the signing key or the database is used.

The migration URL (`AUDIT_LOG_MIGRATION_DATABASE_URL`) is separate and is never part of the service's configuration (ADR-0009).

**Deferred:**

- filesystem paths;
- the Scenario C vocabulary names;
- `.gitignore` details;
- the demo-key generation mechanism.

## Consequences

- The boundary is explicit and testable, and could be replaced by an identity provider later.
- Compromise of a key allows actions within its capabilities, attributed via `recordedBy`.
- Writers cannot read the audit log; administrators cannot export.
- Adding, removing, or rotating keys requires editing the mounted file and restarting the service or CLI.
- Unsalted SHA-256 is adequate only because raw keys are high-entropy and machine-generated; human-chosen secrets are not supported.

## Alternatives considered

- **Locally issued JWTs:** add token issuance and expiry handling for little benefit.
- **Mutual TLS:** heavy for a local prototype.
- **OIDC identity provider:** out of scope (requirements §7).
- **API keys stored in the database:** rejected, so that a database writer cannot create credentials.
- **YAML or JSON configuration:** YAML would add a dependency; JSON lacks comments and silently accepts duplicate keys. TOML was chosen (D3).
- **`pydantic-settings`:** not needed; plain Pydantic v2 validation is sufficient (D3).
- **Capability lists per principal:** rejected; roles keep the approved mapping authoritative (D3).
- **Hot reload of configuration:** rejected; not required, and it adds concurrency and validation edge cases (D3).
- **RFC 6750 granular errors** (`400 invalid_request`, `401` with `error="invalid_token"`): not adopted. A uniform `401` gives callers no indication of why authentication failed (D4).
- **Leaving the validation order as an implementation choice:** not adopted. A fixed order makes statuses testable and gives unauthorized callers no validation feedback (D4).

## References

- [architecture.md](../architecture.md) Sections 5, 6, 17
- [requirements.md](../requirements.md) FR-1, NFR-2
