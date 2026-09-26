# Clarified Requirements - Audit Log Service
  
## 1. Problem statement
 
Build a service that records an append-only history of audit events and makes any later modification, deletion, insertion, reordering or rewrite of stored records detectable. Callers write events and query them; auditors and regulators can verify the integrity of the whole history, or of an exported subset, without trusting the database. Sensitive values must be removable for privacy without breaking that integrity guarantee.
 
## 2. Actors
 
| Actor | Needs |
|---|---|
| Writing service | Append events; never change or delete them |
| Auditor | Query events, verify the chain, export verifiable bundles |
| Regulator | See who accessed client account data, with provable records |
| Admin | Redact sensitive fields, run retention, create checkpoints |
 
## 3. Ambiguities and decisions
 
| # | Ambiguity | Options considered | Decision | Why |
|---|---|---|---|---|
| 1 | Event timestamp: caller or server? | Caller-supplied · server-assigned · both | Both: server `recorded_at` is authoritative and always hashed; caller `occurred_at` is optional and hashed if given | The server clock can't be spoofed by callers, but the business time of the event is still useful for queries |
| 2 | Event fields | Free-form · fixed minimal set | Fixed: `action`, `actor`, `resource_type`, `resource_id`, `details` (object), optional `occurred_at`; unknown fields rejected | Predictable schema, clear hash input, strict validation |
| 3 | Limits on `details` | None · max size and depth | Max 16 KB serialized and nesting depth 8 (configurable) | Protects storage and hashing from abuse; generous for audit data |
| 4 | Pagination | Offset · keyset (cursor) | Keyset on sequence number, opaque cursor | Stable under concurrent writes; stays fast at any size |
| 5 | What "hash of its own content" covers | Event fields only · fields + server metadata | All event fields including `recorded_at`, via a per-field commitment root; the record hash also covers sequence number and previous hash | Any change to any stored field, or to position in the chain, changes a hash |
| 6 | Which tampering must be detected | Edits only · edits, deletes, inserts, reorders, full rewrite, tail truncation | All of them | A plain hash chain alone misses deletions at the end and full rewrites; the design must close those gaps |
| 7 | Detecting a full rewrite (all later hashes recomputed) | Out of scope · signed checkpoints · external anchoring | Ed25519-signed checkpoints every N records and on demand; key kept outside the database; checkpoints also written to an external log | Someone with database access can recompute hashes but cannot forge a signature |
| 8 | Ordering under concurrent writes | Chain-head row lock · single-writer queue | Lock a single chain-head row per append; gap-free sequence numbers | Simple, correct, testable; throughput limit documented |
| 9 | Retention: what remains after archiving? | Delete rows · soft-delete flag · archive stubs keeping hashes | Archive stubs: details cleared, sequence and hashes kept, `archived_at` set | Deleting rows would break the chain; stubs let verification pass without false alarms |
| 10 | Redaction: which fields, who, when? | Fixed fields at write time · any field later | Any leaf field in `details`, later, by an admin with a recorded reason | Sensitive data is often discovered after the fact; per-field salted commitments make any field redactable |
| 11 | Export scope and format | By actor · by resource · both; JSON bundle | Either one actor or one resource per export; signed JSON bundle with the hashes needed to link records to a signed checkpoint | Recipients can verify offline with only the bundle and the public key |
| 12 | Authentication and roles | None · API key · JWT with roles | JWT with roles `writer`, `auditor`, `regulator`, `admin` (development tokens locally) | Needed for Scenario C and for least-privilege access |
| 13 | Duplicate writes on client retry | Accept duplicates · idempotency key | Out of scope for v1; documented as future work | Keeps v1 focused; duplicates are still tamper-evident, just not deduplicated |
| 14 | Verification cost on large chains | Full walk only · range · from checkpoint | Full streaming walk in v1; range verification anchored at a checkpoint as a stretch | Correctness first; measured time documented |
 
## 4. Functional requirements
 
- **FR-1 Write:** `POST /events` appends one event and returns its sequence number, timestamps and hashes. No update or delete operation exists at any layer.
- **FR-2 Query:** `GET /events` filters by any combination of actor, action, resource type, resource ID and time range, with keyset pagination.
- **FR-3 Verify:** `GET /verify` walks the full chain and reports whether it is intact; if not, the first inconsistent record and the violation type (edited content, broken link, missing record, invalid or mismatched checkpoint, truncated tail).
- **FR-4 Checkpoints:** the service signs checkpoints every N records and on demand; verification checks them.
- **FR-5 Retention:** a command archives records older than a configurable window into stubs; verification still passes and reports the archived count.
- **FR-6 Redaction:** an admin can redact named fields of an event with a reason; values are removed, verification still passes, and the redaction is itself recorded as an event.
- **FR-7 Export:** `GET /export` returns a signed, self-contained bundle for one actor or one resource; a standalone script verifies it without the service.
- **FR-8 Compliance access reporting:** regulators must be able to audit access to client account data. This requirement is intentionally vague in the brief and will be clarified before any design or code; the working assumption is that every read of client account data, and of the audit log itself, is recorded and reportable.
## 5. Non-functional requirements
 
- **Integrity:** append-only is enforced in the database (roles and triggers), not only in the API.
- **Security:** least-privilege database roles; secrets and the signing key never stored in the database or in git; no personal data in logs; dependency and secret scanning in CI.
- **Performance:** single-node target of at least 200 writes/second and full verification of 100,000 records in under 30 seconds on a laptop; measured values recorded in the engineering summary.
- **Operability:** one-command local run with Docker Compose; no cloud accounts needed.
- **Observability:** structured JSON logs with request IDs; health and readiness endpoints.
- **Quality:** typed code, linting, unit, property and integration tests against real PostgreSQL, coverage of at least 85%.
## 6. Assumptions
 
- A single logical chain for all events (no multi-tenant partitioning in v1).
- One service instance writes at a time through the database lock; horizontal scaling is future work.
- The signing key is supplied by the operator; in production it would live in a key management service.
- Event `details` are JSON objects containing only JSON-safe values.
- Development JWTs are acceptable locally; production would use an identity provider.
## 7. Out of scope
 
- User interface; the API and scripts are the interface.
- Multi-tenant chains, cross-region replication and horizontal write scaling.
- Cloud deployment and infrastructure as code (design described, not built).
- Idempotency keys for retried writes.
- External timestamping authority for checkpoints (a local external log file stands in).
## 8. Open questions for Product
 
1. Which regulation or regulator applies, and what retention period does it require?
2. Is "access" limited to reads, or does it include writes and exports?
3. Must regulators' own reads of the audit log also be audited? (Assumed yes.)
4. Who is authorised to redact, and does redaction need a second approver?
5. What throughput and history size should the service support in production?
 