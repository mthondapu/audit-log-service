"""Signed exports (requirements FR-7, ADR-0007, Phase 11 decisions E1 to E17).

`create_export` runs after the caller has authenticated, authorized `export:create`, validated the
scope, and confirmed that the export signing key is configured. It then:

1. reads and validates the checkpoint store, before the snapshot opens (CP16);
2. in one REPEATABLE READ, READ ONLY snapshot: reads `generatedAt` from the database clock, selects
   the matching records (archived ones included) and refuses more than the record limit, verifies
   the whole chain against the latest checkpoint, and reads the retention evidence and each
   record's redacted paths;
3. refuses a chain that is not intact (409), before anything is signed or appended;
4. builds and signs the manifest, and serializes the bundle, refusing more than the byte limit; and
5. only then appends the `AUDIT_LOG_EXPORT` event, in its own READ COMMITTED transaction under the
   append lock. Its sequence is above `asOfSequence`, so it is never part of its own export. If it
   cannot be appended, the error propagates and no bundle is returned.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import Engine, func, select

from audit_log_service.application.events import (
    MAX_IDENTIFIER_LENGTH,
    TYPE_PATTERN,
    SubmissionError,
    describe_schema_errors,
    is_storable_text,
)
from audit_log_service.application.retention import (
    RETENTION_ACTOR_ID,
    RETENTION_RESOURCE_ID,
    RETENTION_RESOURCE_TYPE,
)
from audit_log_service.application.views import event_views
from audit_log_service.integrity.canonical import JsonValue
from audit_log_service.integrity.checkpoints import key_id
from audit_log_service.integrity.exports import (
    SCOPE_FIELDS,
    ExportRecord,
    Manifest,
    ManifestRecord,
    encode_bundle,
    retention_evidence,
    sign_manifest,
)
from audit_log_service.integrity.timestamps import format_timestamp
from audit_log_service.integrity.verification import ChainHead, verify_chain
from audit_log_service.persistence.audit_log import (
    EventFilters,
    NewEvent,
    append_event,
    load_chain_entries,
    query_entries,
    read_only_snapshot,
)
from audit_log_service.persistence.checkpoint_store import load_latest_checkpoint

EXPORT_EVENT_TYPE = "AUDIT_LOG_EXPORT"
SCOPE_ERROR = (
    "The export scope must be exactly one of {actorId}, {resourceId}, or "
    "{resourceId, resourceType}."
)

Identifier = Annotated[str, Field(min_length=1, max_length=MAX_IDENTIFIER_LENGTH)]


class ExportRequest(BaseModel):
    """The body of `POST /audit/exports`: exactly one allowed scope. Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    actorId: Identifier | None = None
    resourceId: Identifier | None = None
    resourceType: Annotated[str, Field(pattern=TYPE_PATTERN)] | None = None


class ExportTooLargeError(Exception):
    """The export exceeds the configured record or byte limit (422)."""


class ExportVerificationError(Exception):
    """Pre-signing verification failed, so nothing was signed or appended (409)."""


@dataclass(frozen=True, slots=True)
class ExportPolicy:
    max_records: int
    max_bytes: int


@dataclass(frozen=True, slots=True)
class ExportResult:
    body: bytes = field(repr=False)
    record_count: int


def parse_export_request(document: object) -> dict[str, str]:
    """Validate the body with the FR-2 identifier and type rules (E16) and return the scope."""
    try:
        request = ExportRequest.model_validate(document)
    except ValidationError as error:
        raise SubmissionError(
            describe_schema_errors(error, set(ExportRequest.model_fields))
        ) from None
    scope = {
        name: value
        for name, value in request.model_dump().items()
        if name in request.model_fields_set
    }
    if frozenset(scope) not in SCOPE_FIELDS or not all(
        isinstance(value, str) for value in scope.values()
    ):
        raise SubmissionError(SCOPE_ERROR)
    for name, value in scope.items():
        if not is_storable_text(value):
            raise SubmissionError(f"{name} contains a character that is not allowed")
    return scope


def create_export(
    engine: Engine,
    scope: Mapping[str, str],
    private_key: Ed25519PrivateKey,
    policy: ExportPolicy,
    checkpoint_store_dir: Path,
    checkpoint_public_key: Ed25519PublicKey,
    requester: str,
) -> ExportResult:
    """Build, sign, and record an export of every record matching `scope`."""
    latest = load_latest_checkpoint(checkpoint_store_dir, checkpoint_public_key)
    anchor = (
        None
        if latest is None
        else ChainHead(
            sequence=latest.checkpoint.sequence, record_hash=latest.checkpoint.record_hash
        )
    )
    filters = EventFilters(
        actor_id=scope.get("actorId"),
        resource_type=scope.get("resourceType"),
        resource_id=scope.get("resourceId"),
        include_archived=True,
    )
    with read_only_snapshot(engine) as snapshot:
        generated_at = snapshot.execute(select(func.clock_timestamp())).scalar_one()
        selected = query_entries(snapshot, filters, 0, policy.max_records + 1)
        if len(selected) > policy.max_records:
            raise ExportTooLargeError
        chain = load_chain_entries(snapshot)
        verification = verify_chain(chain, anchor)
        if not verification.intact:
            raise ExportVerificationError
        evidence = retention_evidence(chain)
        views = event_views(snapshot, selected, 0 if evidence is None else evidence.up_to_sequence)

    head = verification.head
    records = [
        ExportRecord(
            entry=view.entry, archived=view.archived, redacted_paths=tuple(view.redacted_paths)
        )
        for view in views
    ]
    manifest = Manifest(
        scope=dict(scope),
        as_of_sequence=0 if head is None else head.sequence,
        as_of_record_hash=None if head is None else head.record_hash,
        generated_at=format_timestamp(generated_at),
        requested_by=requester,
        record_count=len(records),
        records=tuple(
            ManifestRecord(
                sequence=record.entry.record.sequence,
                id=record.entry.record.content.id,
                record_hash=record.entry.record.record_hash,
            )
            for record in records
        ),
        retention=evidence,
        key_id=key_id(private_key.public_key()),
    )
    signature = sign_manifest(private_key, manifest)
    body = encode_bundle(manifest, signature, records)
    if len(body) > policy.max_bytes:
        raise ExportTooLargeError

    with engine.begin() as connection:
        append_event(connection, _export_event(manifest, signature))
    return ExportResult(body=body, record_count=len(records))


def _export_event(manifest: Manifest, signature: str) -> NewEvent:
    """The export audit event (E9): identity from the scope, fixed server values otherwise."""
    scope = manifest.scope
    scope_json: dict[str, JsonValue] = {name: value for name, value in scope.items()}
    payload: dict[str, JsonValue] = {
        "scope": scope_json,
        "asOfSequence": manifest.as_of_sequence,
        "recordCount": manifest.record_count,
        "keyId": manifest.key_id,
        "manifestSignature": signature,
    }
    return NewEvent(
        event_type=EXPORT_EVENT_TYPE,
        actor_id=scope.get("actorId", RETENTION_ACTOR_ID),
        resource_type=scope.get("resourceType", RETENTION_RESOURCE_TYPE),
        resource_id=scope.get("resourceId", RETENTION_RESOURCE_ID),
        timestamp=None,
        recorded_by=manifest.requested_by,
        payload=payload,
    )
