"""Signed export bundles and their offline verification (FR-7, ADR-0007, Phase 11 E1 to E15).

A bundle is ``{"manifest": {...}, "signature": "<128 lowercase hex>", "records": [...]}``. Ed25519
signs ``UTF-8("audit-log/v1/manifest") || 0x00 || RFC8785(manifest)`` directly, with no pre-hash;
`keyId` (the SHA-256 of the raw public key) is inside the manifest. The records are outside the
signature: the verifier recomputes their hashes and matches them against the signed record list.

Each exported record carries its hash inputs: identity fields, `committedPayload` (the committed
structure), and `payloadValues`, mapping the JSON Pointer of each available value to its `value`
and `salt`. Redacted values are absent; archived records carry no values. `archived` and
`redactedPaths` are derived fields and are never verified.

Verification checks, in order, the bundle structure, the key, and the signature; only then does it
trust the manifest and check each record (`ExportViolationType`, one violation per record, first in
enum order). A missing value is authorized by the signed retention evidence (records at or below
`upToSequence`) or by an included, valid, later redaction event (FR-3). Supplied checkpoints are
used only where they anchor directly to signed evidence (L-D1, `anchor_checkpoint`).

This module has no web, database, or configuration dependency: the offline verifier uses it.
"""

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import pairwise
from typing import Any, NoReturn, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from audit_log_service.integrity.canonical import (
    MANIFEST_LABEL,
    MAX_SAFE_INTEGER,
    SCHEME,
    JsonValue,
    canonicalize,
    is_sha256_hex,
    labeled_bytes,
)
from audit_log_service.integrity.checkpoints import PRINCIPAL_ID, Checkpoint, key_id
from audit_log_service.integrity.commitments import PayloadValue, values_open_commitments
from audit_log_service.integrity.hashing import GENESIS_PREVIOUS_HASH, AuditRecord, EventContent
from audit_log_service.integrity.timestamps import is_canonical_timestamp
from audit_log_service.integrity.verification import (
    RETENTION_EVENT_TYPE,
    ChainEntry,
    content_hash_matches,
    has_unauthorized_missing_value,
    record_hash_matches,
    redaction_authorizations,
)

FORMAT = "audit-log-export/v1"
COMPLETENESS = "ALL_MATCHING_RECORDS_INCLUDING_ARCHIVED_AS_OF_SEQUENCE"
# The largest bundle a verifier reads, and the largest configurable export size.
MAX_BUNDLE_BYTES = 1024 * 1024 * 1024
SCOPE_FIELDS = (
    frozenset({"actorId"}),
    frozenset({"resourceId"}),
    frozenset({"resourceId", "resourceType"}),
)
_SIGNATURE_LENGTH = 128
_BUNDLE_KEYS = frozenset({"manifest", "signature", "records"})
_MANIFEST_KEYS = frozenset(
    {
        "format",
        "scheme",
        "scope",
        "asOfSequence",
        "asOfRecordHash",
        "generatedAt",
        "completeness",
        "requestedBy",
        "recordCount",
        "records",
        "retention",
        "keyId",
    }
)
_LISTED_KEYS = frozenset({"sequence", "id", "recordHash"})
_RETENTION_KEYS = frozenset(
    {"upToSequence", "cutoff", "eventSequence", "eventId", "eventRecordHash"}
)
_RECORD_KEYS = frozenset(
    {
        "id",
        "sequence",
        "eventType",
        "actorId",
        "resourceType",
        "resourceId",
        "timestamp",
        "recordedAt",
        "recordedBy",
        "committedPayload",
        "payloadValues",
        "previousHash",
        "contentHash",
        "recordHash",
        "archived",
        "redactedPaths",
    }
)
_VALUE_KEYS = frozenset({"value", "salt"})
_SCOPE_ATTRIBUTES = {
    "actorId": "actor_id",
    "resourceId": "resource_id",
    "resourceType": "resource_type",
}


class ExportViolationType(StrEnum):
    """Export verification failures (E15). Per record, the first in this order is reported."""

    MANIFEST_INVALID = "MANIFEST_INVALID"
    KEY_MISMATCH = "KEY_MISMATCH"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    RECORD_LIST_MISMATCH = "RECORD_LIST_MISMATCH"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    AS_OF_MISMATCH = "AS_OF_MISMATCH"
    PREVIOUS_HASH_MISMATCH = "PREVIOUS_HASH_MISMATCH"
    CONTENT_HASH_MISMATCH = "CONTENT_HASH_MISMATCH"
    PAYLOAD_VALUE_MISMATCH = "PAYLOAD_VALUE_MISMATCH"
    PAYLOAD_VALUE_MISSING = "PAYLOAD_VALUE_MISSING"
    RECORD_HASH_MISMATCH = "RECORD_HASH_MISMATCH"


class AnchorResult(StrEnum):
    """How a supplied, valid checkpoint relates to an export (L-D1)."""

    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class BundleFormatError(Exception):
    """The bundle is not well-formed. Carries no content from the bundle."""


@dataclass(frozen=True, slots=True)
class RetentionEvidence:
    """The latest applicable retention event as of the export snapshot (E4)."""

    up_to_sequence: int
    cutoff: str
    event_sequence: int
    event_id: str
    event_record_hash: str

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "upToSequence": self.up_to_sequence,
            "cutoff": self.cutoff,
            "eventSequence": self.event_sequence,
            "eventId": self.event_id,
            "eventRecordHash": self.event_record_hash,
        }


@dataclass(frozen=True, slots=True)
class ManifestRecord:
    sequence: int
    id: str
    record_hash: str


@dataclass(frozen=True, slots=True)
class Manifest:
    """The signed manifest (E1). `record_count` is kept as signed, so a verifier can compare it."""

    scope: Mapping[str, str] = field(repr=False)
    as_of_sequence: int
    as_of_record_hash: str | None
    generated_at: str
    requested_by: str
    record_count: int
    records: tuple[ManifestRecord, ...]
    retention: RetentionEvidence | None
    key_id: str

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "format": FORMAT,
            "scheme": SCHEME,
            "scope": dict(self.scope),
            "asOfSequence": self.as_of_sequence,
            "asOfRecordHash": self.as_of_record_hash,
            "generatedAt": self.generated_at,
            "completeness": COMPLETENESS,
            "requestedBy": self.requested_by,
            "recordCount": self.record_count,
            "records": [
                {"sequence": item.sequence, "id": item.id, "recordHash": item.record_hash}
                for item in self.records
            ],
            "retention": None if self.retention is None else self.retention.to_json(),
            "keyId": self.key_id,
        }


@dataclass(frozen=True, slots=True)
class ExportRecord:
    """A record as exported. Archived records never carry values (E3)."""

    entry: ChainEntry = field(repr=False)
    archived: bool
    redacted_paths: tuple[str, ...]

    def to_json(self) -> dict[str, JsonValue]:
        record = self.entry.record
        content = record.content
        values: dict[str, JsonValue] = (
            {}
            if self.archived
            else {
                pointer: {"value": json.loads(stored.canonical_text), "salt": stored.salt}
                for pointer, stored in sorted(self.entry.payload_values.items())
            }
        )
        return {
            "id": content.id,
            "sequence": record.sequence,
            "eventType": content.event_type,
            "actorId": content.actor_id,
            "resourceType": content.resource_type,
            "resourceId": content.resource_id,
            "timestamp": content.timestamp,
            "recordedAt": content.recorded_at,
            "recordedBy": content.recorded_by,
            "committedPayload": content.payload,
            "payloadValues": values,
            "previousHash": record.previous_hash,
            "contentHash": record.content_hash,
            "recordHash": record.record_hash,
            "archived": self.archived,
            "redactedPaths": list(self.redacted_paths),
        }


@dataclass(frozen=True, slots=True)
class ParsedBundle:
    manifest: Manifest
    signature: str
    records: tuple[ExportRecord, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class ExportViolation:
    type: ExportViolationType
    sequence: int | None
    record_id: str | None


@dataclass(frozen=True, slots=True)
class ExportVerification:
    """The result. `manifest` is set only when its signature verified, so it can be trusted."""

    valid: bool
    manifest: Manifest | None
    violation_count: int
    first_violation: ExportViolation | None


def manifest_signing_input(manifest: Manifest) -> bytes:
    """The bytes Ed25519 signs: UTF-8(label) || 0x00 || RFC8785(manifest)."""
    return labeled_bytes(MANIFEST_LABEL, manifest.to_json())


def sign_manifest(private_key: Ed25519PrivateKey, manifest: Manifest) -> str:
    """Sign a manifest whose `keyId` identifies the signing key; return the hex signature."""
    if manifest.key_id != key_id(private_key.public_key()):
        raise ValueError("the manifest keyId does not identify the signing key")
    return private_key.sign(manifest_signing_input(manifest)).hex()


def encode_bundle(manifest: Manifest, signature: str, records: Sequence[ExportRecord]) -> bytes:
    """The bundle as RFC 8785 JSON bytes."""
    bundle: dict[str, JsonValue] = {
        "manifest": manifest.to_json(),
        "signature": signature,
        "records": [record.to_json() for record in records],
    }
    return canonicalize(bundle)


def retention_evidence(entries: Sequence[ChainEntry]) -> RetentionEvidence | None:
    """The latest applicable retention event in a verified chain, or None.

    Applicable as for the archived boundary (FR-5): an `AUDIT_LOG_RETENTION` event whose
    `upToSequence` is an integer from 1 to just below its own sequence. The latest such event keeps
    its own values, so its `cutoff` is readable; a `ValueError` otherwise means the chain was not
    verified first.
    """
    for entry in reversed(entries):
        record = entry.record
        if record.content.event_type != RETENTION_EVENT_TYPE:
            continue
        up_to = _stored_value(entry, "/upToSequence")
        if type(up_to) is not int or not 1 <= up_to < record.sequence:
            continue
        cutoff = _stored_value(entry, "/cutoff")
        if not isinstance(cutoff, str) or not is_canonical_timestamp(cutoff):
            raise ValueError("the applicable retention event has no readable cutoff")
        return RetentionEvidence(
            up_to_sequence=up_to,
            cutoff=cutoff,
            event_sequence=record.sequence,
            event_id=record.content.id,
            event_record_hash=record.record_hash,
        )
    return None


def verify_export(data: bytes, public_key: Ed25519PublicKey) -> ExportVerification:
    """Verify a bundle with the trusted export public key (FR-7, E12, E15)."""
    try:
        bundle = parse_bundle(data)
    except BundleFormatError:
        return _rejected(ExportViolationType.MANIFEST_INVALID)
    manifest = bundle.manifest
    if manifest.key_id != key_id(public_key):
        return _rejected(ExportViolationType.KEY_MISMATCH)
    try:
        public_key.verify(bytes.fromhex(bundle.signature), manifest_signing_input(manifest))
    except InvalidSignature:
        return _rejected(ExportViolationType.SIGNATURE_INVALID)
    violations = _record_violations(manifest, bundle.records)
    return ExportVerification(
        valid=not violations,
        manifest=manifest,
        violation_count=len(violations),
        first_violation=violations[0] if violations else None,
    )


def anchor_checkpoint(verification: ExportVerification, checkpoint: Checkpoint) -> AnchorResult:
    """Relate a checkpoint whose signature was already verified to the export (L-D1).

    It is compared with the signed `asOfRecordHash` when its sequence is `asOfSequence`, or with the
    signed record list entry when its sequence is an included record's. Otherwise, or when the
    manifest could not be trusted, it is not applicable.
    """
    manifest = verification.manifest
    if manifest is None:
        return AnchorResult.NOT_APPLICABLE
    expected: str | None = None
    if checkpoint.sequence == manifest.as_of_sequence:
        expected = manifest.as_of_record_hash
    else:
        for item in manifest.records:
            if item.sequence == checkpoint.sequence:
                expected = item.record_hash
    if expected is None:
        return AnchorResult.NOT_APPLICABLE
    return AnchorResult.MATCH if checkpoint.record_hash == expected else AnchorResult.MISMATCH


def parse_bundle(data: bytes) -> ParsedBundle:
    """Parse a bundle strictly: UTF-8 JSON, no duplicate keys, no NaN or infinity, exact keys."""
    if len(data) > MAX_BUNDLE_BYTES:
        _malformed()
    try:
        document: object = json.loads(
            data.decode("utf-8"), object_pairs_hook=_unique_keys, parse_constant=_reject_constant
        )
    except (ValueError, RecursionError):
        _malformed()
    bundle = _object(document, _BUNDLE_KEYS)
    signature = bundle["signature"]
    if not (
        isinstance(signature, str)
        and len(signature) == _SIGNATURE_LENGTH
        and all(c in "0123456789abcdef" for c in signature)
    ):
        _malformed()
    records = bundle["records"]
    if not isinstance(records, list):
        _malformed()
    return ParsedBundle(
        manifest=_manifest(bundle["manifest"]),
        signature=signature,
        records=tuple(_record(item) for item in cast(list[object], records)),
    )


def _rejected(violation: ExportViolationType) -> ExportVerification:
    return ExportVerification(
        valid=False,
        manifest=None,
        violation_count=1,
        first_violation=ExportViolation(violation, None, None),
    )


def _record_violations(
    manifest: Manifest, records: Sequence[ExportRecord]
) -> list[ExportViolation]:
    listed = manifest.records
    violations: list[ExportViolation] = []
    ascending = all(a.sequence < b.sequence for a, b in pairwise(listed))
    if manifest.record_count != len(listed) or not ascending:
        violations.append(ExportViolation(ExportViolationType.RECORD_LIST_MISMATCH, None, None))
    if len(records) != len(listed):
        violations.append(ExportViolation(ExportViolationType.RECORD_LIST_MISMATCH, None, None))
        return violations

    entries = [record.entry for record in records]
    checked: list[ExportViolationType | None] = []
    for index, (entry, item) in enumerate(zip(entries, listed, strict=True)):
        predecessor = entries[index - 1].record if index else None
        checked.append(_first_violation(manifest, entry, item, predecessor))

    authorized = redaction_authorizations(entries, [v is None for v in checked])
    retained_up_to = 0 if manifest.retention is None else manifest.retention.up_to_sequence
    for entry, violation_type in zip(entries, checked, strict=True):
        record = entry.record
        outranks_missing = violation_type is not None and (
            _PRECEDENCE.index(violation_type) < _MISSING_RANK
        )
        if (
            not outranks_missing
            and record.sequence > retained_up_to
            and has_unauthorized_missing_value(entry, authorized)
        ):
            violation_type = ExportViolationType.PAYLOAD_VALUE_MISSING
        if violation_type is not None:
            violations.append(ExportViolation(violation_type, record.sequence, record.content.id))
    return violations


def _first_violation(
    manifest: Manifest,
    entry: ChainEntry,
    item: ManifestRecord,
    predecessor: AuditRecord | None,
) -> ExportViolationType | None:
    record = entry.record
    content = record.content
    if (record.sequence, content.id, record.record_hash) != (
        item.sequence,
        item.id,
        item.record_hash,
    ):
        return ExportViolationType.RECORD_LIST_MISMATCH
    if any(
        getattr(content, _SCOPE_ATTRIBUTES[name]) != value for name, value in manifest.scope.items()
    ):
        return ExportViolationType.SCOPE_MISMATCH
    if record.sequence > manifest.as_of_sequence or (
        record.sequence == manifest.as_of_sequence
        and record.record_hash != manifest.as_of_record_hash
    ):
        return ExportViolationType.AS_OF_MISMATCH
    if (record.sequence == 1 and record.previous_hash != GENESIS_PREVIOUS_HASH) or (
        predecessor is not None
        and predecessor.sequence == record.sequence - 1
        and record.previous_hash != predecessor.record_hash
    ):
        return ExportViolationType.PREVIOUS_HASH_MISMATCH
    if not content_hash_matches(record):
        return ExportViolationType.CONTENT_HASH_MISMATCH
    if not values_open_commitments(content.payload, entry.payload_values):
        return ExportViolationType.PAYLOAD_VALUE_MISMATCH
    if not record_hash_matches(record):
        return ExportViolationType.RECORD_HASH_MISMATCH
    return None


_PRECEDENCE = list(ExportViolationType)
_MISSING_RANK = _PRECEDENCE.index(ExportViolationType.PAYLOAD_VALUE_MISSING)


def _stored_value(entry: ChainEntry, pointer: str) -> object:
    stored = entry.payload_values.get(pointer)
    if stored is None:
        return None
    try:
        return json.loads(stored.canonical_text)
    except ValueError:
        return None


def _manifest(value: object) -> Manifest:
    document = _object(value, _MANIFEST_KEYS)
    scope = document["scope"]
    if not (
        isinstance(scope, dict)
        and frozenset(cast(dict[str, Any], scope)) in SCOPE_FIELDS
        and all(isinstance(v, str) and v for v in cast(dict[str, Any], scope).values())
    ):
        _malformed()
    as_of = _integer(document["asOfSequence"], minimum=0)
    as_of_hash = document["asOfRecordHash"]
    if not ((as_of == 0 and as_of_hash is None) or (as_of > 0 and is_sha256_hex(as_of_hash))):
        _malformed()
    records = document["records"]
    retention = document["retention"]
    if not (
        document["format"] == FORMAT
        and document["scheme"] == SCHEME
        and document["completeness"] == COMPLETENESS
        and is_canonical_timestamp(document["generatedAt"])
        and _is_principal(document["requestedBy"])
        and is_sha256_hex(document["keyId"])
        and isinstance(records, list)
    ):
        _malformed()
    return Manifest(
        scope=cast(dict[str, str], scope),
        as_of_sequence=as_of,
        as_of_record_hash=cast(str | None, as_of_hash),
        generated_at=document["generatedAt"],
        requested_by=document["requestedBy"],
        record_count=_integer(document["recordCount"], minimum=0),
        records=tuple(_listed(item) for item in cast(list[object], records)),
        retention=None if retention is None else _retention(retention, as_of),
        key_id=document["keyId"],
    )


def _listed(value: object) -> ManifestRecord:
    document = _object(value, _LISTED_KEYS)
    if not (isinstance(document["id"], str) and is_sha256_hex(document["recordHash"])):
        _malformed()
    return ManifestRecord(
        sequence=_integer(document["sequence"], minimum=1),
        id=document["id"],
        record_hash=document["recordHash"],
    )


def _retention(value: object, as_of: int) -> RetentionEvidence:
    document = _object(value, _RETENTION_KEYS)
    up_to = _integer(document["upToSequence"], minimum=1)
    event_sequence = _integer(document["eventSequence"], minimum=1)
    if not (
        up_to < event_sequence <= as_of
        and is_canonical_timestamp(document["cutoff"])
        and isinstance(document["eventId"], str)
        and is_sha256_hex(document["eventRecordHash"])
    ):
        _malformed()
    return RetentionEvidence(
        up_to_sequence=up_to,
        cutoff=document["cutoff"],
        event_sequence=event_sequence,
        event_id=document["eventId"],
        event_record_hash=document["eventRecordHash"],
    )


def _record(value: object) -> ExportRecord:
    document = _object(value, _RECORD_KEYS)
    text_fields = (
        "id",
        "eventType",
        "actorId",
        "resourceType",
        "resourceId",
        "recordedAt",
        "recordedBy",
        "previousHash",
        "contentHash",
        "recordHash",
    )
    timestamp = document["timestamp"]
    payload = document["committedPayload"]
    redacted = document["redactedPaths"]
    if not (
        all(isinstance(document[name], str) for name in text_fields)
        and (timestamp is None or isinstance(timestamp, str))
        and isinstance(payload, dict)
        and isinstance(document["archived"], bool)
        and isinstance(redacted, list)
        and all(isinstance(path, str) for path in cast(list[object], redacted))
    ):
        _malformed()
    content = EventContent(
        id=document["id"],
        event_type=document["eventType"],
        actor_id=document["actorId"],
        resource_type=document["resourceType"],
        resource_id=document["resourceId"],
        timestamp=timestamp,
        recorded_at=document["recordedAt"],
        recorded_by=document["recordedBy"],
        payload=cast(dict[str, JsonValue], payload),
    )
    record = AuditRecord(
        sequence=_integer(document["sequence"], minimum=1),
        previous_hash=document["previousHash"],
        content_hash=document["contentHash"],
        record_hash=document["recordHash"],
        content=content,
    )
    return ExportRecord(
        entry=ChainEntry(record, _payload_values(document["payloadValues"])),
        archived=document["archived"],
        redacted_paths=tuple(cast(list[str], redacted)),
    )


def _payload_values(value: object) -> dict[str, PayloadValue]:
    if not isinstance(value, dict):
        _malformed()
    values: dict[str, PayloadValue] = {}
    for pointer, item in cast(dict[str, object], value).items():
        stored = _object(item, _VALUE_KEYS)
        if not isinstance(stored["salt"], str):
            _malformed()
        # The value is kept as JSON text; its commitment check parses it and rejects anything
        # that is not an in-domain scalar.
        values[pointer] = PayloadValue(
            canonical_text=json.dumps(stored["value"]), salt=stored["salt"]
        )
    return values


def _integer(value: object, *, minimum: int) -> int:
    if type(value) is not int or not minimum <= value <= MAX_SAFE_INTEGER:
        _malformed()
    return value


def _is_principal(value: object) -> bool:
    return isinstance(value, str) and PRINCIPAL_ID.fullmatch(value) is not None


def _object(value: object, keys: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(cast(dict[str, Any], value)) != keys:
        _malformed()
    return cast(dict[str, Any], value)


def _malformed() -> NoReturn:
    raise BundleFormatError("the export bundle is malformed")


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_name: str) -> NoReturn:
    raise ValueError("non-finite number")
