"""Export bundles: manifest signing, strict parsing, and offline verification (FR-7, E1 to E15).

Keys are generated in memory for each test. Bundles are built here the way the service builds
them, from a chain made with the integrity primitives, so every check runs without a database.
"""

import copy
import dataclasses
import json
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st

from audit_log_service.integrity import exports as exports_module
from audit_log_service.integrity.canonical import MANIFEST_LABEL, JsonValue
from audit_log_service.integrity.checkpoints import Checkpoint, key_id
from audit_log_service.integrity.commitments import commit_payload
from audit_log_service.integrity.exports import (
    COMPLETENESS,
    FORMAT,
    AnchorResult,
    BundleFormatError,
    ExportRecord,
    ExportVerification,
    ExportViolationType,
    Manifest,
    ManifestRecord,
    RetentionEvidence,
    anchor_checkpoint,
    encode_bundle,
    manifest_signing_input,
    parse_bundle,
    retention_evidence,
    sign_manifest,
    verify_export,
)
from audit_log_service.integrity.hashing import GENESIS_PREVIOUS_HASH, EventContent, seal_record
from audit_log_service.integrity.timestamps import format_timestamp
from audit_log_service.integrity.verification import (
    REDACTION_EVENT_TYPE,
    RETENTION_EVENT_TYPE,
    ChainEntry,
)

X = ExportViolationType
BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)
GENERATED_AT = "2026-09-28T12:00:00.000000Z"
CUTOFF = "2026-06-01T00:00:00.000000Z"
Chain = list[ChainEntry]
Scope = dict[str, str]
PAYLOAD: dict[str, JsonValue] = {"card": "4111", "tags": ["a", 1.5, None, True]}


# --- Chain builders ------------------------------------------------------------------------------


def append(
    chain: Chain,
    payload: dict[str, JsonValue] | None = None,
    *,
    event_type: str = "ORDER_PLACED",
    actor: str = "actor-a",
    resource_type: str = "ORDER",
    resource_id: str = "order-1",
) -> Chain:
    sequence = len(chain) + 1
    committed = commit_payload(PAYLOAD if payload is None else payload)
    content = EventContent(
        id=str(uuid.UUID(int=sequence)),
        event_type=event_type,
        actor_id=actor,
        resource_type=resource_type,
        resource_id=resource_id,
        timestamp=None,
        recorded_at=format_timestamp(BASE_TIME + timedelta(seconds=sequence)),
        recorded_by="svc-writer",
        payload=committed.structure,
    )
    previous = chain[-1].record.record_hash if chain else GENESIS_PREVIOUS_HASH
    return [*chain, ChainEntry(seal_record(content, sequence, previous), committed.values)]


def redact(chain: Chain, index: int, pointer: str) -> Chain:
    """Remove one value and append the redaction event, which inherits the target's identity."""
    target = chain[index]
    chain = [*chain]
    chain[index] = dataclasses.replace(
        target, payload_values={p: v for p, v in target.payload_values.items() if p != pointer}
    )
    content = target.record.content
    return append(
        chain,
        {"targetId": content.id, "paths": [pointer], "reason": "test-only reason"},
        event_type=REDACTION_EVENT_TYPE,
        actor=content.actor_id,
        resource_type=content.resource_type,
        resource_id=content.resource_id,
    )


def retain(chain: Chain) -> Chain:
    """Archive every current record: append the retention event and purge their values."""
    up_to = len(chain)
    chain = append(
        chain,
        {"cutoff": CUTOFF, "upToSequence": up_to},
        event_type=RETENTION_EVENT_TYPE,
        actor="audit-log-service",
        resource_type="AUDIT_LOG",
        resource_id="audit-log",
    )
    return [
        dataclasses.replace(entry, payload_values={}) if entry.record.sequence <= up_to else entry
        for entry in chain
    ]


def matches(entry: ChainEntry, scope: Mapping[str, str]) -> bool:
    content = entry.record.content
    fields = {
        "actorId": content.actor_id,
        "resourceId": content.resource_id,
        "resourceType": content.resource_type,
    }
    return all(fields[name] == value for name, value in scope.items())


def build(
    chain: Chain,
    scope: Scope,
    key: Ed25519PrivateKey,
    *,
    requested_by: str = "auditor-1",
    change_manifest: Callable[[Manifest], Manifest] | None = None,
) -> bytes:
    """Build a signed bundle the way the service does."""
    evidence = retention_evidence(chain)
    boundary = 0 if evidence is None else evidence.up_to_sequence
    records = [
        ExportRecord(entry=entry, archived=entry.record.sequence <= boundary, redacted_paths=())
        for entry in chain
        if matches(entry, scope)
    ]
    head = chain[-1].record if chain else None
    manifest = Manifest(
        scope=scope,
        as_of_sequence=0 if head is None else head.sequence,
        as_of_record_hash=None if head is None else head.record_hash,
        generated_at=GENERATED_AT,
        requested_by=requested_by,
        record_count=len(records),
        records=tuple(
            ManifestRecord(
                r.entry.record.sequence, r.entry.record.content.id, r.entry.record.record_hash
            )
            for r in records
        ),
        retention=evidence,
        key_id=key_id(key.public_key()),
    )
    if change_manifest is not None:
        manifest = change_manifest(manifest)
    return encode_bundle(manifest, sign_manifest(key, manifest), records)


def document(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = json.loads(data)
    return result


def encode(bundle: object) -> bytes:
    return json.dumps(bundle).encode("utf-8")


def first(result: ExportVerification) -> tuple[ExportViolationType, int | None] | None:
    violation = result.first_violation
    return None if violation is None else (violation.type, violation.sequence)


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def sample_chain() -> Chain:
    chain = append([], actor="actor-a", resource_id="order-1")
    chain = append(chain, actor="actor-b", resource_id="order-1")
    chain = append(chain, actor="actor-a", resource_id="order-2", resource_type="INVOICE")
    return append(chain, actor="actor-a", resource_id="order-1")


# --- Manifest format and signing ----------------------------------------------------------------


def test_label_is_the_approved_manifest_label() -> None:
    assert MANIFEST_LABEL == "audit-log/v1/manifest"


def test_signing_input_is_the_labeled_canonical_manifest(key: Ed25519PrivateKey) -> None:
    manifest = Manifest(
        scope={"actorId": "a"},
        as_of_sequence=0,
        as_of_record_hash=None,
        generated_at=GENERATED_AT,
        requested_by="auditor-1",
        record_count=0,
        records=(),
        retention=None,
        key_id="f" * 64,
    )
    expected = (
        '{"asOfRecordHash":null,"asOfSequence":0,'
        '"completeness":"ALL_MATCHING_RECORDS_INCLUDING_ARCHIVED_AS_OF_SEQUENCE",'
        '"format":"audit-log-export/v1","generatedAt":"2026-09-28T12:00:00.000000Z",'
        '"keyId":"' + "f" * 64 + '","recordCount":0,"records":[],"requestedBy":"auditor-1",'
        '"retention":null,"scheme":"audit-log/v1","scope":{"actorId":"a"}}'
    )
    assert manifest_signing_input(manifest) == (
        b"audit-log/v1/manifest" + bytes([0]) + expected.encode("ascii")
    )
    assert (FORMAT, COMPLETENESS) == (
        "audit-log-export/v1",
        "ALL_MATCHING_RECORDS_INCLUDING_ARCHIVED_AS_OF_SEQUENCE",
    )


def test_manifest_has_exactly_the_approved_fields(key: Ed25519PrivateKey) -> None:
    bundle = document(build(sample_chain(), {"actorId": "actor-a"}, key))
    assert set(bundle) == {"manifest", "signature", "records"}
    assert set(bundle["manifest"]) == {
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
    assert bundle["manifest"]["keyId"] == key_id(key.public_key())
    assert all(
        set(item) == {"sequence", "id", "recordHash"} for item in bundle["manifest"]["records"]
    )


def test_signature_is_a_direct_ed25519_signature_in_lowercase_hex(key: Ed25519PrivateKey) -> None:
    data = build(sample_chain(), {"actorId": "actor-a"}, key)
    parsed = parse_bundle(data)
    assert len(parsed.signature) == 128 and parsed.signature == parsed.signature.lower()
    key.public_key().verify(
        bytes.fromhex(parsed.signature), manifest_signing_input(parsed.manifest)
    )


def test_signing_requires_the_key_id_of_the_signing_key(key: Ed25519PrivateKey) -> None:
    with pytest.raises(ValueError, match="keyId"):
        build(
            sample_chain(),
            {"actorId": "actor-a"},
            key,
            change_manifest=lambda m: dataclasses.replace(m, key_id="0" * 64),
        )


def test_bundle_is_canonical_json(key: Ed25519PrivateKey) -> None:
    data = build(sample_chain(), {"actorId": "actor-a"}, key)
    assert rfc8785.dumps(json.loads(data)) == data


def test_exported_record_carries_its_hash_inputs(key: Ed25519PrivateKey) -> None:
    chain = sample_chain()
    record = document(build(chain, {"actorId": "actor-b"}, key))["records"][0]
    source = chain[1]
    assert set(record) == {
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
    assert record["committedPayload"] == source.record.content.payload
    assert record["payloadValues"] == {
        pointer: {"value": json.loads(value.canonical_text), "salt": value.salt}
        for pointer, value in source.payload_values.items()
    }
    assert "payload" not in record
    assert (record["archived"], record["redactedPaths"]) == (False, [])


def test_archived_record_is_exported_without_values_even_if_still_stored() -> None:
    entry = sample_chain()[0]
    assert entry.payload_values
    exported = ExportRecord(entry=entry, archived=True, redacted_paths=("/card",)).to_json()
    assert exported["payloadValues"] == {}
    assert exported["archived"] is True
    assert exported["redactedPaths"] == ["/card"]


# --- Verification of valid bundles --------------------------------------------------------------


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        ({"actorId": "actor-a"}, [1, 3, 4]),
        ({"resourceId": "order-1"}, [1, 2, 4]),
        ({"resourceId": "order-2", "resourceType": "INVOICE"}, [3]),
        ({"resourceId": "order-2", "resourceType": "ORDER"}, []),
    ],
    ids=["actor", "resource-any-type", "resource-and-type", "empty"],
)
def test_each_scope_verifies(key: Ed25519PrivateKey, scope: Scope, expected: list[int]) -> None:
    data = build(sample_chain(), scope, key)

    result = verify_export(data, key.public_key())

    assert result.valid, result.first_violation
    assert result.manifest is not None
    assert [item.sequence for item in result.manifest.records] == expected
    assert (result.manifest.as_of_sequence, result.violation_count) == (4, 0)


def test_empty_chain_export(key: Ed25519PrivateKey) -> None:
    data = build([], {"actorId": "actor-a"}, key)
    manifest = document(data)["manifest"]

    assert (manifest["asOfSequence"], manifest["asOfRecordHash"], manifest["recordCount"]) == (
        0,
        None,
        0,
    )
    assert verify_export(data, key.public_key()).valid


def test_redacted_value_is_authorized_by_the_included_redaction_event(
    key: Ed25519PrivateKey,
) -> None:
    chain = redact(sample_chain(), 0, "/card")
    data = build(chain, {"actorId": "actor-a"}, key)
    exported = document(data)["records"]

    assert "/card" not in exported[0]["payloadValues"]
    assert exported[-1]["eventType"] == REDACTION_EVENT_TYPE
    assert verify_export(data, key.public_key()).valid


def test_missing_value_without_a_redaction_event_is_reported(key: Ed25519PrivateKey) -> None:
    chain = sample_chain()
    chain[0] = dataclasses.replace(
        chain[0], payload_values={p: v for p, v in chain[0].payload_values.items() if p != "/card"}
    )
    result = verify_export(build(chain, {"actorId": "actor-a"}, key), key.public_key())
    assert first(result) == (X.PAYLOAD_VALUE_MISSING, 1)


def test_tampered_redaction_event_does_not_authorize(key: Ed25519PrivateKey) -> None:
    chain = redact(sample_chain(), 0, "/card")
    event = chain[-1]
    values = dict(event.payload_values)
    values["/paths/0"] = dataclasses.replace(values["/paths/0"], canonical_text='"/tags"')
    chain[-1] = dataclasses.replace(event, payload_values=values)

    result = verify_export(build(chain, {"actorId": "actor-a"}, key), key.public_key())

    assert first(result) == (X.PAYLOAD_VALUE_MISSING, 1)
    assert result.violation_count == 2  # the target and the tampered event


def test_archived_records_are_authorized_by_the_signed_retention_evidence(
    key: Ed25519PrivateKey,
) -> None:
    chain = append(retain(redact(sample_chain(), 0, "/card")), actor="actor-a")
    data = build(chain, {"actorId": "actor-a"}, key)
    bundle = document(data)

    assert bundle["manifest"]["retention"] == {
        "upToSequence": 5,
        "cutoff": CUTOFF,
        "eventSequence": 6,
        "eventId": chain[5].record.content.id,
        "eventRecordHash": chain[5].record.record_hash,
    }
    archived = [r for r in bundle["records"] if r["archived"]]
    assert [r["sequence"] for r in archived] == [1, 3, 4, 5]
    assert all(r["payloadValues"] == {} for r in archived)
    assert bundle["records"][-1]["payloadValues"]
    assert verify_export(data, key.public_key()).valid


def test_values_missing_above_the_retention_boundary_are_reported(key: Ed25519PrivateKey) -> None:
    chain = append(retain(sample_chain()), actor="actor-a")
    chain[-1] = dataclasses.replace(chain[-1], payload_values={})
    result = verify_export(build(chain, {"actorId": "actor-a"}, key), key.public_key())
    assert first(result) == (X.PAYLOAD_VALUE_MISSING, 6)


# --- Manifest and key failures ------------------------------------------------------------------


def test_bundle_from_another_key_is_a_key_mismatch(key: Ed25519PrivateKey) -> None:
    other = Ed25519PrivateKey.generate()
    result = verify_export(build(sample_chain(), {"actorId": "actor-a"}, other), key.public_key())
    assert first(result) == (X.KEY_MISMATCH, None)
    assert result.manifest is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scope", {"actorId": "actor-b"}),
        ("asOfSequence", 5),
        ("requestedBy", "someone.else"),
        ("generatedAt", "2026-09-28T12:00:00.000001Z"),
        ("recordCount", 2),
        ("retention", None),
    ],
)
def test_modified_manifest_field_fails_the_signature(
    key: Ed25519PrivateKey, field: str, value: Any
) -> None:
    chain = append(retain(sample_chain()), actor="actor-a")
    bundle = document(build(chain, {"actorId": "actor-a"}, key))
    bundle["manifest"][field] = value
    result = verify_export(encode(bundle), key.public_key())
    assert first(result) == (X.SIGNATURE_INVALID, None)
    assert result.manifest is None


def test_modified_record_list_fails_the_signature(key: Ed25519PrivateKey) -> None:
    bundle = document(build(sample_chain(), {"actorId": "actor-a"}, key))
    bundle["manifest"]["records"].pop()
    bundle["manifest"]["recordCount"] -= 1
    bundle["records"].pop()
    assert first(verify_export(encode(bundle), key.public_key())) == (X.SIGNATURE_INVALID, None)


def test_key_id_swapped_to_the_trusted_key_fails_the_signature(key: Ed25519PrivateKey) -> None:
    other = Ed25519PrivateKey.generate()
    bundle = document(build(sample_chain(), {"actorId": "actor-a"}, other))
    bundle["manifest"]["keyId"] = key_id(key.public_key())
    assert first(verify_export(encode(bundle), key.public_key())) == (X.SIGNATURE_INVALID, None)


def test_signed_but_inconsistent_record_count_is_a_list_mismatch(key: Ed25519PrivateKey) -> None:
    data = build(
        sample_chain(),
        {"actorId": "actor-a"},
        key,
        change_manifest=lambda m: dataclasses.replace(m, record_count=m.record_count + 1),
    )
    assert first(verify_export(data, key.public_key())) == (X.RECORD_LIST_MISMATCH, None)


def test_signed_but_unordered_record_list_is_a_list_mismatch(key: Ed25519PrivateKey) -> None:
    chain = sample_chain()

    def reverse(manifest: Manifest) -> Manifest:
        return dataclasses.replace(manifest, records=tuple(reversed(manifest.records)))

    result = verify_export(
        build(chain, {"actorId": "actor-a"}, key, change_manifest=reverse), key.public_key()
    )
    assert first(result) == (X.RECORD_LIST_MISMATCH, None)


def test_signed_as_of_below_a_record_is_an_as_of_mismatch(key: Ed25519PrivateKey) -> None:
    chain = sample_chain()

    def lower(manifest: Manifest) -> Manifest:
        return dataclasses.replace(
            manifest, as_of_sequence=3, as_of_record_hash=chain[2].record.record_hash
        )

    result = verify_export(
        build(chain, {"actorId": "actor-a"}, key, change_manifest=lower), key.public_key()
    )
    assert first(result) == (X.AS_OF_MISMATCH, 4)


def test_record_at_as_of_with_another_hash_is_an_as_of_mismatch(key: Ed25519PrivateKey) -> None:
    def other_hash(manifest: Manifest) -> Manifest:
        return dataclasses.replace(manifest, as_of_record_hash="e" * 64)

    data = build(sample_chain(), {"actorId": "actor-a"}, key, change_manifest=other_hash)
    assert first(verify_export(data, key.public_key())) == (X.AS_OF_MISMATCH, 4)


# --- Record tampering ---------------------------------------------------------------------------


def _tampered(
    key: Ed25519PrivateKey, change: Callable[[dict[str, Any]], object]
) -> ExportVerification:
    bundle = document(build(sample_chain(), {"actorId": "actor-a"}, key))
    change(bundle)
    return verify_export(encode(bundle), key.public_key())


def _record(bundle: dict[str, Any], index: int) -> dict[str, Any]:
    record: dict[str, Any] = bundle["records"][index]
    return record


Mutation = Callable[[dict[str, Any]], object]
Expected = tuple[ExportViolationType, int | None]
TAMPERING: list[tuple[Mutation, Expected]] = [
    (
        lambda b: _record(b, 0)["payloadValues"]["/card"].update(value="4112"),
        (X.PAYLOAD_VALUE_MISMATCH, 1),
    ),
    (
        lambda b: _record(b, 0)["payloadValues"]["/card"].update(salt="0" * 32),
        (X.PAYLOAD_VALUE_MISMATCH, 1),
    ),
    (
        lambda b: _record(b, 0)["payloadValues"]["/card"].update(value=["4111"]),
        (X.PAYLOAD_VALUE_MISMATCH, 1),
    ),
    (
        lambda b: _record(b, 0)["payloadValues"]["/card"].update(value=2**60),
        (X.PAYLOAD_VALUE_MISMATCH, 1),
    ),
    (
        lambda b: _record(b, 0)["payloadValues"].update({"/nope": {"value": 1, "salt": "0" * 32}}),
        (X.PAYLOAD_VALUE_MISMATCH, 1),
    ),
    (lambda b: _record(b, 0)["payloadValues"].pop("/card"), (X.PAYLOAD_VALUE_MISSING, 1)),
    (lambda b: _record(b, 1).update(eventType="ORDER_CANCELLED"), (X.CONTENT_HASH_MISMATCH, 3)),
    (lambda b: _record(b, 1).update(recordedBy="someone"), (X.CONTENT_HASH_MISMATCH, 3)),
    (lambda b: _record(b, 1).update(timestamp="not a time"), (X.CONTENT_HASH_MISMATCH, 3)),
    (lambda b: _record(b, 1).update(contentHash="c" * 64), (X.CONTENT_HASH_MISMATCH, 3)),
    (
        lambda b: _record(b, 1)["committedPayload"].update(card="d" * 64),
        (X.CONTENT_HASH_MISMATCH, 3),
    ),
    (lambda b: _record(b, 1).update(previousHash="d" * 64), (X.RECORD_HASH_MISMATCH, 3)),
    (lambda b: _record(b, 2).update(previousHash="d" * 64), (X.PREVIOUS_HASH_MISMATCH, 4)),
    (lambda b: _record(b, 0).update(previousHash="d" * 64), (X.PREVIOUS_HASH_MISMATCH, 1)),
    (lambda b: _record(b, 1).update(recordHash="d" * 64), (X.RECORD_LIST_MISMATCH, 3)),
    (lambda b: _record(b, 1).update(id=str(uuid.UUID(int=99))), (X.RECORD_LIST_MISMATCH, 3)),
    (lambda b: _record(b, 1).update(sequence=2), (X.RECORD_LIST_MISMATCH, 2)),
    (lambda b: _record(b, 1).update(actorId="actor-b"), (X.SCOPE_MISMATCH, 3)),
    (lambda b: b["records"].pop(1), (X.RECORD_LIST_MISMATCH, None)),
    (
        lambda b: b["records"].append(copy.deepcopy(b["records"][0])),
        (X.RECORD_LIST_MISMATCH, None),
    ),
    (lambda b: b["records"].reverse(), (X.RECORD_LIST_MISMATCH, 4)),
]
TAMPERING_IDS = [
    "value",
    "salt",
    "non-scalar-value",
    "out-of-domain-value",
    "unknown-pointer",
    "dropped-value",
    "event-type",
    "recorded-by",
    "malformed-timestamp",
    "content-hash",
    "commitment",
    "previous-hash-unlinked",
    "previous-hash-adjacent",
    "genesis",
    "record-hash",
    "id",
    "sequence",
    "out-of-scope",
    "dropped-record",
    "added-record",
    "reordered",
]


@pytest.mark.parametrize(("change", "expected"), TAMPERING, ids=TAMPERING_IDS)
def test_record_tampering_is_detected(
    key: Ed25519PrivateKey,
    change: Mutation,
    expected: Expected,
) -> None:
    result = _tampered(key, change)
    assert not result.valid
    assert first(result) == expected


def test_adjacent_records_must_link(key: Ed25519PrivateKey) -> None:
    # Records 3 and 4 are adjacent: 4 must link to 3, even with a consistent forged hash.
    chain = sample_chain()
    record = chain[3].record
    forged = seal_record(record.content, 4, "d" * 64)
    chain[3] = dataclasses.replace(chain[3], record=forged)

    result = verify_export(build(chain, {"actorId": "actor-a"}, key), key.public_key())

    assert first(result) == (X.PREVIOUS_HASH_MISMATCH, 4)


def test_verification_continues_and_counts_every_violation(key: Ed25519PrivateKey) -> None:
    def change(bundle: dict[str, Any]) -> None:
        _record(bundle, 0)["payloadValues"]["/card"]["value"] = "x"
        _record(bundle, 2)["recordedBy"] = "x"

    result = _tampered(key, change)
    assert (first(result), result.violation_count) == ((X.PAYLOAD_VALUE_MISMATCH, 1), 2)


def test_derived_fields_are_not_verified(key: Ed25519PrivateKey) -> None:
    def change(bundle: dict[str, Any]) -> None:
        _record(bundle, 0)["archived"] = True
        _record(bundle, 0)["redactedPaths"] = ["/anything"]

    assert _tampered(key, change).valid


# --- Strict parsing ------------------------------------------------------------------------------


Change = Callable[[dict[str, Any]], Any]


def _set(path: tuple[Any, ...], value: Any) -> Change:
    def change(bundle: dict[str, Any]) -> dict[str, Any]:
        target: Any = bundle
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
        return bundle

    return change


def _delete(path: tuple[Any, ...]) -> Change:
    def change(bundle: dict[str, Any]) -> dict[str, Any]:
        target: Any = bundle
        for part in path[:-1]:
            target = target[part]
        del target[path[-1]]
        return bundle

    return change


M = ("manifest",)
R0 = ("records", 0)
STRUCTURAL: list[tuple[str, Change]] = [
    ("bundle-not-object", lambda b: [b]),
    ("extra-bundle-key", _set(("note",), 1)),
    ("missing-signature", _delete(("signature",))),
    ("signature-uppercase", lambda b: {**b, "signature": b["signature"].upper()}),
    ("signature-short", lambda b: {**b, "signature": b["signature"][:-2]}),
    ("signature-not-hex", lambda b: {**b, "signature": "z" * 128}),
    ("records-not-list", _set(("records",), {})),
    ("manifest-not-object", _set(M, [])),
    ("extra-manifest-key", _set((*M, "note"), 1)),
    ("missing-manifest-key", _delete((*M, "keyId"))),
    ("format", _set((*M, "format"), "audit-log-export/v2")),
    ("scheme", _set((*M, "scheme"), "audit-log/v2")),
    ("completeness", _set((*M, "completeness"), "SOME")),
    ("scope-not-object", _set((*M, "scope"), "actor-a")),
    ("scope-combination", _set((*M, "scope"), {"actorId": "a", "resourceType": "ORDER"})),
    ("scope-empty-value", _set((*M, "scope"), {"actorId": ""})),
    ("scope-non-string", _set((*M, "scope"), {"actorId": 1})),
    ("as-of-negative", _set((*M, "asOfSequence"), -1)),
    ("as-of-bool", _set((*M, "asOfSequence"), True)),
    ("as-of-float", _set((*M, "asOfSequence"), 4.0)),
    ("as-of-hash-null", _set((*M, "asOfRecordHash"), None)),
    ("as-of-hash-short", _set((*M, "asOfRecordHash"), "ab")),
    ("generated-at", _set((*M, "generatedAt"), "2026-09-28T12:00:00Z")),
    ("requested-by", _set((*M, "requestedBy"), "Auditor")),
    ("key-id", _set((*M, "keyId"), "ab")),
    ("record-count-negative", _set((*M, "recordCount"), -1)),
    ("records-list-not-list", _set((*M, "records"), {})),
    ("listed-extra-key", _set((*M, "records", 0, "note"), 1)),
    ("listed-sequence-zero", _set((*M, "records", 0, "sequence"), 0)),
    ("listed-id-number", _set((*M, "records", 0, "id"), 1)),
    ("listed-hash-short", _set((*M, "records", 0, "recordHash"), "ab")),
    ("retention-not-object", _set((*M, "retention"), [])),
    ("retention-up-to-zero", _set((*M, "retention", "upToSequence"), 0)),
    ("retention-up-to-not-below-event", _set((*M, "retention", "upToSequence"), 6)),
    ("retention-event-above-as-of", _set((*M, "retention", "eventSequence"), 99)),
    ("retention-cutoff", _set((*M, "retention", "cutoff"), "yesterday")),
    ("retention-event-id", _set((*M, "retention", "eventId"), None)),
    ("retention-event-hash", _set((*M, "retention", "eventRecordHash"), "ab")),
    ("record-not-object", _set(R0, [])),
    ("record-extra-key", _set((*R0, "payload"), {})),
    ("record-missing-key", _delete((*R0, "redactedPaths"))),
    ("record-sequence-string", _set((*R0, "sequence"), "1")),
    ("record-actor-number", _set((*R0, "actorId"), 7)),
    ("record-timestamp-number", _set((*R0, "timestamp"), 7)),
    ("record-payload-list", _set((*R0, "committedPayload"), [])),
    ("record-archived-string", _set((*R0, "archived"), "false")),
    ("record-redacted-not-list", _set((*R0, "redactedPaths"), "/card")),
    ("record-redacted-number", _set((*R0, "redactedPaths"), [1])),
    ("values-not-object", _set((*R0, "payloadValues"), [])),
    ("value-extra-key", _set(("records", -1, "payloadValues", "/card", "note"), 1)),
    ("value-salt-number", _set(("records", -1, "payloadValues", "/card", "salt"), 1)),
]


@pytest.mark.parametrize("change", [c for _, c in STRUCTURAL], ids=[n for n, _ in STRUCTURAL])
def test_structural_deviation_is_manifest_invalid(key: Ed25519PrivateKey, change: Change) -> None:
    chain = append(retain(sample_chain()), actor="actor-a")
    bundle = document(build(chain, {"actorId": "actor-a"}, key))
    data = encode(change(bundle))

    with pytest.raises(BundleFormatError):
        parse_bundle(data)
    result = verify_export(data, key.public_key())
    assert first(result) == (X.MANIFEST_INVALID, None)
    assert (result.manifest, result.violation_count) == (None, 1)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not json",
        bytes([0xFF, 0xFE]) + b"{}",
        b'{"manifest": 1, "manifest": 2, "signature": "x", "records": []}',
        b'{"manifest": NaN}',
        b'{"manifest": Infinity}',
        b"[" * 100_000,
        b"1" * 5000,
    ],
    ids=["empty", "text", "not-utf8", "duplicate", "nan", "infinity", "deep", "huge-int"],
)
def test_unparseable_input_is_manifest_invalid(key: Ed25519PrivateKey, data: bytes) -> None:
    assert first(verify_export(data, key.public_key())) == (X.MANIFEST_INVALID, None)


def test_duplicate_key_inside_a_record_is_manifest_invalid(key: Ed25519PrivateKey) -> None:
    data = build(sample_chain(), {"actorId": "actor-a"}, key)
    duplicated = data.replace(b'"archived":false', b'"archived":false,"archived":true', 1)
    assert first(verify_export(duplicated, key.public_key())) == (X.MANIFEST_INVALID, None)


def test_oversized_bundle_is_manifest_invalid(
    key: Ed25519PrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = build(sample_chain(), {"actorId": "actor-a"}, key)
    monkeypatch.setattr(exports_module, "MAX_BUNDLE_BYTES", len(data))
    assert verify_export(data, key.public_key()).valid
    assert first(verify_export(data + b" ", key.public_key())) == (X.MANIFEST_INVALID, None)


def test_bundle_errors_carry_no_content(key: Ed25519PrivateKey) -> None:
    with pytest.raises(BundleFormatError) as caught:
        parse_bundle(b'{"manifest": "test-only-secret"}')
    assert "test-only-secret" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_reader_accepts_any_json_formatting(key: Ed25519PrivateKey) -> None:
    bundle = document(build(sample_chain(), {"actorId": "actor-a"}, key))
    pretty = json.dumps(bundle, indent=2).encode("utf-8")
    assert verify_export(pretty, key.public_key()).valid


# --- Retention evidence -------------------------------------------------------------------------


def test_no_retention_event_means_no_evidence() -> None:
    assert retention_evidence(sample_chain()) is None


def test_evidence_is_the_latest_applicable_retention_event() -> None:
    chain = append(retain(append(retain(sample_chain()), actor="x")), actor="y")
    evidence = retention_evidence(chain)
    assert evidence == RetentionEvidence(
        up_to_sequence=6,
        cutoff=CUTOFF,
        event_sequence=7,
        event_id=chain[6].record.content.id,
        event_record_hash=chain[6].record.record_hash,
    )


@pytest.mark.parametrize(
    "up_to", [0, 5, "1", None, True], ids=["zero", "own", "string", "null", "bool"]
)
def test_retention_event_without_a_valid_boundary_is_skipped(up_to: Any) -> None:
    chain = append(
        sample_chain(),
        {"cutoff": CUTOFF, "upToSequence": up_to},
        event_type=RETENTION_EVENT_TYPE,
    )
    assert retention_evidence(chain) is None


def test_retention_event_whose_boundary_value_is_unreadable_is_skipped() -> None:
    chain = retain(sample_chain())
    event = chain[-1]
    values = dict(event.payload_values)
    values["/upToSequence"] = dataclasses.replace(values["/upToSequence"], canonical_text="{")
    chain[-1] = dataclasses.replace(event, payload_values=values)
    assert retention_evidence(chain) is None


def test_applicable_retention_event_without_a_cutoff_is_an_error() -> None:
    chain = retain(sample_chain())
    event = chain[-1]
    chain[-1] = dataclasses.replace(
        event, payload_values={p: v for p, v in event.payload_values.items() if p != "/cutoff"}
    )
    with pytest.raises(ValueError, match="cutoff"):
        retention_evidence(chain)


# --- Checkpoint anchoring (L-D1) ---------------------------------------------------------------


def _checkpoint(sequence: int, record_hash: str) -> Checkpoint:
    return Checkpoint(
        sequence=sequence,
        record_hash=record_hash,
        created_at=GENERATED_AT,
        created_by="ops.admin",
        key_id="f" * 64,
    )


def test_checkpoint_anchoring(key: Ed25519PrivateKey) -> None:
    chain = sample_chain()
    verification = verify_export(build(chain, {"actorId": "actor-a"}, key), key.public_key())

    def hash_of(sequence: int) -> str:
        return chain[sequence - 1].record.record_hash

    assert anchor_checkpoint(verification, _checkpoint(4, hash_of(4))) is AnchorResult.MATCH
    assert anchor_checkpoint(verification, _checkpoint(4, "e" * 64)) is AnchorResult.MISMATCH
    assert anchor_checkpoint(verification, _checkpoint(1, hash_of(1))) is AnchorResult.MATCH
    assert anchor_checkpoint(verification, _checkpoint(3, "e" * 64)) is AnchorResult.MISMATCH
    # Record 2 is not in the actor's export: no signed evidence at that sequence.
    assert (
        anchor_checkpoint(verification, _checkpoint(2, hash_of(2))) is AnchorResult.NOT_APPLICABLE
    )
    assert anchor_checkpoint(verification, _checkpoint(9, "e" * 64)) is AnchorResult.NOT_APPLICABLE


def test_checkpoint_is_not_applicable_to_an_untrusted_manifest(key: Ed25519PrivateKey) -> None:
    other = Ed25519PrivateKey.generate()
    chain = sample_chain()
    verification = verify_export(build(chain, {"actorId": "actor-a"}, other), key.public_key())
    checkpoint = _checkpoint(4, chain[3].record.record_hash)
    assert anchor_checkpoint(verification, checkpoint) is AnchorResult.NOT_APPLICABLE


def test_checkpoint_never_anchors_to_an_empty_chain(key: Ed25519PrivateKey) -> None:
    verification = verify_export(build([], {"actorId": "a"}, key), key.public_key())
    assert anchor_checkpoint(verification, _checkpoint(1, "e" * 64)) is AnchorResult.NOT_APPLICABLE


# --- Properties ---------------------------------------------------------------------------------

_ACTORS = ("actor-a", "actor-b")
_RESOURCES = ("order-1", "order-2")
_OPERATION = st.one_of(
    st.tuples(st.just("append"), st.sampled_from(_ACTORS), st.sampled_from(_RESOURCES)),
    st.tuples(st.just("redact"), st.integers(min_value=0, max_value=50), st.just("")),
    st.tuples(st.just("retain"), st.just(""), st.just("")),
)
_SCOPES: list[Scope] = [
    {"actorId": "actor-a"},
    {"actorId": "actor-b"},
    {"resourceId": "order-1"},
    {"resourceId": "order-2", "resourceType": "ORDER"},
]


def _interleaved(operations: list[tuple[str, Any, Any]]) -> Chain:
    chain: Chain = []
    boundary = 0
    for kind, first_argument, second_argument in operations:
        if kind == "append":
            chain = append(chain, actor=first_argument, resource_id=second_argument)
        elif kind == "redact":
            candidates = [
                index
                for index, entry in enumerate(chain)
                if entry.record.sequence > boundary
                and not entry.record.content.event_type.startswith("AUDIT_LOG_")
                and "/card" in entry.payload_values
            ]
            if candidates:
                position = int(first_argument) % len(candidates)
                chain = redact(chain, candidates[position], "/card")
        elif chain:
            boundary = len(chain)
            chain = retain(chain)
    return chain


@settings(max_examples=60, deadline=None)
@given(operations=st.lists(_OPERATION, min_size=1, max_size=10), scope=st.sampled_from(_SCOPES))
def test_any_export_of_any_interleaving_verifies(
    operations: list[tuple[str, Any, Any]], scope: Scope
) -> None:
    key = Ed25519PrivateKey.generate()
    result = verify_export(build(_interleaved(operations), scope, key), key.public_key())
    assert result.valid, result.first_violation


_MUTATIONS = [
    "value",
    "salt",
    "actor",
    "record-hash",
    "content-hash",
    "drop",
    "duplicate",
    "manifest-as-of",
    "manifest-requested-by",
    "signature",
]


@settings(max_examples=60, deadline=None)
@given(
    operations=st.lists(_OPERATION, min_size=1, max_size=8),
    mutation=st.sampled_from(_MUTATIONS),
    position=st.integers(min_value=0, max_value=50),
)
def test_any_mutation_fails_verification(
    operations: list[tuple[str, Any, Any]], mutation: str, position: int
) -> None:
    key = Ed25519PrivateKey.generate()
    chain = append(_interleaved(operations), actor="actor-a", resource_id="order-1")
    bundle = document(build(chain, {"actorId": "actor-a"}, key))
    records = bundle["records"]
    record = records[position % len(records)]
    with_values = [r for r in records if r["payloadValues"]]
    valued = with_values[position % len(with_values)]  # the appended record always has values
    pointer = sorted(valued["payloadValues"])[0]
    if mutation == "value":
        valued["payloadValues"][pointer]["value"] = "test-only-changed"
    elif mutation == "salt":
        salt = valued["payloadValues"][pointer]["salt"]
        valued["payloadValues"][pointer]["salt"] = ("1" if salt[0] == "0" else "0") + salt[1:]
    elif mutation == "actor":
        record["actorId"] = "actor-z"
    elif mutation == "record-hash":
        record["recordHash"] = "e" * 64
    elif mutation == "content-hash":
        record["contentHash"] = "e" * 64
    elif mutation == "drop":
        records.remove(record)
    elif mutation == "duplicate":
        records.append(copy.deepcopy(record))
    elif mutation == "manifest-as-of":
        bundle["manifest"]["asOfSequence"] += 1
    elif mutation == "manifest-requested-by":
        bundle["manifest"]["requestedBy"] = "someone.else"
    else:
        signature = bundle["signature"]
        bundle["signature"] = ("1" if signature[0] == "0" else "0") + signature[1:]

    assert not verify_export(encode(bundle), key.public_key()).valid
