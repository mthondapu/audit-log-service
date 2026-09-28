"""Checkpoint artifact format, signing, and strict parsing (FR-4, Phase 10 decision CP5).

Every key is generated in memory for the test. No key material is stored or committed.
"""

import hashlib
import json
import re
from collections.abc import Callable
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from hypothesis import given
from hypothesis import strategies as st

from audit_log_service.config.api_keys import PRINCIPAL_ID_PATTERN
from audit_log_service.integrity.canonical import CHECKPOINT_LABEL, MAX_SAFE_INTEGER
from audit_log_service.integrity.checkpoints import (
    MAX_ARTIFACT_BYTES,
    Checkpoint,
    CheckpointError,
    CheckpointFailure,
    KeyFormatError,
    SignedCheckpoint,
    encode_artifact,
    key_id,
    load_private_key,
    load_public_key,
    parse_artifact,
    sign_checkpoint,
    signing_input,
    verify_checkpoint,
)

F = CheckpointFailure
RECORD_HASH = "ab" * 32
CREATED_AT = "2026-09-28T10:15:30.123456Z"


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _checkpoint(key: Ed25519PrivateKey, **changes: Any) -> Checkpoint:
    fields: dict[str, Any] = {
        "sequence": 42,
        "record_hash": RECORD_HASH,
        "created_at": CREATED_AT,
        "created_by": "ops.admin",
        "key_id": key_id(key.public_key()),
    }
    fields.update(changes)
    return Checkpoint(**fields)


def _document(key: Ed25519PrivateKey) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(encode_artifact(sign_checkpoint(key, _checkpoint(key))))
    return document


def _bytes(document: object) -> bytes:
    return json.dumps(document).encode("utf-8")


def _failure(data: bytes, key: Ed25519PrivateKey) -> CheckpointFailure:
    with pytest.raises(CheckpointError) as caught:
        verify_checkpoint(parse_artifact(data), key.public_key())
    return caught.value.failure


def test_label_is_the_approved_checkpoint_label() -> None:
    assert CHECKPOINT_LABEL == "audit-log/v1/checkpoint"


def test_signing_input_is_the_labeled_canonical_checkpoint() -> None:
    checkpoint = Checkpoint(
        sequence=7,
        record_hash="0" * 64,
        created_at=CREATED_AT,
        created_by="ops.admin",
        key_id="f" * 64,
    )
    expected_object = (
        '{"createdAt":"2026-09-28T10:15:30.123456Z","createdBy":"ops.admin","keyId":"'
        + "f" * 64
        + '","recordHash":"'
        + "0" * 64
        + '","scheme":"audit-log/v1","sequence":7}'
    )
    assert signing_input(checkpoint) == (
        b"audit-log/v1/checkpoint" + bytes([0]) + expected_object.encode("ascii")
    )


def test_key_id_is_the_sha256_of_the_raw_public_key(key: Ed25519PrivateKey) -> None:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert key_id(key.public_key()) == hashlib.sha256(raw).hexdigest()
    assert re.fullmatch(r"[0-9a-f]{64}", key_id(key.public_key()))


def test_signature_is_a_direct_deterministic_ed25519_signature(key: Ed25519PrivateKey) -> None:
    checkpoint = _checkpoint(key)
    signed = sign_checkpoint(key, checkpoint)

    assert re.fullmatch(r"[0-9a-f]{128}", signed.signature)
    assert sign_checkpoint(key, checkpoint) == signed
    # No pre-hash: the signature verifies over the labeled bytes themselves.
    key.public_key().verify(bytes.fromhex(signed.signature), signing_input(checkpoint))


def test_signing_requires_the_key_id_of_the_signing_key(key: Ed25519PrivateKey) -> None:
    with pytest.raises(ValueError, match="keyId"):
        sign_checkpoint(key, _checkpoint(key, key_id="0" * 64))


def test_artifact_is_canonical_json_with_a_trailing_line_feed(key: Ed25519PrivateKey) -> None:
    signed = sign_checkpoint(key, _checkpoint(key))
    data = encode_artifact(signed)

    assert data.endswith(bytes([10]))
    document = json.loads(data)
    assert rfc8785.dumps(document) + bytes([10]) == data
    assert set(document) == {"checkpoint", "signature"}
    assert document["checkpoint"] == {
        "scheme": "audit-log/v1",
        "sequence": 42,
        "recordHash": RECORD_HASH,
        "createdAt": CREATED_AT,
        "createdBy": "ops.admin",
        "keyId": key_id(key.public_key()),
    }


def test_round_trip_parses_and_verifies(key: Ed25519PrivateKey) -> None:
    signed = sign_checkpoint(key, _checkpoint(key))
    parsed = parse_artifact(encode_artifact(signed))

    assert parsed == signed
    verify_checkpoint(parsed, key.public_key())


def test_reader_accepts_any_json_formatting(key: Ed25519PrivateKey) -> None:
    document = _document(key)
    pretty = json.dumps(document, indent=4, sort_keys=False).encode("utf-8")
    verify_checkpoint(parse_artifact(pretty), key.public_key())


@given(sequence=st.integers(min_value=1, max_value=MAX_SAFE_INTEGER))
def test_any_sequence_in_the_domain_round_trips(sequence: int) -> None:
    key = Ed25519PrivateKey.generate()
    signed = sign_checkpoint(key, _checkpoint(key, sequence=sequence))
    assert parse_artifact(encode_artifact(signed)) == signed


def _without(mapping: dict[str, Any], name: str) -> dict[str, Any]:
    return {k: v for k, v in mapping.items() if k != name}


Change = Callable[[dict[str, Any]], Any]

ENVELOPE_CHANGES: list[tuple[str, Change]] = [
    ("missing-signature", lambda d: _without(d, "signature")),
    ("missing-checkpoint", lambda d: _without(d, "checkpoint")),
    ("extra-envelope-key", lambda d: {**d, "note": "x"}),
    ("envelope-not-object", lambda d: [d]),
    ("checkpoint-not-object", lambda d: {**d, "checkpoint": "x"}),
    ("signature-uppercase", lambda d: {**d, "signature": d["signature"].upper()}),
    ("signature-short", lambda d: {**d, "signature": d["signature"][:-2]}),
    ("signature-not-string", lambda d: {**d, "signature": 1}),
]


def _content_change(name: str, value: Any) -> Change:
    def change(document: dict[str, Any]) -> dict[str, Any]:
        content = dict(document["checkpoint"])
        if value is _DELETE:
            del content[name]
        else:
            content[name] = value
        return {**document, "checkpoint": content}

    return change


_DELETE = object()

CONTENT_CHANGES: list[tuple[str, Change]] = [
    *[
        (f"missing-{name}", _content_change(name, _DELETE))
        for name in ("scheme", "sequence", "recordHash", "createdAt", "createdBy", "keyId")
    ],
    ("extra-key", _content_change("note", "x")),
    ("scheme-other", _content_change("scheme", "audit-log/v2")),
    ("sequence-zero", _content_change("sequence", 0)),
    ("sequence-negative", _content_change("sequence", -1)),
    ("sequence-too-large", _content_change("sequence", MAX_SAFE_INTEGER + 1)),
    ("sequence-float", _content_change("sequence", 42.0)),
    ("sequence-bool", _content_change("sequence", True)),
    ("sequence-string", _content_change("sequence", "42")),
    ("record-hash-uppercase", _content_change("recordHash", RECORD_HASH.upper())),
    ("record-hash-short", _content_change("recordHash", "ab")),
    ("created-at-offset", _content_change("createdAt", "2026-09-28T10:15:30.123456+00:00")),
    ("created-at-millis", _content_change("createdAt", "2026-09-28T10:15:30.123Z")),
    ("created-at-invalid-date", _content_change("createdAt", "2026-02-30T10:15:30.123456Z")),
    ("created-by-uppercase", _content_change("createdBy", "Ops")),
    ("created-by-empty", _content_change("createdBy", "")),
    ("created-by-number", _content_change("createdBy", 7)),
    ("key-id-short", _content_change("keyId", "ab")),
]


@pytest.mark.parametrize(
    "change",
    [change for _, change in ENVELOPE_CHANGES + CONTENT_CHANGES],
    ids=[name for name, _ in ENVELOPE_CHANGES + CONTENT_CHANGES],
)
def test_structural_deviation_is_malformed(key: Ed25519PrivateKey, change: Any) -> None:
    with pytest.raises(CheckpointError) as caught:
        parse_artifact(_bytes(change(_document(key))))
    assert caught.value.failure is F.MALFORMED


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not json",
        b"[]",
        b"null",
        bytes([0xFF, 0xFE]) + b"{}",
        b'{"checkpoint": 1, "checkpoint": 2, "signature": "x"}',
        b'{"checkpoint": {"sequence": NaN}, "signature": "x"}',
        b"[" * 100_000,
        b"1" * 5000,
    ],
    ids=["empty", "text", "array", "null", "not-utf8", "duplicate", "nan", "deep", "huge-int"],
)
def test_unparseable_input_is_malformed(data: bytes) -> None:
    with pytest.raises(CheckpointError) as caught:
        parse_artifact(data)
    assert caught.value.failure is F.MALFORMED


def test_duplicate_key_inside_the_checkpoint_is_malformed(key: Ed25519PrivateKey) -> None:
    data = encode_artifact(sign_checkpoint(key, _checkpoint(key)))
    duplicated = data.replace(b'"sequence":42', b'"sequence":42,"sequence":43')
    with pytest.raises(CheckpointError) as caught:
        parse_artifact(duplicated)
    assert caught.value.failure is F.MALFORMED


def test_oversized_artifact_is_malformed(key: Ed25519PrivateKey) -> None:
    data = encode_artifact(sign_checkpoint(key, _checkpoint(key)))
    padded = data[:-1] + b" " * (MAX_ARTIFACT_BYTES - len(data) + 1)
    assert len(padded) == MAX_ARTIFACT_BYTES
    parse_artifact(padded)  # exactly at the limit
    with pytest.raises(CheckpointError) as caught:
        parse_artifact(padded + b" ")
    assert caught.value.failure is F.MALFORMED


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sequence", 43),
        ("recordHash", "cd" * 32),
        ("createdAt", "2026-09-28T10:15:31.123456Z"),
        ("createdBy", "someone.else"),
    ],
)
def test_modified_signed_field_fails_the_signature(
    key: Ed25519PrivateKey, field: str, value: Any
) -> None:
    document = _document(key)
    document["checkpoint"][field] = value
    assert _failure(_bytes(document), key) is F.SIGNATURE_INVALID


@pytest.mark.parametrize("position", [0, 63, 127])
def test_modified_signature_fails(key: Ed25519PrivateKey, position: int) -> None:
    document = _document(key)
    signature = document["signature"]
    flipped = "0" if signature[position] != "0" else "1"
    document["signature"] = signature[:position] + flipped + signature[position + 1 :]
    assert _failure(_bytes(document), key) is F.SIGNATURE_INVALID


def test_artifact_from_another_key_is_a_key_mismatch(key: Ed25519PrivateKey) -> None:
    other = Ed25519PrivateKey.generate()
    data = encode_artifact(sign_checkpoint(other, _checkpoint(other)))
    assert _failure(data, key) is F.KEY_MISMATCH


def test_key_id_swapped_to_the_trusted_key_fails_the_signature(key: Ed25519PrivateKey) -> None:
    # An attacker's key cannot borrow the trusted keyId: keyId is inside the signed content.
    other = Ed25519PrivateKey.generate()
    document = json.loads(encode_artifact(sign_checkpoint(other, _checkpoint(other))))
    document["checkpoint"]["keyId"] = key_id(key.public_key())
    assert _failure(_bytes(document), key) is F.SIGNATURE_INVALID


def test_errors_carry_only_the_fixed_reason(key: Ed25519PrivateKey) -> None:
    document = _document(key)
    document["checkpoint"]["createdBy"] = "Secret Value"
    with pytest.raises(CheckpointError) as caught:
        parse_artifact(_bytes(document))
    assert str(caught.value) == "MALFORMED"
    assert caught.value.__cause__ is None


def test_principal_id_rule_matches_the_api_key_configuration() -> None:
    # The artifact repeats the ADR-0008 principal-id rule rather than importing configuration.
    assert PRINCIPAL_ID_PATTERN == r"^[a-z][a-z0-9._-]{0,63}$"


def test_public_and_private_keys_load_from_pem(key: Ed25519PrivateKey) -> None:
    public_pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    private_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    assert key_id(load_public_key(public_pem)) == key_id(key.public_key())
    assert key_id(load_private_key(private_pem).public_key()) == key_id(key.public_key())


def _ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.mark.parametrize(
    "pem",
    [
        b"not a key",
        _ec_key().public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
    ],
    ids=["text", "not-ed25519"],
)
def test_invalid_public_key_is_rejected(pem: bytes) -> None:
    with pytest.raises(KeyFormatError):
        load_public_key(pem)


def test_private_key_pem_is_not_a_public_key(key: Ed25519PrivateKey) -> None:
    with pytest.raises(KeyFormatError):
        load_public_key(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))


@pytest.mark.parametrize("kind", ["text", "encrypted", "not-ed25519", "public"])
def test_invalid_private_key_is_rejected(key: Ed25519PrivateKey, kind: str) -> None:
    pem = {
        "text": lambda: b"not a key",
        "encrypted": lambda: key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(b"test-only-passphrase")
        ),
        "not-ed25519": lambda: _ec_key().private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ),
        "public": lambda: key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ),
    }[kind]()
    with pytest.raises(KeyFormatError) as caught:
        load_private_key(pem)
    assert caught.value.__cause__ is None
    assert "BEGIN" not in str(caught.value)


def test_signed_checkpoint_repr_holds_no_key_material(key: Ed25519PrivateKey) -> None:
    signed = sign_checkpoint(key, _checkpoint(key))
    raw_private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    assert raw_private.hex() not in repr(signed)
    assert isinstance(signed, SignedCheckpoint)
