"""Signed checkpoint artifacts (requirements FR-4, ADR-0006, Phase 10 decisions CP5 and CP13).

A checkpoint signs the head of a verified chain. Its signed content is the `checkpoint` object:

    {"scheme", "sequence", "recordHash", "createdAt", "createdBy", "keyId"}

Ed25519 signs ``UTF-8("audit-log/v1/checkpoint") || 0x00 || RFC8785(checkpoint)`` directly, with no
pre-hash. `keyId` is the SHA-256 of the raw 32-byte public key, inside the signed content. The
artifact is ``RFC8785({"checkpoint": ..., "signature": <128 lowercase hex>})`` followed by a line
feed. Readers accept any JSON formatting but require exactly these keys and value forms.

This module has no web, database, or configuration dependency: the offline verifier uses it.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, NoReturn, cast

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from audit_log_service.integrity.canonical import (
    CHECKPOINT_LABEL,
    MAX_SAFE_INTEGER,
    SCHEME,
    JsonValue,
    canonicalize,
    is_sha256_hex,
    labeled_bytes,
)
from audit_log_service.integrity.timestamps import is_canonical_timestamp

MAX_ARTIFACT_BYTES = 64 * 1024
_SIGNATURE_HEX = re.compile(r"[0-9a-f]{128}")
# The principal-id rule of the API-key configuration (ADR-0008), repeated here because this module
# must not depend on configuration code.
PRINCIPAL_ID = re.compile(r"[a-z][a-z0-9._-]{0,63}")
_ENVELOPE_KEYS = frozenset({"checkpoint", "signature"})
_CHECKPOINT_KEYS = frozenset(
    {"scheme", "sequence", "recordHash", "createdAt", "createdBy", "keyId"}
)


class CheckpointFailure(StrEnum):
    """Why an artifact was rejected. Fixed reasons, never derived from the artifact's content."""

    MALFORMED = "MALFORMED"
    KEY_MISMATCH = "KEY_MISMATCH"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"


class CheckpointError(Exception):
    """A checkpoint artifact is malformed, names another key, or has an invalid signature."""

    def __init__(self, failure: CheckpointFailure) -> None:
        super().__init__(failure.value)
        self.failure = failure


class KeyFormatError(Exception):
    """A key file is not an Ed25519 key in the expected PEM form. Carries no key material."""


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """The signed content of a checkpoint."""

    sequence: int
    record_hash: str
    created_at: str
    created_by: str
    key_id: str

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "scheme": SCHEME,
            "sequence": self.sequence,
            "recordHash": self.record_hash,
            "createdAt": self.created_at,
            "createdBy": self.created_by,
            "keyId": self.key_id,
        }


@dataclass(frozen=True, slots=True)
class SignedCheckpoint:
    checkpoint: Checkpoint
    signature: str


def key_id(public_key: Ed25519PublicKey) -> str:
    """The approved key identifier: SHA-256 of the raw 32-byte public key, lowercase hex."""
    return hashlib.sha256(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()


def signing_input(checkpoint: Checkpoint) -> bytes:
    """The bytes Ed25519 signs: UTF-8(label) || 0x00 || RFC8785(checkpoint)."""
    return labeled_bytes(CHECKPOINT_LABEL, checkpoint.to_json())


def sign_checkpoint(private_key: Ed25519PrivateKey, checkpoint: Checkpoint) -> SignedCheckpoint:
    """Sign a checkpoint whose `keyId` identifies the signing key."""
    if checkpoint.key_id != key_id(private_key.public_key()):
        raise ValueError("the checkpoint keyId does not identify the signing key")
    return SignedCheckpoint(checkpoint, private_key.sign(signing_input(checkpoint)).hex())


def encode_artifact(signed: SignedCheckpoint) -> bytes:
    """The deterministic artifact bytes: RFC 8785 of the envelope, then a line feed."""
    envelope: dict[str, JsonValue] = {
        "checkpoint": signed.checkpoint.to_json(),
        "signature": signed.signature,
    }
    return canonicalize(envelope) + b"\n"


def verify_checkpoint(signed: SignedCheckpoint, public_key: Ed25519PublicKey) -> None:
    """Raise `CheckpointError` unless the checkpoint names this key and its signature verifies."""
    if signed.checkpoint.key_id != key_id(public_key):
        raise CheckpointError(CheckpointFailure.KEY_MISMATCH)
    try:
        public_key.verify(bytes.fromhex(signed.signature), signing_input(signed.checkpoint))
    except InvalidSignature:
        raise CheckpointError(CheckpointFailure.SIGNATURE_INVALID) from None


def parse_artifact(data: bytes) -> SignedCheckpoint:
    """Parse artifact bytes strictly, raising `CheckpointError(MALFORMED)` on any deviation.

    The input must be at most 64 KiB of UTF-8 JSON with no duplicate keys and no NaN or infinity,
    and exactly the approved keys and value forms.
    """
    if len(data) > MAX_ARTIFACT_BYTES:
        _malformed()
    try:
        document: object = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_keys,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError):
        _malformed()
    envelope = _object_with_keys(document, _ENVELOPE_KEYS)
    content = _object_with_keys(envelope["checkpoint"], _CHECKPOINT_KEYS)
    signature = envelope["signature"]
    sequence = content["sequence"]
    if not (
        content["scheme"] == SCHEME
        and type(sequence) is int
        and 1 <= sequence <= MAX_SAFE_INTEGER
        and is_sha256_hex(content["recordHash"])
        and is_canonical_timestamp(content["createdAt"])
        and isinstance(content["createdBy"], str)
        and PRINCIPAL_ID.fullmatch(content["createdBy"]) is not None
        and is_sha256_hex(content["keyId"])
        and isinstance(signature, str)
        and _SIGNATURE_HEX.fullmatch(signature) is not None
    ):
        _malformed()
    checkpoint = Checkpoint(
        sequence=sequence,
        record_hash=cast(str, content["recordHash"]),
        created_at=cast(str, content["createdAt"]),
        created_by=content["createdBy"],
        key_id=cast(str, content["keyId"]),
    )
    return SignedCheckpoint(checkpoint, signature)


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from SubjectPublicKeyInfo PEM."""
    try:
        key = load_pem_public_key(pem)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise KeyFormatError("not a PEM public key") from None
    if not isinstance(key, Ed25519PublicKey):
        raise KeyFormatError("not an Ed25519 public key")
    return key


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    """Load an unencrypted Ed25519 private key from PKCS#8 PEM."""
    try:
        key = load_pem_private_key(pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise KeyFormatError("not an unencrypted PEM private key") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyFormatError("not an Ed25519 private key")
    return key


def _malformed() -> NoReturn:
    raise CheckpointError(CheckpointFailure.MALFORMED)


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_name: str) -> NoReturn:
    raise ValueError("non-finite number")


def _object_with_keys(value: object, keys: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(cast(dict[str, Any], value)) != keys:
        _malformed()
    return cast(dict[str, Any], value)
