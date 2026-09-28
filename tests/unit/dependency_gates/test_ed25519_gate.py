"""Dependency gate: Ed25519 signing and verification with `cryptography` (ADR-0006, ADR-0007).

Every private key here is generated in memory for the test and discarded. No key material is
written to disk or committed. The RFC 8032 vector is used for verification only, with its public
key, message, and signature.
"""

from collections.abc import Callable

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# RFC 8032 Section 7.1, TEST 2: public key, one-byte message, and signature.
RFC8032_PUBLIC_KEY = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)
RFC8032_MESSAGE = bytes.fromhex("72")
RFC8032_SIGNATURE = bytes.fromhex(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
)

MESSAGE = b"dependency-gate test message"

Modification = Callable[[bytes], bytes]


def _append_byte(data: bytes) -> bytes:
    return data + b"!"


def _flip_first_bit(data: bytes) -> bytes:
    return bytes([data[0] ^ 0x01]) + data[1:]


def _flip_last_bit(data: bytes) -> bytes:
    return data[:-1] + bytes([data[-1] ^ 0x01])


def _truncate(data: bytes) -> bytes:
    return data[:-1]


def test_generated_key_signs_and_verifies() -> None:
    private_key = Ed25519PrivateKey.generate()

    signature = private_key.sign(MESSAGE)

    assert len(signature) == 64
    # Ed25519 signatures are deterministic for a given key and message.
    assert private_key.sign(MESSAGE) == signature
    private_key.public_key().verify(signature, MESSAGE)


@pytest.mark.parametrize(
    "modify", [_append_byte, _flip_first_bit, _truncate], ids=["appended", "flipped", "truncated"]
)
def test_modified_message_is_rejected(modify: Modification) -> None:
    private_key = Ed25519PrivateKey.generate()
    signature = private_key.sign(MESSAGE)

    with pytest.raises(InvalidSignature):
        private_key.public_key().verify(signature, modify(MESSAGE))


@pytest.mark.parametrize(
    "modify",
    [_flip_first_bit, _flip_last_bit, _truncate, _append_byte],
    ids=["first-bit", "last-bit", "truncated", "extended"],
)
def test_modified_signature_is_rejected(modify: Modification) -> None:
    private_key = Ed25519PrivateKey.generate()
    signature = private_key.sign(MESSAGE)

    with pytest.raises(InvalidSignature):
        private_key.public_key().verify(modify(signature), MESSAGE)


def test_signature_from_another_key_is_rejected() -> None:
    signature = Ed25519PrivateKey.generate().sign(MESSAGE)

    with pytest.raises(InvalidSignature):
        Ed25519PrivateKey.generate().public_key().verify(signature, MESSAGE)


def test_raw_public_key_round_trip() -> None:
    public_key = Ed25519PrivateKey.generate().public_key()

    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    assert len(raw) == 32
    assert Ed25519PublicKey.from_public_bytes(raw) == public_key


def test_pem_public_key_round_trip() -> None:
    public_key = Ed25519PrivateKey.generate().public_key()

    pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    loaded = serialization.load_pem_public_key(pem)

    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert isinstance(loaded, Ed25519PublicKey)
    assert loaded == public_key


def test_public_key_of_the_wrong_length_is_rejected() -> None:
    with pytest.raises(ValueError):
        Ed25519PublicKey.from_public_bytes(bytes(31))


def test_private_key_loads_from_in_memory_pkcs8() -> None:
    # Serialized only in memory: shows that a signing key can be loaded from a standard format.
    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    loaded = serialization.load_pem_private_key(pem, password=None)

    assert isinstance(loaded, Ed25519PrivateKey)
    private_key.public_key().verify(loaded.sign(MESSAGE), MESSAGE)


def test_rfc8032_vector_verifies() -> None:
    public_key = Ed25519PublicKey.from_public_bytes(RFC8032_PUBLIC_KEY)

    public_key.verify(RFC8032_SIGNATURE, RFC8032_MESSAGE)
    with pytest.raises(InvalidSignature):
        public_key.verify(_flip_last_bit(RFC8032_SIGNATURE), RFC8032_MESSAGE)


def test_signature_over_canonical_bytes_survives_reordering() -> None:
    # The signature is kept outside the signed content, which is RFC 8785 canonical bytes.
    private_key = Ed25519PrivateKey.generate()
    signature = private_key.sign(rfc8785.dumps({"b": [1, 2], "a": "x"}))

    private_key.public_key().verify(signature, rfc8785.dumps({"a": "x", "b": [1, 2]}))
    with pytest.raises(InvalidSignature):
        private_key.public_key().verify(signature, rfc8785.dumps({"a": "y", "b": [1, 2]}))
