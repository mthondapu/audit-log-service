"""Canonicalization and domain-separated hashing (ADR-0002).

RFC 8785 canonicalization is delegated to the `rfc8785` library. This module adds the service's own
numeric domain (requirements FR-1): every number, whatever its notation, must be finite and within
+/-(2^53 - 1), evaluated as the IEEE-754 double. RFC 8785 itself does not impose that bound.

Every hash input is ``UTF-8(label) || 0x00 || RFC8785(object)``, hashed with SHA-256 and written as
lowercase hexadecimal.
"""

import hashlib
import math
import re
from typing import cast

import rfc8785

from audit_log_service.integrity.errors import IntegrityInputError

SCHEME = "audit-log/v1"
CONTENT_LABEL = "audit-log/v1/content"
RECORD_LABEL = "audit-log/v1/record"
COMMITMENT_LABEL = "audit-log/v1/commitment"

MAX_SAFE_INTEGER = 2**53 - 1
_LABEL_SEPARATOR = b"\x00"
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


def canonicalize(value: JsonValue) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes of a value within the service's JSON profile."""
    _check_profile(value)
    try:
        return rfc8785.dumps(value)
    except ValueError:
        # Covers the library's CanonicalizationError and the UnicodeEncodeError it raises for an
        # unpaired surrogate in a key. The original message may contain the value, so drop it.
        raise IntegrityInputError("value cannot be canonicalized") from None


def labeled_sha256(label: str, value: JsonValue) -> str:
    """Hash a value under a domain label: SHA-256(UTF-8(label) || 0x00 || RFC8785(value))."""
    digest = hashlib.sha256(label.encode("utf-8") + _LABEL_SEPARATOR + canonicalize(value))
    return digest.hexdigest()


def is_sha256_hex(text: object) -> bool:
    """Whether a value is a well-formed hash: exactly 64 lowercase hexadecimal characters."""
    return isinstance(text, str) and _SHA256_HEX.fullmatch(text) is not None


def is_number_in_domain(value: int | float) -> bool:
    """Whether a number is finite and within +/-(2^53 - 1) (requirements FR-1)."""
    if isinstance(value, float) and not math.isfinite(value):
        return False
    return abs(value) <= MAX_SAFE_INTEGER


def _check_profile(value: object) -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, (int, float)):
        if not is_number_in_domain(value):
            raise IntegrityInputError("number outside the accepted numeric domain")
        return
    if isinstance(value, list):
        for item in cast(list[object], value):
            _check_profile(item)
        return
    if isinstance(value, dict):
        for key, item in cast(dict[object, object], value).items():
            if not isinstance(key, str):
                raise IntegrityInputError("object keys must be strings")
            _check_profile(item)
        return
    raise IntegrityInputError("unsupported value type")
