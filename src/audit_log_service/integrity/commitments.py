"""Per-value salted payload commitments (requirements FR-6, ADR-0004).

Each scalar leaf of the payload (string, number, boolean, or null) receives its own 128-bit salt
and commitment::

    SHA-256(UTF-8("audit-log/v1/commitment") || 0x00 || RFC8785({"salt": <hex>, "value": <value>}))

Objects and arrays are structure: the committed payload keeps every key and the array shape, with
each scalar leaf replaced by its commitment. Empty objects and arrays stay as they are. A value's
location is not part of its commitment; `contentHash` binds it through the committed structure.

Recoverable values are held apart from the committed structure, as RFC 8785 canonical JSON text
with their salts, keyed by RFC 6901 JSON Pointer.
"""

import hmac
import json
import re
import secrets
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import cast

from audit_log_service.integrity.canonical import (
    COMMITMENT_LABEL,
    JsonScalar,
    JsonValue,
    canonicalize,
    is_number_in_domain,
    is_sha256_hex,
    labeled_sha256,
)
from audit_log_service.integrity.errors import IntegrityInputError

SALT_BYTES = 16
_SALT_HEX = re.compile(r"[0-9a-f]{32}")


@dataclass(frozen=True, slots=True)
class PayloadValue:
    """A recoverable payload value: its RFC 8785 canonical JSON text and its salt.

    Both fields are excluded from repr so that printing or logging never exposes them.
    """

    canonical_text: str = field(repr=False)
    salt: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class CommittedPayload:
    """A payload split into its committed structure and its recoverable values."""

    structure: dict[str, JsonValue] = field(repr=False)
    values: Mapping[str, PayloadValue] = field(repr=False)


def generate_salt() -> str:
    """Return a fresh 128-bit salt from the operating system's CSPRNG, as lowercase hex."""
    return secrets.token_bytes(SALT_BYTES).hex()


def compute_commitment(value: JsonScalar, salt: str) -> str:
    """Compute the commitment for one scalar value and its salt."""
    if isinstance(value, (list, dict)):
        raise IntegrityInputError("only scalar values receive commitments")
    if not isinstance(salt, str) or _SALT_HEX.fullmatch(salt) is None:  # pyright: ignore[reportUnnecessaryIsInstance]
        raise IntegrityInputError("salt must be 32 lowercase hexadecimal characters")
    return labeled_sha256(COMMITMENT_LABEL, {"salt": salt, "value": value})


def commit_payload(payload: dict[str, JsonValue]) -> CommittedPayload:
    """Salt and commit every scalar leaf of a payload object."""
    if not isinstance(payload, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise IntegrityInputError("payload must be a JSON object")
    # Rejects anything outside the JSON profile before any salt is drawn.
    canonicalize(payload)

    values: dict[str, PayloadValue] = {}

    def commit(node: JsonValue, pointer: str) -> JsonValue:
        if isinstance(node, dict):
            return {key: commit(item, f"{pointer}/{_escape(key)}") for key, item in node.items()}
        if isinstance(node, list):
            return [commit(item, f"{pointer}/{index}") for index, item in enumerate(node)]
        salt = generate_salt()
        values[pointer] = PayloadValue(canonical_text=canonicalize(node).decode("utf-8"), salt=salt)
        return compute_commitment(node, salt)

    structure: dict[str, JsonValue] = {
        key: commit(item, f"/{_escape(key)}") for key, item in payload.items()
    }
    return CommittedPayload(structure=structure, values=values)


def is_committed_structure(structure: object) -> bool:
    """Whether a value is a committed payload: an object whose scalar leaves are all hashes."""
    if not isinstance(structure, dict):
        return False
    return all(is_sha256_hex(leaf) for _, leaf in _leaves(cast(object, structure)))


def values_open_commitments(
    structure: Mapping[str, JsonValue], values: Mapping[str, PayloadValue]
) -> bool:
    """Whether every present value opens the commitment at its pointer.

    Only present values are checked. Whether a missing value is authorized depends on retention
    and redaction evidence, which is deferred (requirements FR-3, `PAYLOAD_VALUE_MISSING`).
    """
    commitments = dict(_leaves(structure))
    for pointer, stored in values.items():
        expected = commitments.get(pointer)
        if not is_sha256_hex(expected):
            return False
        try:
            actual = compute_commitment(_parse_value_text(stored.canonical_text), stored.salt)
        except IntegrityInputError:
            return False
        if not hmac.compare_digest(actual, str(expected)):
            return False
    return True


def _leaves(node: object, pointer: str = "") -> Iterator[tuple[str, object]]:
    if isinstance(node, dict):
        for key, item in cast(dict[object, object], node).items():
            yield from _leaves(item, f"{pointer}/{_escape(str(key))}")
    elif isinstance(node, list):
        for index, item in enumerate(cast(list[object], node)):
            yield from _leaves(item, f"{pointer}/{index}")
    else:
        yield pointer, node


def _escape(key: str) -> str:
    # RFC 6901: "~" becomes "~0" and "/" becomes "~1", in that order.
    return key.replace("~", "~0").replace("/", "~1")


def _parse_value_text(text: str) -> JsonScalar:
    try:
        value: object = json.loads(
            text, parse_constant=_reject_constant, parse_float=float, parse_int=int
        )
    except (ValueError, RecursionError):
        raise IntegrityInputError("stored value is not valid JSON") from None
    if isinstance(value, (list, dict)):
        raise IntegrityInputError("stored value is not a scalar")
    if isinstance(value, (int, float)) and not is_number_in_domain(value):
        raise IntegrityInputError("stored value is outside the accepted numeric domain")
    return cast(JsonScalar, value)


def _reject_constant(_name: str) -> float:
    raise ValueError("non-finite number")
