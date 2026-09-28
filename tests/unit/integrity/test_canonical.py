"""Tests for the canonicalization boundary and domain-separated hashing."""

import hashlib
import json
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from audit_log_service.integrity.canonical import (
    COMMITMENT_LABEL,
    CONTENT_LABEL,
    MAX_SAFE_INTEGER,
    RECORD_LABEL,
    SCHEME,
    canonicalize,
    is_sha256_hex,
    labeled_sha256,
)
from audit_log_service.integrity.errors import IntegrityInputError

BACKSLASH = chr(0x5C)
_TEXT = st.text(alphabet=st.characters(exclude_categories=("Cs",)))
_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-MAX_SAFE_INTEGER, max_value=MAX_SAFE_INTEGER)
    | st.floats(min_value=-MAX_SAFE_INTEGER, max_value=MAX_SAFE_INTEGER, allow_nan=False)
    | _TEXT,
    lambda children: st.lists(children, max_size=4) | st.dictionaries(_TEXT, children, max_size=4),
    max_leaves=20,
)


def test_labels_are_the_approved_strings() -> None:
    assert SCHEME == "audit-log/v1"
    assert CONTENT_LABEL == "audit-log/v1/content"
    assert RECORD_LABEL == "audit-log/v1/record"
    assert COMMITMENT_LABEL == "audit-log/v1/commitment"


def test_labeled_hash_is_label_zero_byte_then_canonical_json() -> None:
    # Expected value computed independently from the literal hash input bytes.
    expected = hashlib.sha256(b'audit-log/v1/content\x00{"a":[1,true],"b":null}').hexdigest()

    assert labeled_sha256(CONTENT_LABEL, {"b": None, "a": [1, True]}) == expected


@given(value=_values)
def test_canonicalization_is_deterministic_and_idempotent(value: Any) -> None:
    canonical = canonicalize(value)

    assert canonicalize(value) == canonical
    assert canonicalize(json.loads(canonical)) == canonical


@given(value=_values)
def test_labels_separate_hash_domains(value: Any) -> None:
    hashes = {labeled_sha256(label, value) for label in (CONTENT_LABEL, RECORD_LABEL)}
    assert len(hashes) == 2
    assert all(is_sha256_hex(digest) for digest in hashes)


@pytest.mark.parametrize(
    "value",
    [
        MAX_SAFE_INTEGER + 1,
        -MAX_SAFE_INTEGER - 1,
        float(2**53),
        1e16,
        1e21,
        -1e300,
        float("nan"),
        float("inf"),
        [1, {"nested": 1e16}],
    ],
    ids=[
        "int-above",
        "int-below",
        "float-2^53",
        "1e16",
        "1e21",
        "-1e300",
        "nan",
        "infinity",
        "nested",
    ],
)
def test_numbers_outside_the_domain_are_rejected_by_value(value: Any) -> None:
    with pytest.raises(IntegrityInputError, match="numeric domain"):
        canonicalize(value)


@pytest.mark.parametrize("value", [MAX_SAFE_INTEGER, -MAX_SAFE_INTEGER, 9007199254740991.0, 0.5])
def test_numbers_within_the_domain_are_accepted(value: int | float) -> None:
    canonicalize({"n": value})


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ({1: "x"}, "keys must be strings"),
        ({"a": {1, 2}}, "unsupported value type"),
        (b"bytes", "unsupported value type"),
        ((1, 2), "unsupported value type"),
        (object(), "unsupported value type"),
        (json.loads(f'"{BACKSLASH}ud800"'), "cannot be canonicalized"),
        (json.loads(f'{{"{BACKSLASH}udead": 1}}'), "cannot be canonicalized"),
    ],
    ids=["non-string-key", "set", "bytes", "tuple", "object", "surrogate-value", "surrogate-key"],
)
def test_values_outside_the_json_profile_are_rejected(value: Any, message: str) -> None:
    with pytest.raises(IntegrityInputError, match=message):
        canonicalize(value)


def test_errors_do_not_echo_the_offending_value() -> None:
    secret = "sensitive-payload-value"
    invalid: tuple[Any, ...] = ({secret: {1, 2}}, {"k": [secret, 10**20]})
    for value in invalid:
        with pytest.raises(IntegrityInputError) as caught:
            canonicalize(value)
        assert secret not in str(caught.value)
        assert "100000000000000000000" not in str(caught.value)
        assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("0" * 64, True),
        ("ab" * 32, True),
        ("AB" * 32, False),
        ("0" * 63, False),
        ("0" * 65, False),
        ("g" * 64, False),
        (None, False),
    ],
)
def test_hash_format(text: object, expected: bool) -> None:
    assert is_sha256_hex(text) is expected
