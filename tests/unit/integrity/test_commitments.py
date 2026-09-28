"""Tests for per-value salted payload commitments."""

import hashlib
import secrets
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from audit_log_service.integrity.canonical import (
    MAX_SAFE_INTEGER,
    JsonValue,
    canonicalize,
    is_sha256_hex,
)
from audit_log_service.integrity.commitments import (
    SALT_BYTES,
    PayloadValue,
    commit_payload,
    compute_commitment,
    generate_salt,
    values_open_commitments,
)
from audit_log_service.integrity.errors import IntegrityInputError

SALT_A = "00112233445566778899aabbccddeeff"
SALT_B = "ffeeddccbbaa99887766554433221100"

_TEXT = st.text(alphabet=st.characters(exclude_categories=("Cs",)))
_scalars = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-MAX_SAFE_INTEGER, max_value=MAX_SAFE_INTEGER)
    | st.floats(min_value=-MAX_SAFE_INTEGER, max_value=MAX_SAFE_INTEGER, allow_nan=False)
    | _TEXT
)
_salts = st.binary(min_size=SALT_BYTES, max_size=SALT_BYTES).map(bytes.hex)
_payloads = st.dictionaries(
    _TEXT,
    st.recursive(
        _scalars,
        lambda children: (
            st.lists(children, max_size=3) | st.dictionaries(_TEXT, children, max_size=3)
        ),
        max_leaves=10,
    ),
    max_size=4,
)


def test_commitment_formula() -> None:
    # Expected value computed independently from the literal hash input bytes.
    expected = hashlib.sha256(
        b'audit-log/v1/commitment\x00{"salt":"' + SALT_A.encode() + b'","value":"card-ending-42"}'
    ).hexdigest()

    assert compute_commitment("card-ending-42", SALT_A) == expected


def test_salt_is_128_bits_from_the_csprng(monkeypatch: pytest.MonkeyPatch) -> None:
    requested: list[int] = []

    def fake_token_bytes(size: int) -> bytes:
        requested.append(size)
        return bytes(range(size))

    monkeypatch.setattr(secrets, "token_bytes", fake_token_bytes)

    assert generate_salt() == bytes(range(16)).hex()
    assert requested == [16]


def test_generated_salts_are_lowercase_hex_and_distinct() -> None:
    salts = {generate_salt() for _ in range(64)}

    assert len(salts) == 64
    assert all(len(salt) == 32 and salt == salt.lower() for salt in salts)
    bytes.fromhex(next(iter(salts)))


@given(value=_scalars, salt=_salts)
def test_commitment_is_deterministic(value: Any, salt: str) -> None:
    assert compute_commitment(value, salt) == compute_commitment(value, salt)


@given(value=_scalars, salt=_salts, other_salt=_salts)
def test_different_salts_give_different_commitments(value: Any, salt: str, other_salt: str) -> None:
    assume(salt != other_salt)
    assert compute_commitment(value, salt) != compute_commitment(value, other_salt)


@given(value=_scalars, other=_scalars, salt=_salts)
def test_different_values_give_different_commitments(value: Any, other: Any, salt: str) -> None:
    # Values that canonicalize identically (such as 1 and 1.0) are the same JSON value.
    assume(canonicalize(value) != canonicalize(other))
    assert compute_commitment(value, salt) != compute_commitment(other, salt)


@pytest.mark.parametrize(
    "salt",
    [SALT_A.upper(), SALT_A[:-1], SALT_A + "0", "g" * 32, ""],
    ids=["uppercase", "short", "long", "non-hex", "empty"],
)
def test_malformed_salt_is_rejected(salt: str) -> None:
    with pytest.raises(IntegrityInputError, match="salt"):
        compute_commitment("value", salt)


@pytest.mark.parametrize("value", [[1], {"a": 1}], ids=["array", "object"])
def test_only_scalars_receive_commitments(value: Any) -> None:
    with pytest.raises(IntegrityInputError, match="scalar"):
        compute_commitment(value, SALT_A)


def test_committed_structure_preserves_shape_and_replaces_leaves() -> None:
    payload: dict[str, JsonValue] = {
        "amount": 12.5,
        "items": [{"sku": "A-1", "qty": 2}, None, []],
        "meta": {},
        "a/b~c": True,
    }

    committed = commit_payload(payload)

    structure = committed.structure
    assert set(structure) == {"amount", "items", "meta", "a/b~c"}
    assert structure["meta"] == {}
    items = structure["items"]
    assert isinstance(items, list)
    assert len(items) == 3
    assert items[2] == []
    assert isinstance(items[0], dict)
    assert set(items[0]) == {"sku", "qty"}
    assert set(committed.values) == {
        "/amount",
        "/items/0/sku",
        "/items/0/qty",
        "/items/1",
        "/a~1b~0c",
    }
    stored = committed.values["/items/0/sku"]
    assert stored.canonical_text == '"A-1"'
    assert items[0]["sku"] == compute_commitment("A-1", stored.salt)


@given(payload=_payloads)
def test_committed_values_open_and_raw_values_stay_out_of_the_structure(
    payload: dict[str, Any],
) -> None:
    committed = commit_payload(payload)

    assert values_open_commitments(committed.structure, committed.values)
    leaves = _leaves(committed.structure)
    assert all(is_sha256_hex(leaf) for leaf in leaves)
    assert len(leaves) == len(committed.values)
    assert len({value.salt for value in committed.values.values()}) == len(committed.values)


def _leaves(node: Any) -> list[Any]:
    if isinstance(node, dict):
        return [leaf for item in node.values() for leaf in _leaves(item)]  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
    if isinstance(node, list):
        return [leaf for item in node for leaf in _leaves(item)]  # pyright: ignore[reportUnknownVariableType]
    return [node]


def test_empty_payload_has_no_values() -> None:
    committed = commit_payload({})
    assert committed.structure == {}
    assert committed.values == {}


@pytest.mark.parametrize(
    "payload",
    [[1], "text", {"a": {1, 2}}, {"a": 1e16}, {"a": float("nan")}],
    ids=["array-root", "scalar-root", "set", "out-of-domain", "nan"],
)
def test_invalid_payload_is_rejected(payload: Any) -> None:
    with pytest.raises(IntegrityInputError):
        commit_payload(payload)


Change = Callable[[PayloadValue], PayloadValue]


def _with_text(text: str) -> Change:
    return lambda value: PayloadValue(canonical_text=text, salt=value.salt)


def _with_salt(salt_of: Callable[[str], str]) -> Change:
    return lambda value: PayloadValue(canonical_text=value.canonical_text, salt=salt_of(value.salt))


@pytest.mark.parametrize(
    "change",
    [
        pytest.param(_with_text('"altered"'), id="changed-value"),
        pytest.param(_with_salt(lambda _: SALT_B), id="changed-salt"),
        pytest.param(_with_salt(str.upper), id="malformed-salt"),
        pytest.param(_with_text("not json"), id="invalid-json"),
        pytest.param(_with_text("NaN"), id="non-finite"),
        pytest.param(_with_text("1e16"), id="out-of-domain"),
        pytest.param(_with_text("[1]"), id="non-scalar"),
    ],
)
def test_tampered_value_does_not_open(change: Change) -> None:
    committed = commit_payload({"field": "original"})
    values = dict(committed.values)
    values["/field"] = change(values["/field"])

    assert not values_open_commitments(committed.structure, values)


@pytest.mark.parametrize(
    "pointer", ["/missing", "/nested", ""], ids=["unknown", "container", "root"]
)
def test_value_at_a_non_leaf_pointer_does_not_open(pointer: str) -> None:
    committed = commit_payload({"field": "x", "nested": {"inner": 1}})
    values = {pointer: committed.values["/field"]}

    assert not values_open_commitments(committed.structure, values)


def test_swapped_values_do_not_open() -> None:
    committed = commit_payload({"a": "first", "b": "second"})
    swapped = {"/a": committed.values["/b"], "/b": committed.values["/a"]}

    assert not values_open_commitments(committed.structure, swapped)


def test_missing_values_are_not_checked_in_this_phase() -> None:
    # PAYLOAD_VALUE_MISSING and its authorization rule are deferred to retention and redaction.
    committed = commit_payload({"a": "first", "b": "second"})
    only_a = {"/a": committed.values["/a"]}

    assert values_open_commitments(committed.structure, only_a)


def test_repr_does_not_expose_values_or_salts() -> None:
    committed = commit_payload({"card": "4111-secret"})
    stored = committed.values["/card"]

    for text in (repr(committed), repr(stored)):
        assert "4111-secret" not in text
        assert stored.salt not in text
