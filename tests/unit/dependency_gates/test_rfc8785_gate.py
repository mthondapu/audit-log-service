"""Dependency gate: the `rfc8785` library against RFC 8785 and the FR-1 input profile (ADR-0002).

These tests establish that the adopted library canonicalizes as the approved design requires. The
RFC's published examples test library conformance and include numbers outside the service's
numeric domain; the FR-1 tests below apply that domain. No audit-log hash input is defined here.
"""

import hashlib
import json
import math
import struct
from typing import Any

import pytest
import rfc8785
from hypothesis import given
from hypothesis import strategies as st

MAX_SAFE_INTEGER = 2**53 - 1
BACKSLASH = chr(0x5C)

# RFC 8785 Section 3.2.2 sample input, as Python values. The string is built from code points so
# that the escapes in the RFC's JSON text cannot be misread.
RFC_SAMPLE = {
    "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
    "string": "".join(
        map(chr, [0x20AC, 0x24, 0x0F, 0x0A, 0x41, 0x27, 0x42, 0x22, 0x5C, 0x5C, 0x22, 0x2F])
    ),
    "literals": [None, True, False],
}

# RFC 8785 Section 3.2.4: the canonical UTF-8 bytes of the sample above.
RFC_SAMPLE_CANONICAL_HEX = (
    "7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72"
    "75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a"
    "5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31"
    "65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37"
    "5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30"
    "30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d"
)

# RFC 8785 Appendix B: IEEE 754 bit patterns and their canonical number serialization.
RFC_NUMBER_SAMPLES = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


def _double(bits_hex: str) -> float:
    value: float = struct.unpack(">d", bytes.fromhex(bits_hex))[0]
    return value


def test_rfc_sample_canonicalizes_to_the_published_bytes() -> None:
    canonical = rfc8785.dumps(RFC_SAMPLE)

    assert isinstance(canonical, bytes)
    assert canonical == bytes.fromhex(RFC_SAMPLE_CANONICAL_HEX)
    # The output is UTF-8 bytes, directly usable as SHA-256 input.
    canonical.decode("utf-8")
    assert len(hashlib.sha256(canonical).digest()) == 32


def test_rfc_property_sorting_sample_uses_utf16_code_unit_order() -> None:
    # RFC 8785 Section 3.2.3 test data; values name the keys.
    data = {
        chr(0x20AC): "Euro Sign",
        chr(0x0D): "Carriage Return",
        chr(0xFB33): "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        chr(0x1F600): "Emoji: Grinning Face",
        chr(0x80): "Control",
        chr(0xF6): "Latin Small Letter O With Diaeresis",
    }

    ordered_values = list(json.loads(rfc8785.dumps(data)).values())

    assert ordered_values == [
        "Carriage Return",
        "One",
        "Control",
        "Latin Small Letter O With Diaeresis",
        "Euro Sign",
        "Emoji: Grinning Face",
        "Hebrew Letter Dalet With Dagesh",
    ]


@pytest.mark.parametrize(("bits_hex", "expected"), RFC_NUMBER_SAMPLES)
def test_rfc_number_samples(bits_hex: str, expected: str) -> None:
    assert rfc8785.dumps(_double(bits_hex)) == expected.encode("ascii")


def test_nested_objects_are_sorted_recursively_and_arrays_keep_their_order() -> None:
    value = {"b": [{"d": 1, "c": 2}, 3], "a": {"z": None, "y": chr(0xE9)}}

    assert (
        rfc8785.dumps(value)
        == ('{"a":{"y":"' + chr(0xE9) + '","z":null},"b":[{"c":2,"d":1},3]}').encode()
    )


def test_insertion_order_does_not_affect_output() -> None:
    assert rfc8785.dumps({"a": 1, "b": [1, 2]}) == rfc8785.dumps({"b": [1, 2], "a": 1})


def test_booleans_are_not_serialized_as_integers() -> None:
    assert rfc8785.dumps([True, False, 1, 0]) == b"[true,false,1,0]"


@pytest.mark.parametrize("value", [MAX_SAFE_INTEGER, -MAX_SAFE_INTEGER])
def test_integers_at_the_fr1_bounds_are_accepted(value: int) -> None:
    assert rfc8785.dumps(value) == str(value).encode("ascii")


@pytest.mark.parametrize("value", [MAX_SAFE_INTEGER + 1, -MAX_SAFE_INTEGER - 1])
def test_integers_beyond_the_fr1_bounds_are_rejected(value: int) -> None:
    with pytest.raises(rfc8785.IntegerDomainError):
        rfc8785.dumps(value)


@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), float("-inf"), _double("7fffffffffffffff")],
    ids=["nan", "infinity", "negative-infinity", "rfc-nan-bits"],
)
def test_non_finite_numbers_are_rejected(value: float) -> None:
    with pytest.raises(rfc8785.FloatDomainError):
        rfc8785.dumps({"n": value})


@pytest.mark.parametrize(
    "json_text",
    [
        pytest.param(f'"{BACKSLASH}ud800"', id="lone-high-surrogate-in-value"),
        pytest.param(f'"{BACKSLASH}ude00"', id="lone-low-surrogate-in-value"),
        pytest.param(f'"{BACKSLASH}ude00{BACKSLASH}ud83d"', id="reversed-pair-in-value"),
        pytest.param(f'{{"{BACKSLASH}udead": 1}}', id="lone-surrogate-in-key"),
    ],
)
def test_unpaired_surrogates_are_rejected(json_text: str) -> None:
    # Python's JSON parser accepts escaped lone surrogates, so canonicalization must reject them.
    # The library raises CanonicalizationError for values but UnicodeEncodeError for keys; both
    # are ValueError subclasses.
    value = json.loads(json_text)
    with pytest.raises(ValueError):
        rfc8785.dumps(value)


def test_escaped_surrogate_pair_is_a_valid_character() -> None:
    value = json.loads(f'"{BACKSLASH}ud83d{BACKSLASH}ude00"')
    assert rfc8785.dumps(value) == ('"' + chr(0x1F600) + '"').encode()


@pytest.mark.parametrize(
    "value",
    [b"bytes", {1, 2}, {1: "non-string key"}],
    ids=["bytes", "set", "non-string-key"],
)
def test_values_outside_the_json_data_model_are_rejected(value: Any) -> None:
    # Typed Any because these values are deliberately outside the library's accepted types.
    with pytest.raises(rfc8785.CanonicalizationError):
        rfc8785.dumps(value)


def _reject_constant(name: str) -> float:
    raise ValueError(f"non-finite number {name} is not accepted")


def _parse_int(text: str) -> int:
    value = int(text)
    if abs(value) > MAX_SAFE_INTEGER:
        raise ValueError("integer outside the accepted numeric domain")
    return value


def _parse_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value) or abs(value) > MAX_SAFE_INTEGER:
        raise ValueError("number outside the accepted numeric domain")
    return value


def parse_with_fr1_number_rules(text: str) -> Any:
    """Reference parse for this gate, applying the FR-1 numeric domain by value, not notation.

    Integers are taken exactly; fractional and exponent numbers are interpreted as IEEE-754
    doubles. Every number must be finite and within +/-(2^53 - 1). This is not the service's
    request validator, which belongs to the API phase.
    """
    return json.loads(
        text, parse_int=_parse_int, parse_float=_parse_float, parse_constant=_reject_constant
    )


@pytest.mark.parametrize(
    "json_text",
    [
        "9007199254740991",
        "-9007199254740991",
        "9007199254740991.0",
        "-9007199254740991.0",
        "9.007199254740991e15",
        "-9.007199254740991E+15",
        # The domain applies to the IEEE-754 double: this rounds to 2^53 - 1.
        pytest.param("9007199254740991.4", id="fraction-rounding-to-max"),
        "0.5",
        "-123.456",
        "1e-7",
        "4.5e15",
        "1E3",
    ],
)
def test_numbers_within_the_domain_are_accepted_and_round_trip(json_text: str) -> None:
    value = parse_with_fr1_number_rules(json_text)
    canonical = rfc8785.dumps(value)

    assert rfc8785.dumps(parse_with_fr1_number_rules(canonical.decode("utf-8"))) == canonical


@pytest.mark.parametrize(
    "json_text",
    [
        "9007199254740992",
        "-9007199254740992",
        "9007199254740992.0",
        "-9007199254740992.0",
        "9.007199254740992e15",
        # The domain applies to the IEEE-754 double: this rounds to 2^53.
        pytest.param("9007199254740991.5", id="fraction-rounding-to-2^53"),
        "1e16",
        "-1e16",
        "1e20",
        "1e21",
        "1e300",
        "-1e300",
        "1e400",
        "NaN",
        "-Infinity",
    ],
)
def test_numbers_outside_the_domain_are_rejected_whatever_the_notation(json_text: str) -> None:
    with pytest.raises(ValueError):
        parse_with_fr1_number_rules(json_text)


def test_whole_number_doubles_beyond_the_domain_canonicalize_as_plain_digits() -> None:
    # Why the domain bound exists: RFC 8785 writes this double as integer digits, which would be
    # read back as an out-of-range integer. The bound keeps such values from being accepted.
    canonical = rfc8785.dumps(1e16)

    assert canonical == b"10000000000000000"
    with pytest.raises(ValueError):
        parse_with_fr1_number_rules(canonical.decode("utf-8"))


_TEXT = st.text(alphabet=st.characters(exclude_categories=("Cs",)))
_accepted_scalars = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-MAX_SAFE_INTEGER, max_value=MAX_SAFE_INTEGER)
    | st.floats(min_value=-MAX_SAFE_INTEGER, max_value=MAX_SAFE_INTEGER, allow_nan=False)
    | _TEXT
)
_accepted_values = st.recursive(
    _accepted_scalars,
    lambda children: st.lists(children, max_size=4) | st.dictionaries(_TEXT, children, max_size=4),
    max_leaves=20,
)


@given(value=_accepted_values)
def test_accepted_values_survive_the_canonical_round_trip(value: Any) -> None:
    # accepted value -> canonical bytes -> parse under the FR-1 number rules -> canonical bytes
    canonical = rfc8785.dumps(value)

    assert rfc8785.dumps(value) == canonical
    assert rfc8785.dumps(parse_with_fr1_number_rules(canonical.decode("utf-8"))) == canonical


@given(
    value=st.floats(allow_nan=False, allow_infinity=False).filter(
        lambda x: abs(x) > MAX_SAFE_INTEGER
    )
)
def test_canonical_text_of_out_of_domain_numbers_is_rejected(value: float) -> None:
    with pytest.raises(ValueError):
        parse_with_fr1_number_rules(rfc8785.dumps(value).decode("utf-8"))
