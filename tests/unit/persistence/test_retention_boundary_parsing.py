"""Parsing a retention event's upToSequence (FR-5, Phase 9 decision 9)."""

import pytest

from audit_log_service.persistence.retention import retention_up_to_sequence


@pytest.mark.parametrize(("text", "expected"), [("1", 1), ("4", 4)])
def test_valid_boundaries_below_the_event_are_accepted(text: str, expected: int) -> None:
    assert retention_up_to_sequence(text, 5) == expected


@pytest.mark.parametrize(
    "text",
    ["5", "6", "0", "-1", "2.5", '"2"', "true", "null", "not json", ""],
    ids=["own", "above", "zero", "negative", "fraction", "string", "bool", "null", "text", "empty"],
)
def test_invalid_boundaries_are_rejected(text: str) -> None:
    assert retention_up_to_sequence(text, 5) is None
