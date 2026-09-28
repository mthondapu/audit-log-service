"""Unit tests for redaction request validation (FR-6, Phase 8 decisions 4 and 5)."""

from typing import Any

import pytest

from audit_log_service.application.events import SubmissionError
from audit_log_service.application.redactions import (
    MAX_PATHS,
    MAX_REASON_LENGTH,
    parse_redaction_request,
)


def _error(document: object) -> str:
    with pytest.raises(SubmissionError) as caught:
        parse_redaction_request(document)
    return str(caught.value)


@pytest.mark.parametrize(
    "paths",
    [
        [""],
        ["/card"],
        ["/a~1b", "/a~0b"],
        ["/items/0/sku"],
        ["/"],
        ["/nested/"],
        ["/card", "/card"],
    ],
    ids=["root", "leaf", "escaped", "array-index", "empty-key", "trailing-empty-key", "duplicate"],
)
def test_valid_pointers_are_accepted(paths: list[str]) -> None:
    assert parse_redaction_request({"paths": paths, "reason": "privacy"}).paths == paths


def test_reason_is_kept_exactly() -> None:
    reason = "  Customer request #42\n  "
    assert parse_redaction_request({"paths": ["/a"], "reason": reason}).reason == reason


def test_limits_are_inclusive() -> None:
    request = parse_redaction_request(
        {"paths": ["/a"] * MAX_PATHS, "reason": "r" * MAX_REASON_LENGTH}
    )
    assert (len(request.paths), len(request.reason)) == (MAX_PATHS, MAX_REASON_LENGTH)


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({"paths": [], "reason": "r"}, "paths"),
        ({"paths": ["/a"] * (MAX_PATHS + 1), "reason": "r"}, "paths"),
        ({"paths": "/a", "reason": "r"}, "paths"),
        ({"paths": [1], "reason": "r"}, "paths"),
        ({"reason": "r"}, "paths"),
        ({"paths": ["/a"]}, "reason"),
        ({"paths": ["/a"], "reason": ""}, "reason"),
        ({"paths": ["/a"], "reason": "r" * (MAX_REASON_LENGTH + 1)}, "reason"),
        ({"paths": ["/a"], "reason": 7}, "reason"),
        ({"paths": ["/a"], "reason": " \t\n "}, "reason must not be empty or whitespace only"),
        ({"paths": ["/a"], "reason": "a\x00b"}, "reason contains a character"),
        # Pydantic rejects the unpaired surrogate itself, still on the reason field.
        ({"paths": ["/a"], "reason": "a" + chr(0xD800)}, "reason"),
        ({"paths": ["/a"], "reason": "r", "target": "x"}, "an unknown field"),
        ([], "Input should be"),
    ],
    ids=[
        "no-paths",
        "too-many-paths",
        "paths-not-list",
        "path-not-string",
        "paths-missing",
        "reason-missing",
        "reason-empty",
        "reason-too-long",
        "reason-not-string",
        "reason-whitespace",
        "reason-nul",
        "reason-surrogate",
        "unknown-field",
        "not-an-object",
    ],
)
def test_invalid_requests_are_rejected(document: Any, expected: str) -> None:
    assert expected in _error(document)


@pytest.mark.parametrize(
    ("paths", "position"),
    [(["card"], 0), (["/a", "/b~2"], 1), (["/a", "/b", "/c~"], 2), (["/a\x00"], 0)],
    ids=["no-leading-slash", "bad-escape", "trailing-tilde", "nul"],
)
def test_invalid_pointers_are_identified_by_position_only(paths: list[str], position: int) -> None:
    message = _error({"paths": paths, "reason": "r"})
    assert message == f"paths[{position}] is not a valid JSON Pointer"


def test_errors_do_not_echo_submitted_values() -> None:
    secret = "4111-1111-1111-1111"
    for document in (
        {"paths": [secret], "reason": "r"},
        {"paths": ["/a"], "reason": secret + "\x00"},
        {"paths": ["/a"], "reason": "r", secret: 1},
    ):
        assert secret not in _error(document)
