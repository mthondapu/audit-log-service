"""Export request validation: exactly one allowed scope, with the FR-2 rules (FR-7, E16)."""

from typing import Any

import pytest

from audit_log_service.application.events import SubmissionError
from audit_log_service.application.exports import SCOPE_ERROR, parse_export_request


@pytest.mark.parametrize(
    "body",
    [
        {"actorId": "user-7"},
        {"resourceId": "acct-42"},
        {"resourceId": "acct-42", "resourceType": "CLIENT_ACCOUNT"},
        {"actorId": "a" * 256},
    ],
    ids=["actor", "resource", "resource-and-type", "longest-identifier"],
)
def test_allowed_scopes_are_accepted(body: dict[str, str]) -> None:
    assert parse_export_request(body) == body


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"resourceType": "CLIENT_ACCOUNT"},
        {"actorId": "user-7", "resourceType": "CLIENT_ACCOUNT"},
        {"actorId": "user-7", "resourceId": "acct-42"},
        {"actorId": "user-7", "resourceId": "acct-42", "resourceType": "CLIENT_ACCOUNT"},
        {"actorId": None},
        {"resourceId": "acct-42", "resourceType": None},
    ],
    ids=[
        "empty",
        "type-only",
        "actor-and-type",
        "actor-and-resource",
        "all-three",
        "null-actor",
        "null-type",
    ],
)
def test_other_combinations_are_rejected(body: dict[str, Any]) -> None:
    with pytest.raises(SubmissionError) as caught:
        parse_export_request(body)
    assert str(caught.value) == SCOPE_ERROR


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"actorId": ""}, "actorId: String should have at least 1 character"),
        ({"actorId": "a" * 257}, "actorId: String should have at most 256 characters"),
        ({"actorId": 7}, "actorId: Input should be a valid string"),
        ({"resourceId": "r", "resourceType": "client"}, "resourceType: String should match"),
        ({"actorId": "user-7", "limit": 5}, "an unknown field: field is not accepted"),
        (["actorId"], "Input should be a valid dictionary or instance of ExportRequest"),
        ({"actorId": "bad" + chr(0) + "id"}, "actorId contains a character that is not allowed"),
        ({"resourceId": "bad" + chr(0xD800)}, "resourceId: Input should be a valid string"),
    ],
    ids=[
        "empty",
        "too-long",
        "number",
        "type-pattern",
        "unknown",
        "not-object",
        "nul",
        "surrogate",
    ],
)
def test_invalid_fields_are_rejected_without_echoing_input(body: object, message: str) -> None:
    with pytest.raises(SubmissionError) as caught:
        parse_export_request(body)
    assert str(caught.value).startswith(message)
    assert "bad" not in str(caught.value)
