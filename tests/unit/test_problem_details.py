"""Tests for the RFC 9457 Problem Details used for authentication and authorization failures."""

from collections.abc import Mapping

from audit_log_service.problem_details import (
    PROBLEM_JSON_MEDIA_TYPE,
    authentication_failure,
    authorization_failure,
)


def test_authentication_failure_is_401_with_bearer_challenge() -> None:
    problem = authentication_failure()

    assert problem.status == 401
    assert problem.headers == {"WWW-Authenticate": "Bearer"}
    assert problem.media_type == PROBLEM_JSON_MEDIA_TYPE
    assert problem.body == {
        "type": "about:blank",
        "title": "Unauthorized",
        "status": 401,
        "detail": "Valid Bearer credentials are required.",
    }


def test_authentication_failure_is_identical_for_every_cause() -> None:
    assert authentication_failure() == authentication_failure()


def test_authorization_failure_is_403_without_challenge() -> None:
    problem = authorization_failure()

    assert problem.status == 403
    assert "WWW-Authenticate" not in problem.headers
    assert problem.body["title"] == "Forbidden"
    assert problem.body["status"] == 403


def test_request_id_is_included_when_provided() -> None:
    assert authentication_failure(request_id="req-123").body["requestId"] == "req-123"
    assert authorization_failure(request_id="req-456").body["requestId"] == "req-456"


def test_problem_bodies_contain_no_credentials(fake_keys: Mapping[str, str]) -> None:
    rendered = repr(authentication_failure().body) + repr(authorization_failure().body)
    for key in fake_keys.values():
        assert key not in rendered
