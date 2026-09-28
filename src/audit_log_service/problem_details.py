"""RFC 9457 Problem Details responses (NFR-7, D4).

These builders return plain data so they can be tested without HTTP routing; the API layer turns
them into responses. Bodies are fixed text and never include credentials, hashes, or input.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from http import HTTPStatus
from types import MappingProxyType

PROBLEM_JSON_MEDIA_TYPE = "application/problem+json"


@dataclass(frozen=True, slots=True)
class ProblemResponse:
    status: int
    body: Mapping[str, object]
    headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    media_type: str = PROBLEM_JSON_MEDIA_TYPE


def _problem_body(
    *, title: str, status: int, detail: str, request_id: str | None
) -> Mapping[str, object]:
    body: dict[str, object] = {
        "type": "about:blank",
        "title": title,
        "status": status,
        "detail": detail,
    }
    if request_id is not None:
        body["requestId"] = request_id
    return MappingProxyType(body)


def problem(status: int, detail: str, request_id: str | None = None) -> ProblemResponse:
    """A Problem Details response with the standard title for `status` and a fixed detail."""
    return ProblemResponse(
        status=status,
        body=_problem_body(
            title=HTTPStatus(status).phrase, status=status, detail=detail, request_id=request_id
        ),
    )


def authentication_failure(request_id: str | None = None) -> ProblemResponse:
    """The single response used for every authentication failure: 401 with a Bearer challenge."""
    return ProblemResponse(
        status=401,
        body=_problem_body(
            title="Unauthorized",
            status=401,
            detail="Valid Bearer credentials are required.",
            request_id=request_id,
        ),
        headers=MappingProxyType({"WWW-Authenticate": "Bearer"}),
    )


def authorization_failure(request_id: str | None = None) -> ProblemResponse:
    """The response for an authenticated principal that lacks the required capability."""
    return ProblemResponse(
        status=403,
        body=_problem_body(
            title="Forbidden",
            status=403,
            detail="The authenticated principal is not permitted to perform this operation.",
            request_id=request_id,
        ),
    )
