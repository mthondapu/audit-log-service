"""Problem Details responses and the per-request identifier (NFR-7, Phase 5 decisions D3, D4)."""

from fastapi import Request
from fastapi.responses import JSONResponse

from audit_log_service.problem_details import ProblemResponse


class ApiProblem(Exception):
    """Raised by handlers to return a Problem Details response."""

    def __init__(self, response: ProblemResponse) -> None:
        super().__init__(response.status)
        self.response = response


def request_id_of(request: Request) -> str:
    request_id: str = request.state.request_id
    return request_id


def problem_json(response: ProblemResponse) -> JSONResponse:
    return JSONResponse(
        dict(response.body),
        status_code=response.status,
        headers=dict(response.headers),
        media_type=response.media_type,
    )
