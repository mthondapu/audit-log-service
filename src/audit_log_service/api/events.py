"""`POST /audit/events` and `GET /audit/events/{id}`.

Each handler follows the D4 order: authenticate, authorize, validate, then look up or append.
Database work runs in the thread pool, so the synchronous SQLAlchemy calls do not block the event
loop.
"""

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from audit_log_service.api.body import BodyError, read_json_body
from audit_log_service.api.errors import ApiProblem, request_id_of
from audit_log_service.api.schemas import AuditEvent, ProblemDetails, represent
from audit_log_service.application.events import (
    SubmissionError,
    find_event,
    parse_submission,
    prepare_event,
    record_event,
)
from audit_log_service.config.settings import Settings
from audit_log_service.problem_details import (
    authentication_failure,
    authorization_failure,
    problem,
)
from audit_log_service.security.authentication import AuthenticatedPrincipal, AuthenticationError
from audit_log_service.security.authorization import AuthorizationError, authenticate_and_authorize
from audit_log_service.security.capabilities import Capability

router = APIRouter()

_PROBLEM: dict[str, Any] = {"model": ProblemDetails}
_AUTH_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {**_PROBLEM, "description": "Missing, malformed, or unknown credentials"},
    403: {**_PROBLEM, "description": "The principal lacks the required capability"},
    503: {**_PROBLEM, "description": "The database is unavailable"},
}
_REQUEST_BODY_SCHEMA = {
    "requestBody": {
        "required": True,
        "content": {
            "application/json": {"schema": {"$ref": "#/components/schemas/EventSubmission"}}
        },
    }
}


@router.post(
    "/audit/events",
    status_code=201,
    response_model=AuditEvent,
    summary="Append an audit event",
    openapi_extra=_REQUEST_BODY_SCHEMA,
    responses={
        201: {
            "description": "The event was recorded",
            "headers": {
                "Location": {
                    "description": "Path of the new event",
                    "schema": {"type": "string"},
                }
            },
        },
        400: {**_PROBLEM, "description": "The body is not valid JSON"},
        413: {**_PROBLEM, "description": "The body exceeds 64 KiB"},
        415: {**_PROBLEM, "description": "The body is not application/json"},
        422: {**_PROBLEM, "description": "The event failed validation"},
        **_AUTH_RESPONSES,
    },
)
async def append_audit_event(request: Request) -> JSONResponse:
    settings = _settings(request)
    principal = _authorize(request, settings, Capability.EVENTS_WRITE)
    try:
        document = await read_json_body(request)
        event = prepare_event(parse_submission(document), principal.id, settings.vocabulary)
    except BodyError as error:
        raise ApiProblem(problem(error.status, error.detail, request_id_of(request))) from None
    except SubmissionError as error:
        raise ApiProblem(problem(422, str(error), request_id_of(request))) from None

    def append() -> dict[str, Any]:
        with request.app.state.engine.begin() as connection:
            return represent(record_event(connection, event, settings.timestamp_skew))

    try:
        body = await run_in_threadpool(append)
    except SubmissionError as error:
        raise ApiProblem(problem(422, str(error), request_id_of(request))) from None
    return JSONResponse(body, status_code=201, headers={"Location": f"/audit/events/{body['id']}"})


@router.get(
    "/audit/events/{id}",
    response_model=AuditEvent,
    summary="Retrieve one audit event",
    responses={404: {**_PROBLEM, "description": "No event has this identifier"}, **_AUTH_RESPONSES},
)
async def get_audit_event(request: Request, id: str) -> JSONResponse:
    settings = _settings(request)
    _authorize(request, settings, Capability.EVENTS_READ)

    def load() -> dict[str, Any] | None:
        with request.app.state.engine.connect() as connection:
            entry = find_event(connection, id)
        return None if entry is None else represent(entry)

    body = await run_in_threadpool(load)
    if body is None:
        raise ApiProblem(
            problem(404, "No audit event has this identifier.", request_id_of(request))
        )
    return JSONResponse(body)


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def _authorize(
    request: Request, settings: Settings, capability: Capability
) -> AuthenticatedPrincipal:
    # Every Authorization value is passed on, so multiple headers are rejected (Phase 1 note).
    headers = request.headers.getlist("authorization")
    try:
        return authenticate_and_authorize(headers, settings.api_keys, capability)
    except AuthenticationError:
        raise ApiProblem(authentication_failure(request_id_of(request))) from None
    except AuthorizationError:
        raise ApiProblem(authorization_failure(request_id_of(request))) from None
