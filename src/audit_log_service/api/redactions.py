"""`POST /audit/events/{id}/redactions` (requirements FR-6).

The D4 order: authenticate, authorize `events:redact`, validate the body, then look up the target
and redact, all in one transaction under the append lock.
"""

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from audit_log_service.api.body import BodyError, read_json_body
from audit_log_service.api.errors import ApiProblem, request_id_of
from audit_log_service.api.events import AUTH_RESPONSES, PROBLEM, app_settings, authorize_request
from audit_log_service.api.schemas import AuditEvent, represent
from audit_log_service.application.events import SubmissionError
from audit_log_service.application.redactions import (
    RedactionConflictError,
    RedactionNotFoundError,
    parse_redaction_request,
    redact,
)
from audit_log_service.problem_details import problem
from audit_log_service.security.capabilities import Capability

router = APIRouter()

_REQUEST_BODY_SCHEMA = {
    "requestBody": {
        "required": True,
        "content": {
            "application/json": {"schema": {"$ref": "#/components/schemas/RedactionRequest"}}
        },
    }
}


@router.post(
    "/audit/events/{id}/redactions",
    status_code=201,
    response_model=AuditEvent,
    summary="Redact payload values of one audit event",
    openapi_extra=_REQUEST_BODY_SCHEMA,
    responses={
        201: {
            "description": "The redaction event that was recorded",
            "headers": {
                "Location": {
                    "description": "Path of the redaction event",
                    "schema": {"type": "string"},
                }
            },
        },
        400: {**PROBLEM, "description": "The body is not valid JSON"},
        404: {**PROBLEM, "description": "No event has this identifier"},
        409: {
            **PROBLEM,
            "description": "The target is a system event, or nothing new would be redacted",
        },
        413: {**PROBLEM, "description": "The body exceeds 64 KiB"},
        415: {**PROBLEM, "description": "The body is not application/json"},
        422: {**PROBLEM, "description": "The request or a JSON Pointer is invalid"},
        **AUTH_RESPONSES,
    },
)
async def redact_audit_event(request: Request, id: str) -> JSONResponse:
    principal = authorize_request(request, app_settings(request), Capability.EVENTS_REDACT)
    request_id = request_id_of(request)
    try:
        redaction = parse_redaction_request(await read_json_body(request))
    except BodyError as error:
        raise ApiProblem(problem(error.status, error.detail, request_id)) from None
    except SubmissionError as error:
        raise ApiProblem(problem(422, str(error), request_id)) from None

    def apply() -> dict[str, Any]:
        with request.app.state.engine.begin() as connection:
            return represent(redact(connection, id, redaction, principal.id))

    try:
        body = await run_in_threadpool(apply)
    except RedactionNotFoundError:
        raise ApiProblem(problem(404, "No audit event has this identifier.", request_id)) from None
    except RedactionConflictError as error:
        raise ApiProblem(problem(409, str(error), request_id)) from None
    except SubmissionError as error:
        raise ApiProblem(problem(422, str(error), request_id)) from None
    return JSONResponse(body, status_code=201, headers={"Location": f"/audit/events/{body['id']}"})
