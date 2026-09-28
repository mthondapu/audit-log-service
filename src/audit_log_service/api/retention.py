"""`POST /audit/retention-runs` (requirements FR-5).

The D4 order: authenticate, authorize `retention:run`, validate (no query parameters and no
body), then run. There is no retention-run resource; a new retention event is the only resource a
run creates.
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from audit_log_service.api.errors import ApiProblem, request_id_of
from audit_log_service.api.events import AUTH_RESPONSES, PROBLEM, app_settings, authorize_request
from audit_log_service.api.schemas import RetentionRun, represent_retention
from audit_log_service.application.retention import (
    RetentionDisabledError,
    RetentionIncompleteError,
    RetentionOutcome,
    RetentionPolicy,
    run_retention,
)
from audit_log_service.problem_details import problem
from audit_log_service.security.capabilities import Capability

router = APIRouter()


@router.post(
    "/audit/retention-runs",
    response_model=RetentionRun,
    summary="Run retention once",
    responses={
        200: {"description": "A purge was resumed and completed, or nothing was eligible"},
        201: {
            "model": RetentionRun,
            "description": "A new retention event was recorded and its purge completed",
            "headers": {
                "Location": {
                    "description": "Path of the retention event",
                    "schema": {"type": "string"},
                }
            },
        },
        422: {
            **PROBLEM,
            "description": "The request has a body or query parameters, or retention is disabled",
        },
        503: {
            **PROBLEM,
            "description": "The execution bound was reached (a later run resumes), "
            "or the database is unavailable",
        },
        **{code: AUTH_RESPONSES[code] for code in (401, 403)},
    },
)
async def run_retention_route(request: Request) -> JSONResponse:
    settings = app_settings(request)
    principal = authorize_request(request, settings, Capability.RETENTION_RUN)
    request_id = request_id_of(request)
    if request.query_params:
        raise ApiProblem(problem(422, "The retention run accepts no query parameters.", request_id))
    async for chunk in request.stream():
        if chunk:
            raise ApiProblem(problem(422, "The retention run accepts no request body.", request_id))
    policy = RetentionPolicy(
        window=settings.retention_window,
        batch_size=settings.retention_batch_size,
        max_batches=settings.retention_max_batches,
    )
    try:
        result = await run_in_threadpool(
            run_retention, request.app.state.engine, policy, principal.id
        )
    except RetentionDisabledError:
        raise ApiProblem(problem(422, "Retention is not configured.", request_id)) from None
    except RetentionIncompleteError:
        raise ApiProblem(
            problem(
                503,
                "The retention purge reached its execution bound; a later run resumes it.",
                request_id,
            )
        ) from None
    body = represent_retention(result)
    if result.outcome is RetentionOutcome.RETENTION_RECORDED:
        location = f"/audit/events/{body['retentionEvent']['id']}"
        return JSONResponse(body, status_code=201, headers={"Location": location})
    return JSONResponse(body)
