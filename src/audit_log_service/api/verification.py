"""`GET /audit/verify` (requirements FR-3).

The D4 order: authenticate, authorize `chain:verify`, validate (the endpoint takes no query
parameters), then verify. A broken chain is a verification result with 200, not an HTTP error.
The chain is compared with the latest checkpoint in the store (FR-4); an invalid or unreadable
store is a 500 Problem Details response, handled in `app` (Phase 10 decision CP8).
"""

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from audit_log_service.api.errors import ApiProblem, request_id_of
from audit_log_service.api.events import AUTH_RESPONSES, PROBLEM, app_settings, authorize_request
from audit_log_service.api.schemas import ChainVerification, represent_verification
from audit_log_service.application.verification import verify_audit_chain
from audit_log_service.problem_details import problem
from audit_log_service.security.capabilities import Capability

router = APIRouter()


@router.get(
    "/audit/verify",
    response_model=ChainVerification,
    summary="Verify the audit chain",
    responses={
        200: {"description": "The verification result, whether or not the chain is intact"},
        422: {**PROBLEM, "description": "The request has a query parameter"},
        **AUTH_RESPONSES,
        500: {**PROBLEM, "description": "The checkpoint store is invalid or unreadable"},
    },
)
async def verify_chain_route(request: Request) -> JSONResponse:
    authorize_request(request, app_settings(request), Capability.CHAIN_VERIFY)
    if request.query_params:
        raise ApiProblem(
            problem(
                422, "the verification endpoint accepts no query parameters", request_id_of(request)
            )
        )
    settings = app_settings(request)
    verification = await run_in_threadpool(
        verify_audit_chain,
        request.app.state.engine,
        settings.checkpoint_store_dir,
        settings.checkpoint_public_key,
    )
    body: dict[str, Any] = represent_verification(verification)
    return JSONResponse(body)
