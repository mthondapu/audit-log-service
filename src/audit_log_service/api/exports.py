"""`POST /audit/exports` (requirements FR-7, Phase 11 decisions E1 to E17).

The order is fixed: authenticate, authorize `export:create`, validate the body and scope, confirm
that the export signing key is configured (503 otherwise), and only then read the checkpoint store
and the database. The bundle is returned as the exact signed bytes with `Cache-Control: no-store`.
Logs record the request identifier, status, and record count only: never the scope identifiers,
payload values, salts, keys, or the manifest.
"""

import logging

from fastapi import APIRouter, Request, Response
from starlette.concurrency import run_in_threadpool

from audit_log_service.api.body import BodyError, read_json_body
from audit_log_service.api.errors import ApiProblem, request_id_of
from audit_log_service.api.events import AUTH_RESPONSES, PROBLEM, app_settings, authorize_request
from audit_log_service.application.events import SubmissionError
from audit_log_service.application.exports import (
    ExportPolicy,
    ExportTooLargeError,
    ExportVerificationError,
    create_export,
    parse_export_request,
)
from audit_log_service.problem_details import problem
from audit_log_service.security.capabilities import Capability

logger = logging.getLogger("audit_log_service.api")
router = APIRouter()

SIGNING_UNAVAILABLE_DETAIL = "Export signing is not configured."
TOO_LARGE_DETAIL = "The export exceeds the configured size limit."
VERIFICATION_FAILED_DETAIL = "The audit chain failed verification; no export was signed."

_REQUEST_BODY_SCHEMA = {
    "requestBody": {
        "required": True,
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ExportRequest"}}},
    }
}


@router.post(
    "/audit/exports",
    summary="Export every audit record matching one scope as a signed bundle",
    openapi_extra=_REQUEST_BODY_SCHEMA,
    response_class=Response,
    responses={
        200: {
            "description": "The signed bundle: manifest, signature, and records (never cached)",
            "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/ExportBundle"}}
            },
        },
        400: {**PROBLEM, "description": "The body is not valid JSON"},
        409: {**PROBLEM, "description": "The audit chain failed verification; nothing was signed"},
        413: {**PROBLEM, "description": "The body exceeds 64 KiB"},
        415: {**PROBLEM, "description": "The body is not application/json"},
        422: {**PROBLEM, "description": "The scope is invalid, or the export exceeds a size limit"},
        500: {**PROBLEM, "description": "The checkpoint store is invalid or unreadable"},
        **AUTH_RESPONSES,
        503: {
            **PROBLEM,
            "description": (
                "Export signing is not configured, the database is unavailable, or the export "
                "event could not be recorded; no bundle is returned"
            ),
        },
    },
)
async def export_audit_events(request: Request) -> Response:
    settings = app_settings(request)
    principal = authorize_request(request, settings, Capability.EXPORT_CREATE)
    request_id = request_id_of(request)
    try:
        scope = parse_export_request(await read_json_body(request))
    except BodyError as error:
        raise ApiProblem(problem(error.status, error.detail, request_id)) from None
    except SubmissionError as error:
        raise ApiProblem(problem(422, str(error), request_id)) from None
    private_key = settings.export_signing_key
    if private_key is None:
        raise ApiProblem(problem(503, SIGNING_UNAVAILABLE_DETAIL, request_id))

    try:
        result = await run_in_threadpool(
            create_export,
            request.app.state.engine,
            scope,
            private_key,
            ExportPolicy(
                max_records=settings.export_max_records, max_bytes=settings.export_max_bytes
            ),
            settings.checkpoint_store_dir,
            settings.checkpoint_public_key,
            principal.id,
        )
    except ExportTooLargeError:
        raise ApiProblem(problem(422, TOO_LARGE_DETAIL, request_id)) from None
    except ExportVerificationError:
        raise ApiProblem(problem(409, VERIFICATION_FAILED_DETAIL, request_id)) from None
    logger.info(
        "export created request_id=%s status=200 records=%d", request_id, result.record_count
    )
    return Response(
        content=result.body,
        media_type="application/json",
        headers={"Cache-Control": "no-store"},
    )
