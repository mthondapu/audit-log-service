"""Liveness and readiness (requirements NFR-2 and NFR-5, architecture §5, Phase 12 decision P4).

Both endpoints are unauthenticated and disclose nothing about audit data. `/health/live` reports
that the process is serving requests. `/health/ready` also runs `SELECT 1` on the database; when the
database is unavailable, the app's handler returns the usual `503` Problem Details.
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import Engine, text
from starlette.concurrency import run_in_threadpool

from audit_log_service.api.events import PROBLEM

router = APIRouter()

_STATUS_SCHEMA = {
    "application/json": {
        "schema": {
            "type": "object",
            "properties": {"status": {"type": "string", "enum": ["ok"]}},
            "required": ["status"],
        }
    }
}


@router.get(
    "/health/live",
    summary="Liveness",
    response_class=JSONResponse,
    responses={200: {"description": "The service is running", "content": _STATUS_SCHEMA}},
)
async def live() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@router.get(
    "/health/ready",
    summary="Readiness",
    response_class=JSONResponse,
    responses={
        200: {"description": "The service can reach its database", "content": _STATUS_SCHEMA},
        503: {**PROBLEM, "description": "The database is unavailable"},
    },
)
async def ready(request: Request) -> JSONResponse:
    engine: Engine = request.app.state.engine
    await run_in_threadpool(_ping, engine)
    return JSONResponse({"status": "ok"})


def _ping(engine: Engine) -> None:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
