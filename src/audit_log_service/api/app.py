"""FastAPI application factory.

Run with: ``uvicorn audit_log_service.api.app:create_app --factory``.

Settings are loaded once, when the app is created, and fail fast (D2). At startup the service also
confirms that its database login has no UPDATE, DELETE, or TRUNCATE privilege on audit records, so
it cannot run as the owner or another privileged role (ADR-0009). The service reads the checkpoint
store with the trusted public key and has no code path that writes it (FR-4).

Every response carries a server-generated `X-Request-ID`; an incoming one is ignored (D3). Every
error is RFC 9457 Problem Details with that `requestId`. Logs record request identifiers, methods,
paths without query strings, statuses, and exception class names only: never credentials, bodies,
payload values, or exception messages.
"""

import logging
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.openapi.utils import get_openapi
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from audit_log_service.api.errors import ApiProblem, problem_json, request_id_of
from audit_log_service.api.events import router as events_router
from audit_log_service.api.exports import router as exports_router
from audit_log_service.api.health import router as health_router
from audit_log_service.api.redactions import router as redactions_router
from audit_log_service.api.retention import router as retention_router
from audit_log_service.api.schemas import ExportBundle
from audit_log_service.api.verification import router as verification_router
from audit_log_service.application.events import EventSubmission
from audit_log_service.application.exports import ExportRequest
from audit_log_service.application.redactions import RedactionRequest
from audit_log_service.config.errors import ConfigurationError
from audit_log_service.config.settings import DATABASE_URL_VARIABLE, Settings, load_settings
from audit_log_service.persistence.checkpoint_store import CheckpointStoreError
from audit_log_service.problem_details import problem

logger = logging.getLogger("audit_log_service.api")

REQUEST_ID_HEADER = "X-Request-ID"
CHECKPOINT_STORE_ERROR_DETAIL = "The checkpoint store is invalid or unreadable."
CONNECT_TIMEOUT_SECONDS = 5
_FORBIDDEN_PRIVILEGES = ("UPDATE", "DELETE", "TRUNCATE")


def create_app(settings: Settings | None = None, engine: Engine | None = None) -> FastAPI:
    """Build the application. Tests may supply settings and an engine; otherwise both come from the
    environment."""
    settings = settings if settings is not None else load_settings()
    if engine is None:
        # A connect timeout makes an unreachable database fail promptly with 503 instead of
        # waiting for the operating system's TCP timeout.
        engine = create_engine(
            settings.database_url,
            pool_pre_ping=True,
            connect_args={"connect_timeout": CONNECT_TIMEOUT_SECONDS},
        )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncGenerator[None]:
        await run_in_threadpool(check_database_role, engine)
        yield

    app = FastAPI(
        title="Audit Log Service",
        version="0.1.0",
        description="Tamper-evident, append-only audit log.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.engine = engine
    app.include_router(events_router)
    app.include_router(verification_router)
    app.include_router(redactions_router)
    app.include_router(retention_router)
    app.include_router(exports_router)
    app.include_router(health_router)
    _install_error_handling(app)
    app.openapi = lambda: _openapi(app)  # type: ignore[method-assign]
    return app


def check_database_role(engine: Engine) -> None:
    """Refuse to start unless the database login lacks update, delete, and truncate on records."""
    with engine.connect() as connection:
        privileged = [
            privilege
            for privilege in _FORBIDDEN_PRIVILEGES
            if connection.execute(
                text("SELECT has_table_privilege(current_user, 'audit_records', :privilege)"),
                {"privilege": privilege},
            ).scalar_one()
        ]
    if privileged:
        raise ConfigurationError(
            f"{DATABASE_URL_VARIABLE} must use a member of audit_log_app; the configured login "
            f"can {', '.join(privileged)} audit records"
        )


def _install_error_handling(app: FastAPI) -> None:
    @app.middleware("http")
    async def request_context(  # pyright: ignore[reportUnusedFunction]
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        except Exception as error:
            logger.error(
                "unhandled error request_id=%s method=%s path=%s error=%s",
                request_id,
                request.method,
                request.url.path,
                type(error).__name__,
            )
            response = problem_json(problem(500, "The request could not be completed.", request_id))
        response.headers[REQUEST_ID_HEADER] = request_id
        return response

    @app.exception_handler(ApiProblem)
    async def api_problem(request: Request, error: ApiProblem) -> Response:  # pyright: ignore[reportUnusedFunction]
        if error.response.status in (401, 403):
            # Denied attempts are logged operationally, never appended to the chain (ADR-0008).
            logger.warning(
                "denied request_id=%s method=%s path=%s status=%s",
                request_id_of(request),
                request.method,
                request.url.path,
                error.response.status,
            )
        return problem_json(error.response)

    @app.exception_handler(OperationalError)
    @app.exception_handler(PoolTimeoutError)
    async def database_unavailable(request: Request, error: Exception) -> Response:  # pyright: ignore[reportUnusedFunction]
        # Covers an unreachable database and an append that could not get the lock in time.
        logger.error(
            "database unavailable request_id=%s path=%s error=%s",
            request_id_of(request),
            request.url.path,
            type(error).__name__,
        )
        return problem_json(
            problem(503, "The service is temporarily unavailable.", request_id_of(request))
        )

    @app.exception_handler(CheckpointStoreError)
    async def checkpoint_store_invalid(request: Request, error: CheckpointStoreError) -> Response:  # pyright: ignore[reportUnusedFunction]
        # Fail closed: nothing in the store is trusted. The log names the file, never its content.
        logger.error(
            "checkpoint store invalid request_id=%s path=%s file=%s",
            request_id_of(request),
            request.url.path,
            error.file_name,
        )
        return problem_json(problem(500, CHECKPOINT_STORE_ERROR_DETAIL, request_id_of(request)))

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, error: StarletteHTTPException) -> Response:  # pyright: ignore[reportUnusedFunction]
        # Routing errors from the framework (unknown path, method not allowed), with fixed text.
        response = problem_json(
            problem(
                error.status_code,
                f"{HTTPStatus(error.status_code).phrase}.",
                request_id_of(request),
            )
        )
        response.headers.update(error.headers or {})
        return response


def _openapi(app: FastAPI) -> dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title, version=app.version, description=app.description, routes=app.routes
    )
    components = schema.setdefault("components", {})
    schemas = components.setdefault("schemas", {})
    # Request bodies are read explicitly after authorization, so their schemas are added here.
    for model in (EventSubmission, RedactionRequest, ExportRequest, ExportBundle):
        body_schema = model.model_json_schema(ref_template="#/components/schemas/{model}")
        schemas.update(body_schema.pop("$defs", {}))
        schemas[model.__name__] = body_schema
    components["securitySchemes"] = {"bearerAuth": {"type": "http", "scheme": "bearer"}}

    # Every /audit operation is authenticated; the health endpoints are not (NFR-2).
    for path, operations in schema["paths"].items():
        for operation in operations.values():
            operation["security"] = [] if path.startswith("/health/") else [{"bearerAuth": []}]
            responses = operation["responses"]
            # FastAPI's default 422 describes body-parameter validation, which is not used here.
            if "HTTPValidationError" in str(responses.get("422", {})):
                del responses["422"]
            for code, response in responses.items():
                content = response.get("content", {})
                if int(code) >= 400 and "application/json" in content:
                    content["application/problem+json"] = content.pop("application/json")
            operation["responses"] = responses
    for unused in ("HTTPValidationError", "ValidationError"):
        schemas.pop(unused, None)
    app.openapi_schema = schema
    return schema
