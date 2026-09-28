"""Failure handling: database unavailability, unexpected errors, startup checks, and logging."""

import logging
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, create_engine, func, select, text

from audit_log_service.api import events as events_routes
from audit_log_service.api.app import create_app
from audit_log_service.application import events as application_events
from audit_log_service.config.errors import ConfigurationError
from audit_log_service.config.settings import Settings
from audit_log_service.persistence import audit_log
from audit_log_service.persistence.audit_log import APPEND_LOCK_KEY

Headers = dict[str, str]
MakeClient = Callable[[Any], httpx.Client]
BODY = {
    "eventType": "ORDER_PLACED",
    "actorId": "user-7",
    "resourceType": "ORDER",
    "resourceId": "order-1",
    "payload": {"card": "4111-1111"},
}


def _assert_problem(response: httpx.Response, status: int) -> dict[str, Any]:
    assert response.status_code == status
    assert response.headers["content-type"] == "application/problem+json"
    body: dict[str, Any] = response.json()
    assert body["requestId"] == response.headers["x-request-id"]
    return body


def test_unreachable_database_is_503_without_details(
    settings: Settings, make_client: MakeClient, writer: Headers, auditor: Headers
) -> None:
    unreachable = create_engine(
        "postgresql+psycopg://nobody@127.0.0.1:1/nothing", connect_args={"connect_timeout": 1}
    )
    # No client context: the startup check would fail first, which is tested separately.
    client = make_client(create_app(settings, unreachable))

    for response in (
        client.post("/audit/events", json=BODY, headers=writer),
        client.get("/audit/events/00000000-0000-4000-8000-000000000000", headers=auditor),
    ):
        body = _assert_problem(response, 503)
        assert body["detail"] == "The service is temporarily unavailable."
        assert "127.0.0.1" not in response.text
        assert "psycopg" not in response.text.lower()


def test_append_lock_timeout_is_503_and_stores_nothing(
    client: httpx.Client,
    writer: Headers,
    owner_engine: Engine,
    app_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(audit_log, "_SET_LOCK_TIMEOUT", text("SET LOCAL lock_timeout = '200ms'"))

    with owner_engine.begin() as holder:
        holder.execute(select(func.pg_advisory_xact_lock(APPEND_LOCK_KEY)))
        response = client.post("/audit/events", json=BODY, headers=writer)

    _assert_problem(response, 503)
    with app_engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM audit_records")).scalar_one() == 0


def test_unexpected_error_is_a_500_without_details(
    client: httpx.Client, auditor: Headers, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_args: Any) -> None:
        raise RuntimeError("internal detail: connection string and payload 4111-1111")

    monkeypatch.setattr(events_routes, "find_event", explode)

    response = client.get("/audit/events/00000000-0000-4000-8000-000000000000", headers=auditor)

    body = _assert_problem(response, 500)
    assert body["detail"] == "The request could not be completed."
    assert "internal detail" not in response.text
    assert "Traceback" not in response.text
    assert "RuntimeError" not in response.text


def test_startup_refuses_a_login_that_can_change_records(
    settings: Settings, owner_engine: Engine, make_client: MakeClient
) -> None:
    with (
        pytest.raises(ConfigurationError, match="must use a member of audit_log_app") as caught,
        make_client(create_app(settings, owner_engine)),
    ):
        pass
    assert "UPDATE" in str(caught.value)


def test_logs_record_denials_and_failures_without_sensitive_values(
    client: httpx.Client,
    writer: Headers,
    auditor: Headers,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)

    client.post(
        "/audit/events?token=query-secret", json=BODY, headers={"Authorization": "Bearer wrong-key"}
    )
    client.post("/audit/events", json=BODY, headers=auditor)
    client.post(
        "/audit/events", json={**BODY, "payload": {"card": "4111-1111", "n": 1e16}}, headers=writer
    )
    client.post("/audit/events", json=BODY, headers=writer)

    # Only the service's own log records; the test's HTTP client logs its request URLs.
    logged = " | ".join(
        record.getMessage()
        for record in caplog.records
        if record.name.startswith("audit_log_service")
    )
    assert "denied" in logged
    assert "status=401" in logged
    assert "status=403" in logged
    for sensitive in (
        "wrong-key",
        "test-only",
        "Bearer",
        "4111-1111",
        "query-secret",
        "Authorization",
    ):
        assert sensitive not in logged


def test_unreadable_appended_record_is_a_500_and_rolls_back(
    client: httpx.Client, writer: Headers, app_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Guards an internal inconsistency: the appended record must be readable in its transaction.
    def missing(*_args: object) -> None:
        return None

    monkeypatch.setattr(application_events, "load_entry", missing)

    response = client.post("/audit/events", json=BODY, headers=writer)

    _assert_problem(response, 500)
    with app_engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM audit_records")).scalar_one() == 0
