"""The OpenAPI document describes exactly the Phase 5 contract."""

from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import create_engine

from audit_log_service.api.app import create_app
from audit_log_service.application.events import SERVER_ASSIGNED_FIELDS
from audit_log_service.application.queries import QUERY_PARAMETERS
from audit_log_service.config.api_keys import ApiKeyConfiguration
from audit_log_service.config.settings import Settings
from audit_log_service.config.vocabulary import load_client_account_vocabulary

CONFIG_DIR = Path(__file__).resolve().parents[3] / "config"
EVENT_FIELDS = {
    "id",
    "sequence",
    "eventType",
    "actorId",
    "resourceType",
    "resourceId",
    "timestamp",
    "recordedAt",
    "recordedBy",
    "payload",
    "redactedPaths",
    "archived",
    "contentHash",
    "previousHash",
    "recordHash",
}


@pytest.fixture
def openapi(
    api_key_configuration: ApiKeyConfiguration, make_client: Callable[[Any], httpx.Client]
) -> dict[str, Any]:
    settings = Settings(
        database_url="postgresql+psycopg://unused@127.0.0.1:1/unused",
        api_keys=api_key_configuration,
        vocabulary=load_client_account_vocabulary(
            CONFIG_DIR / "client-account-vocabulary.example.toml"
        ),
        timestamp_skew=timedelta(minutes=5),
    )
    # The engine never connects: the lifespan does not run without a client context.
    app = create_app(settings, create_engine(settings.database_url))
    document: dict[str, Any] = make_client(app).get("/openapi.json").json()
    assert app.openapi() is app.openapi()  # generated once, then cached
    return document


def _problem_codes(responses: dict[str, Any]) -> set[str]:
    return {
        code
        for code, response in responses.items()
        if response.get("content", {}).get("application/problem+json", {}).get("schema")
        == {"$ref": "#/components/schemas/ProblemDetails"}
    }


def test_only_the_implemented_operations_are_documented(openapi: dict[str, Any]) -> None:
    operations = {
        (path, method) for path, methods in openapi["paths"].items() for method in methods
    }
    assert operations == {
        ("/audit/events", "post"),
        ("/audit/events", "get"),
        ("/audit/events/{id}", "get"),
    }


def test_post_documents_the_request_body_and_statuses(openapi: dict[str, Any]) -> None:
    post = openapi["paths"]["/audit/events"]["post"]

    assert post["requestBody"]["required"] is True
    assert post["requestBody"]["content"] == {
        "application/json": {"schema": {"$ref": "#/components/schemas/EventSubmission"}}
    }
    assert set(post["responses"]) == {"201", "400", "401", "403", "413", "415", "422", "503"}
    assert _problem_codes(post["responses"]) == set(post["responses"]) - {"201"}
    created = post["responses"]["201"]
    assert "Location" in created["headers"]
    assert created["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/AuditEvent"
    }


def test_query_documents_its_parameters_statuses_and_page(openapi: dict[str, Any]) -> None:
    query = openapi["paths"]["/audit/events"]["get"]
    parameters = {parameter["name"]: parameter for parameter in query["parameters"]}

    assert set(parameters) == set(QUERY_PARAMETERS)
    assert all(p["in"] == "query" and p["required"] is False for p in parameters.values())
    assert parameters["limit"]["schema"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": 200,
        "default": 50,
    }
    assert parameters["includeArchived"]["schema"] == {"type": "boolean", "default": False}
    assert parameters["eventType"]["schema"]["pattern"] == "^[A-Z][A-Z0-9_]{0,63}$"
    assert parameters["resourceType"]["schema"]["pattern"] == "^[A-Z][A-Z0-9_]{0,63}$"
    assert parameters["actorId"]["schema"]["maxLength"] == 256
    assert parameters["from"]["schema"] == {"type": "string", "format": "date-time"}
    assert set(query["responses"]) == {"200", "401", "403", "422", "503"}
    assert _problem_codes(query["responses"]) == {"401", "403", "422", "503"}
    assert query["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/AuditEventPage"
    }
    page = openapi["components"]["schemas"]["AuditEventPage"]
    assert set(page["properties"]) == {"items", "nextCursor"}
    assert page["properties"]["items"]["items"] == {"$ref": "#/components/schemas/AuditEvent"}


def test_get_documents_its_statuses(openapi: dict[str, Any]) -> None:
    get = openapi["paths"]["/audit/events/{id}"]["get"]

    assert set(get["responses"]) == {"200", "401", "403", "404", "503"}
    assert _problem_codes(get["responses"]) == {"401", "403", "404", "503"}
    assert get["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/AuditEvent"
    }


def test_request_schema_matches_the_approved_contract(openapi: dict[str, Any]) -> None:
    schema = openapi["components"]["schemas"]["EventSubmission"]

    assert set(schema["properties"]) == {
        "eventType",
        "actorId",
        "resourceType",
        "resourceId",
        "timestamp",
        "payload",
    }
    assert set(schema["required"]) == {
        "eventType",
        "actorId",
        "resourceType",
        "resourceId",
        "payload",
    }
    assert schema["additionalProperties"] is False
    assert not SERVER_ASSIGNED_FIELDS & set(schema["properties"])
    assert schema["properties"]["eventType"]["pattern"] == "^[A-Z][A-Z0-9_]{0,63}$"
    assert schema["properties"]["resourceType"]["pattern"] == "^[A-Z][A-Z0-9_]{0,63}$"
    for field in ("actorId", "resourceId"):
        assert (
            schema["properties"][field]["minLength"],
            schema["properties"][field]["maxLength"],
        ) == (
            1,
            256,
        )


def test_response_schema_is_the_public_representation(openapi: dict[str, Any]) -> None:
    schemas = openapi["components"]["schemas"]

    assert set(schemas["AuditEvent"]["properties"]) == EVENT_FIELDS
    assert set(schemas["ProblemDetails"]["properties"]) == {
        "type",
        "title",
        "status",
        "detail",
        "requestId",
    }
    assert "HTTPValidationError" not in schemas
    serialized = str(schemas).lower()
    assert "salt" not in serialized
    assert "canonical" not in serialized


def test_operations_require_bearer_authentication(openapi: dict[str, Any]) -> None:
    assert openapi["components"]["securitySchemes"] == {
        "bearerAuth": {"type": "http", "scheme": "bearer"}
    }
    for methods in openapi["paths"].values():
        for operation in methods.values():
            assert operation["security"] == [{"bearerAuth": []}]
