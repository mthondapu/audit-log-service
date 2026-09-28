"""Fixtures for API tests against the real persistence layer.

The app uses the session's migrated test database through the `audit_log_app` role (see the parent
conftest), fake API keys, the example Scenario C vocabulary, and an empty checkpoint store trusted
with an ephemeral key.
"""

from collections.abc import Callable, Iterator, Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Engine

from audit_log_service.api.app import create_app
from audit_log_service.config.api_keys import ApiKeyConfiguration
from audit_log_service.config.settings import Settings
from audit_log_service.config.vocabulary import load_client_account_vocabulary

CONFIG_DIR = Path(__file__).resolve().parents[3] / "config"

Headers = dict[str, str]
PostEvent = Callable[..., httpx.Response]


@pytest.fixture
def settings(
    api_key_configuration: ApiKeyConfiguration,
    checkpoint_store: Path,
    checkpoint_key: Ed25519PrivateKey,
) -> Settings:
    return Settings(
        database_url="unused: the tests supply the engine",
        api_keys=api_key_configuration,
        vocabulary=load_client_account_vocabulary(
            CONFIG_DIR / "client-account-vocabulary.example.toml"
        ),
        timestamp_skew=timedelta(minutes=5),
        checkpoint_store_dir=checkpoint_store,
        checkpoint_public_key=checkpoint_key.public_key(),
    )


@pytest.fixture
def client(
    settings: Settings, app_engine: Engine, make_client: Callable[[Any], httpx.Client]
) -> Iterator[httpx.Client]:
    with make_client(create_app(settings, app_engine)) as test_client:
        yield test_client


def _bearer(key: str) -> Headers:
    return {"Authorization": f"Bearer {key}"}


@pytest.fixture
def writer(fake_keys: Mapping[str, str]) -> Headers:
    return _bearer(fake_keys["writer"])


@pytest.fixture
def auditor(fake_keys: Mapping[str, str]) -> Headers:
    return _bearer(fake_keys["auditor"])


@pytest.fixture
def administrator(fake_keys: Mapping[str, str]) -> Headers:
    return _bearer(fake_keys["administrator"])


def event_body(**changes: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "eventType": "ORDER_PLACED",
        "actorId": "user-7",
        "resourceType": "ORDER",
        "resourceId": "order-1",
        "payload": {"amount": 12.5, "items": ["sku-1", "sku-2"]},
    }
    body.update(changes)
    return {key: value for key, value in body.items() if value is not _OMIT}


_OMIT = object()


@pytest.fixture
def omit() -> object:
    """Marker for leaving a field out of `event_body`."""
    return _OMIT


@pytest.fixture
def post_event(client: httpx.Client, writer: Headers) -> PostEvent:
    """POST an event as the writer; keyword arguments change or omit fields."""

    def post(**changes: Any) -> httpx.Response:
        return client.post("/audit/events", json=event_body(**changes), headers=writer)

    return post
