"""Liveness and readiness endpoints (NFR-2, NFR-5, Phase 12 decision P4)."""

import sqlite3
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Engine, create_engine
from sqlalchemy.pool import NullPool

from audit_log_service.api.app import create_app
from audit_log_service.config.api_keys import ApiKeyConfiguration
from audit_log_service.config.settings import Settings
from audit_log_service.config.vocabulary import load_client_account_vocabulary

CONFIG_DIR = Path(__file__).resolve().parents[3] / "config"


@pytest.fixture
def engines() -> Iterator[Callable[[str], Engine]]:
    """SQLite engines, all disposed after the test so no connection is left open."""
    created: list[Engine] = []

    def make(url: str) -> Engine:
        # NullPool closes each connection on release, whichever thread used it.
        engine = create_engine(url, poolclass=NullPool)
        created.append(engine)
        return engine

    yield make
    for engine in created:
        engine.dispose()


def _client(
    engine: Engine,
    api_key_configuration: ApiKeyConfiguration,
    checkpoint_store: Path,
    checkpoint_key: Ed25519PrivateKey,
    make_client: Callable[[Any], httpx.Client],
) -> httpx.Client:
    settings = Settings(
        database_url="unused: the test supplies the engine",
        api_keys=api_key_configuration,
        vocabulary=load_client_account_vocabulary(
            CONFIG_DIR / "client-account-vocabulary.example.toml"
        ),
        timestamp_skew=timedelta(minutes=5),
        checkpoint_store_dir=checkpoint_store,
        checkpoint_public_key=checkpoint_key.public_key(),
    )
    # Without a client context the startup privilege check does not run.
    return make_client(create_app(settings, engine))


def test_liveness_needs_no_credentials_or_database(
    api_key_configuration: ApiKeyConfiguration,
    checkpoint_store: Path,
    checkpoint_key: Ed25519PrivateKey,
    make_client: Callable[[Any], httpx.Client],
    tmp_path: Path,
    engines: Callable[[str], Engine],
) -> None:
    engine = engines(f"sqlite:///{tmp_path / 'missing' / 'x.db'}")
    client = _client(engine, api_key_configuration, checkpoint_store, checkpoint_key, make_client)

    response = client.get("/health/live")

    assert (response.status_code, response.json()) == (200, {"status": "ok"})
    assert "x-request-id" in response.headers


def test_readiness_checks_the_database(
    api_key_configuration: ApiKeyConfiguration,
    checkpoint_store: Path,
    checkpoint_key: Ed25519PrivateKey,
    make_client: Callable[[Any], httpx.Client],
    engines: Callable[[str], Engine],
) -> None:
    client = _client(
        engines("sqlite://"),
        api_key_configuration,
        checkpoint_store,
        checkpoint_key,
        make_client,
    )
    response = client.get("/health/ready")
    assert (response.status_code, response.json()) == (200, {"status": "ok"})


def test_readiness_is_503_when_the_database_is_unavailable(
    api_key_configuration: ApiKeyConfiguration,
    checkpoint_store: Path,
    checkpoint_key: Ed25519PrivateKey,
    make_client: Callable[[Any], httpx.Client],
) -> None:
    # Every connection attempt fails as an unreachable database does: an OperationalError.
    def unavailable() -> sqlite3.Connection:
        raise sqlite3.OperationalError("unavailable")

    engine = create_engine("sqlite://", creator=unavailable, poolclass=NullPool)
    try:
        client = _client(
            engine, api_key_configuration, checkpoint_store, checkpoint_key, make_client
        )
        response = client.get("/health/ready")
    finally:
        engine.dispose()

    assert response.status_code == 503
    assert response.headers["content-type"] == "application/problem+json"
    body = response.json()
    assert body["detail"] == "The service is temporarily unavailable."
    assert body["requestId"] == response.headers["x-request-id"]


def test_health_endpoints_ignore_credentials(
    api_key_configuration: ApiKeyConfiguration,
    checkpoint_store: Path,
    checkpoint_key: Ed25519PrivateKey,
    make_client: Callable[[Any], httpx.Client],
    engines: Callable[[str], Engine],
) -> None:
    client = _client(
        engines("sqlite://"),
        api_key_configuration,
        checkpoint_store,
        checkpoint_key,
        make_client,
    )
    headers = {"Authorization": "Bearer unknown-test-key"}
    assert client.get("/health/live", headers=headers).status_code == 200
    assert client.get("/health/ready", headers=headers).status_code == 200
