"""The app factory loads settings from the environment and fails fast (D2)."""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from audit_log_service.api import app as app_module
from audit_log_service.api.app import CONNECT_TIMEOUT_SECONDS, create_app
from audit_log_service.config.errors import ConfigurationError
from audit_log_service.config.settings import (
    API_KEYS_FILE_VARIABLE,
    CHECKPOINT_PUBLIC_KEY_FILE_VARIABLE,
    CHECKPOINT_STORE_DIR_VARIABLE,
    DATABASE_URL_VARIABLE,
    VOCABULARY_FILE_VARIABLE,
)

CONFIG_DIR = Path(__file__).resolve().parents[3] / "config"
DATABASE_URL = "postgresql+psycopg://audit_app@127.0.0.1:1/audit_log"


@pytest.fixture
def environment(
    monkeypatch: pytest.MonkeyPatch,
    write_file: Callable[[str, str], Path],
    valid_api_key_toml: str,
    checkpoint_store: Path,
    checkpoint_public_key_file: Path,
) -> None:
    monkeypatch.setenv(DATABASE_URL_VARIABLE, DATABASE_URL)
    monkeypatch.setenv(API_KEYS_FILE_VARIABLE, str(write_file("keys.toml", valid_api_key_toml)))
    monkeypatch.setenv(
        VOCABULARY_FILE_VARIABLE, str(CONFIG_DIR / "client-account-vocabulary.example.toml")
    )
    monkeypatch.setenv(CHECKPOINT_STORE_DIR_VARIABLE, str(checkpoint_store))
    monkeypatch.setenv(CHECKPOINT_PUBLIC_KEY_FILE_VARIABLE, str(checkpoint_public_key_file))


@pytest.mark.usefixtures("environment")
def test_factory_builds_from_the_environment_with_a_connect_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    real_create_engine = app_module.create_engine

    def recording_create_engine(url: str, **kwargs: Any) -> Any:
        calls.append((url, kwargs))
        return real_create_engine(url, **kwargs)

    monkeypatch.setattr(app_module, "create_engine", recording_create_engine)

    app = create_app()

    assert app.state.settings.database_url == DATABASE_URL
    assert calls == [
        (
            DATABASE_URL,
            {"pool_pre_ping": True, "connect_args": {"connect_timeout": CONNECT_TIMEOUT_SECONDS}},
        )
    ]


@pytest.mark.usefixtures("environment")
def test_factory_fails_fast_on_missing_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(API_KEYS_FILE_VARIABLE)
    with pytest.raises(ConfigurationError, match=API_KEYS_FILE_VARIABLE):
        create_app()
