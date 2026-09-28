"""Tests for loading service settings from the environment (D2)."""

from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest

from audit_log_service.config.errors import ConfigurationError
from audit_log_service.config.settings import (
    API_KEYS_FILE_VARIABLE,
    DATABASE_URL_VARIABLE,
    RETENTION_BATCH_SIZE_VARIABLE,
    RETENTION_MAX_BATCHES_VARIABLE,
    RETENTION_WINDOW_VARIABLE,
    TIMESTAMP_SKEW_VARIABLE,
    VOCABULARY_FILE_VARIABLE,
    load_settings,
)

CONFIG_DIR = Path(__file__).resolve().parents[3] / "config"
DATABASE_URL = "postgresql+psycopg://audit_app:test-only-password@127.0.0.1/audit_log"

WriteFile = Callable[[str, str], Path]


@pytest.fixture
def environ(write_file: WriteFile, valid_api_key_toml: str) -> dict[str, str]:
    return {
        DATABASE_URL_VARIABLE: DATABASE_URL,
        API_KEYS_FILE_VARIABLE: str(write_file("api-keys.toml", valid_api_key_toml)),
        VOCABULARY_FILE_VARIABLE: str(CONFIG_DIR / "client-account-vocabulary.example.toml"),
    }


def test_settings_load_with_the_default_skew(environ: dict[str, str]) -> None:
    settings = load_settings(environ)

    assert settings.database_url == DATABASE_URL
    assert {p.id for p in settings.api_keys.principals} >= {"svc-writer", "auditor-1"}
    assert settings.vocabulary.resource_type == "CLIENT_ACCOUNT"
    assert settings.timestamp_skew == timedelta(minutes=5)


def test_skew_can_be_configured(environ: dict[str, str]) -> None:
    environ[TIMESTAMP_SKEW_VARIABLE] = " 60 "
    assert load_settings(environ).timestamp_skew == timedelta(seconds=60)


@pytest.mark.parametrize(
    "variable", [DATABASE_URL_VARIABLE, API_KEYS_FILE_VARIABLE, VOCABULARY_FILE_VARIABLE]
)
@pytest.mark.parametrize("value", [None, "", "   "], ids=["unset", "empty", "blank"])
def test_required_variables_fail_fast(
    environ: dict[str, str], variable: str, value: str | None
) -> None:
    if value is None:
        del environ[variable]
    else:
        environ[variable] = value
    with pytest.raises(ConfigurationError, match=f"^{variable} must be set$"):
        load_settings(environ)


@pytest.mark.parametrize("value", ["abc", "-5", "1.5", "", "٣", "9" * 30], ids=str)
def test_invalid_skew_fails_fast(environ: dict[str, str], value: str) -> None:
    environ[TIMESTAMP_SKEW_VARIABLE] = value
    with pytest.raises(ConfigurationError, match=TIMESTAMP_SKEW_VARIABLE) as caught:
        load_settings(environ)
    assert value.strip() == "" or value not in str(caught.value)


def test_unreadable_configuration_file_fails_fast(environ: dict[str, str], tmp_path: Path) -> None:
    environ[API_KEYS_FILE_VARIABLE] = str(tmp_path / "missing.toml")
    with pytest.raises(ConfigurationError, match="not found"):
        load_settings(environ)


def test_repr_does_not_expose_the_database_url(environ: dict[str, str]) -> None:
    text = repr(load_settings(environ))
    assert "test-only-password" not in text
    assert "audit_app" not in text


def test_retention_is_disabled_by_default_with_default_bounds(environ: dict[str, str]) -> None:
    settings = load_settings(environ)
    assert settings.retention_window is None
    assert (settings.retention_batch_size, settings.retention_max_batches) == (500, 20)


def test_retention_settings_are_read(environ: dict[str, str]) -> None:
    environ[RETENTION_WINDOW_VARIABLE] = "86400"
    environ[RETENTION_BATCH_SIZE_VARIABLE] = "10000"
    environ[RETENTION_MAX_BATCHES_VARIABLE] = "1"

    settings = load_settings(environ)

    assert settings.retention_window == timedelta(days=1)
    assert (settings.retention_batch_size, settings.retention_max_batches) == (10_000, 1)


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        (RETENTION_WINDOW_VARIABLE, "0"),
        (RETENTION_WINDOW_VARIABLE, ""),
        (RETENTION_WINDOW_VARIABLE, "-60"),
        (RETENTION_WINDOW_VARIABLE, "1.5"),
        (RETENTION_WINDOW_VARIABLE, "one day"),
        (RETENTION_WINDOW_VARIABLE, str(100 * 365 * 24 * 60 * 60 + 1)),
        (RETENTION_BATCH_SIZE_VARIABLE, "0"),
        (RETENTION_BATCH_SIZE_VARIABLE, "10001"),
        (RETENTION_MAX_BATCHES_VARIABLE, "0"),
        (RETENTION_MAX_BATCHES_VARIABLE, "1001"),
        (RETENTION_MAX_BATCHES_VARIABLE, chr(0x665)),
    ],
)
def test_invalid_retention_settings_fail_fast(
    environ: dict[str, str], variable: str, value: str
) -> None:
    environ[variable] = value
    with pytest.raises(ConfigurationError, match=f"^{variable} must be a whole number from 1 to"):
        load_settings(environ)
