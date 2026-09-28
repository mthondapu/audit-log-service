"""Service settings from environment variables (ADR-0008, Phase 5 decision D2).

- AUDIT_LOG_DATABASE_URL: database URL for a login user that is a member of `audit_log_app`.
- AUDIT_LOG_API_KEYS_FILE: path to the API-key configuration (loaded with the Phase 1 loader).
- AUDIT_LOG_VOCABULARY_FILE: path to the Scenario C vocabulary (loaded with the Phase 1 loader).
- AUDIT_LOG_TIMESTAMP_SKEW_SECONDS: allowed future skew of a caller `timestamp`; default 300.
- AUDIT_LOG_RETENTION_WINDOW_SECONDS: retention window (FR-5); optional. Unset disables retention.
- AUDIT_LOG_RETENTION_BATCH_SIZE: payload-value rows purged per batch; default 500.
- AUDIT_LOG_RETENTION_MAX_BATCHES: purge batches per run (the execution bound); default 20.

Settings are loaded once at startup and fail fast. Errors name the variable, never its value.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from audit_log_service.config.api_keys import ApiKeyConfiguration, load_api_key_configuration
from audit_log_service.config.errors import ConfigurationError
from audit_log_service.config.vocabulary import (
    ClientAccountVocabulary,
    load_client_account_vocabulary,
)

DATABASE_URL_VARIABLE = "AUDIT_LOG_DATABASE_URL"
API_KEYS_FILE_VARIABLE = "AUDIT_LOG_API_KEYS_FILE"
VOCABULARY_FILE_VARIABLE = "AUDIT_LOG_VOCABULARY_FILE"
TIMESTAMP_SKEW_VARIABLE = "AUDIT_LOG_TIMESTAMP_SKEW_SECONDS"
DEFAULT_TIMESTAMP_SKEW = timedelta(seconds=300)
RETENTION_WINDOW_VARIABLE = "AUDIT_LOG_RETENTION_WINDOW_SECONDS"
RETENTION_BATCH_SIZE_VARIABLE = "AUDIT_LOG_RETENTION_BATCH_SIZE"
RETENTION_MAX_BATCHES_VARIABLE = "AUDIT_LOG_RETENTION_MAX_BATCHES"
MAX_RETENTION_WINDOW_SECONDS = 100 * 365 * 24 * 60 * 60
MAX_RETENTION_BATCH_SIZE = 10_000
MAX_RETENTION_BATCHES = 1_000
DEFAULT_RETENTION_BATCH_SIZE = 500
DEFAULT_RETENTION_MAX_BATCHES = 20


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated service settings. The database URL may contain a password, so it is not in repr."""

    database_url: str = field(repr=False)
    api_keys: ApiKeyConfiguration
    vocabulary: ClientAccountVocabulary
    timestamp_skew: timedelta
    retention_window: timedelta | None = None
    retention_batch_size: int = DEFAULT_RETENTION_BATCH_SIZE
    retention_max_batches: int = DEFAULT_RETENTION_MAX_BATCHES


def load_settings(environ: Mapping[str, str] = os.environ) -> Settings:
    """Read and validate every setting, raising `ConfigurationError` on the first problem."""
    return Settings(
        database_url=_required(environ, DATABASE_URL_VARIABLE),
        api_keys=load_api_key_configuration(Path(_required(environ, API_KEYS_FILE_VARIABLE))),
        vocabulary=load_client_account_vocabulary(
            Path(_required(environ, VOCABULARY_FILE_VARIABLE))
        ),
        timestamp_skew=_timestamp_skew(environ),
        retention_window=_retention_window(environ),
        retention_batch_size=_bounded_integer(
            environ,
            RETENTION_BATCH_SIZE_VARIABLE,
            DEFAULT_RETENTION_BATCH_SIZE,
            MAX_RETENTION_BATCH_SIZE,
        ),
        retention_max_batches=_bounded_integer(
            environ,
            RETENTION_MAX_BATCHES_VARIABLE,
            DEFAULT_RETENTION_MAX_BATCHES,
            MAX_RETENTION_BATCHES,
        ),
    )


def _required(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"{name} must be set")
    return value


def _timestamp_skew(environ: Mapping[str, str]) -> timedelta:
    raw = environ.get(TIMESTAMP_SKEW_VARIABLE)
    if raw is None:
        return DEFAULT_TIMESTAMP_SKEW
    text = raw.strip()
    try:
        if not (text.isascii() and text.isdigit()):
            raise ValueError
        return timedelta(seconds=int(text))
    except (ValueError, OverflowError):
        raise ConfigurationError(
            f"{TIMESTAMP_SKEW_VARIABLE} must be a whole number of seconds"
        ) from None


def _retention_window(environ: Mapping[str, str]) -> timedelta | None:
    if environ.get(RETENTION_WINDOW_VARIABLE) is None:
        return None
    seconds = _bounded_integer(environ, RETENTION_WINDOW_VARIABLE, 0, MAX_RETENTION_WINDOW_SECONDS)
    return timedelta(seconds=seconds)


def _bounded_integer(environ: Mapping[str, str], name: str, default: int, maximum: int) -> int:
    raw = environ.get(name)
    if raw is None:
        return default
    text = raw.strip()
    if not (text.isascii() and text.isdigit()) or not 1 <= int(text) <= maximum:
        raise ConfigurationError(f"{name} must be a whole number from 1 to {maximum}")
    return int(text)
