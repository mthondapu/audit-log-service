"""Tests for loading service settings from the environment (D2)."""

from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from audit_log_service.config.errors import ConfigurationError
from audit_log_service.config.settings import (
    API_KEYS_FILE_VARIABLE,
    CHECKPOINT_DATABASE_URL_VARIABLE,
    CHECKPOINT_PUBLIC_KEY_FILE_VARIABLE,
    CHECKPOINT_SIGNING_KEY_FILE_VARIABLE,
    CHECKPOINT_STORE_DIR_VARIABLE,
    DATABASE_URL_VARIABLE,
    RETENTION_BATCH_SIZE_VARIABLE,
    RETENTION_MAX_BATCHES_VARIABLE,
    RETENTION_WINDOW_VARIABLE,
    TIMESTAMP_SKEW_VARIABLE,
    VOCABULARY_FILE_VARIABLE,
    load_checkpoint_cli_settings,
    load_settings,
)

CONFIG_DIR = Path(__file__).resolve().parents[3] / "config"
DATABASE_URL = "postgresql+psycopg://audit_app:test-only-password@127.0.0.1/audit_log"

WriteFile = Callable[[str, str], Path]


@pytest.fixture
def environ(
    write_file: WriteFile,
    valid_api_key_toml: str,
    checkpoint_store: Path,
    checkpoint_public_key_file: Path,
) -> dict[str, str]:
    return {
        DATABASE_URL_VARIABLE: DATABASE_URL,
        API_KEYS_FILE_VARIABLE: str(write_file("api-keys.toml", valid_api_key_toml)),
        VOCABULARY_FILE_VARIABLE: str(CONFIG_DIR / "client-account-vocabulary.example.toml"),
        CHECKPOINT_STORE_DIR_VARIABLE: str(checkpoint_store),
        CHECKPOINT_PUBLIC_KEY_FILE_VARIABLE: str(checkpoint_public_key_file),
    }


@pytest.fixture
def cli_environ(
    write_file: WriteFile,
    valid_api_key_toml: str,
    checkpoint_store: Path,
    checkpoint_signing_key_file: Path,
) -> dict[str, str]:
    return {
        CHECKPOINT_DATABASE_URL_VARIABLE: DATABASE_URL,
        API_KEYS_FILE_VARIABLE: str(write_file("api-keys.toml", valid_api_key_toml)),
        CHECKPOINT_STORE_DIR_VARIABLE: str(checkpoint_store),
        CHECKPOINT_SIGNING_KEY_FILE_VARIABLE: str(checkpoint_signing_key_file),
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
    "variable",
    [
        DATABASE_URL_VARIABLE,
        API_KEYS_FILE_VARIABLE,
        VOCABULARY_FILE_VARIABLE,
        CHECKPOINT_STORE_DIR_VARIABLE,
        CHECKPOINT_PUBLIC_KEY_FILE_VARIABLE,
    ],
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


def test_settings_hold_the_checkpoint_store_and_trusted_public_key(
    environ: dict[str, str], checkpoint_store: Path, checkpoint_key: Ed25519PrivateKey
) -> None:
    settings = load_settings(environ)
    assert settings.checkpoint_store_dir == checkpoint_store
    raw = (Encoding.Raw, PublicFormat.Raw)
    assert settings.checkpoint_public_key.public_bytes(*raw) == (
        checkpoint_key.public_key().public_bytes(*raw)
    )


@pytest.mark.parametrize("target", ["missing", "file"])
def test_checkpoint_store_must_be_an_existing_directory(
    environ: dict[str, str], tmp_path: Path, target: str
) -> None:
    path = tmp_path / target
    if target == "file":
        path.write_text("not a directory", encoding="utf-8")
    environ[CHECKPOINT_STORE_DIR_VARIABLE] = str(path)
    with pytest.raises(
        ConfigurationError,
        match=f"^{CHECKPOINT_STORE_DIR_VARIABLE} must name an existing directory$",
    ):
        load_settings(environ)


def _ec_public_key_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


BAD_PEM = bytes([10]).join(
    [b"-----BEGIN PUBLIC KEY-----", b"AAAA", b"-----END PUBLIC KEY-----", b""]
)


@pytest.mark.parametrize(
    "content",
    [None, b"", b"not a key", BAD_PEM, "ec"],
    ids=["missing", "empty", "text", "bad-pem", "not-ed25519"],
)
def test_invalid_checkpoint_public_key_fails_fast(
    environ: dict[str, str], tmp_path: Path, content: bytes | str | None
) -> None:
    path = tmp_path / "trusted.pem"
    if content is not None:
        path.write_bytes(_ec_public_key_pem() if content == "ec" else cast(bytes, content))
    environ[CHECKPOINT_PUBLIC_KEY_FILE_VARIABLE] = str(path)
    with pytest.raises(ConfigurationError) as caught:
        load_settings(environ)
    assert str(caught.value) == (
        f"{CHECKPOINT_PUBLIC_KEY_FILE_VARIABLE} must name a readable Ed25519 public key in "
        "SubjectPublicKeyInfo PEM form"
    )


def test_private_key_is_not_accepted_as_the_trusted_public_key(
    environ: dict[str, str], checkpoint_signing_key_file: Path
) -> None:
    environ[CHECKPOINT_PUBLIC_KEY_FILE_VARIABLE] = str(checkpoint_signing_key_file)
    with pytest.raises(ConfigurationError, match=CHECKPOINT_PUBLIC_KEY_FILE_VARIABLE) as caught:
        load_settings(environ)
    assert "PRIVATE" not in str(caught.value)


def test_repr_does_not_expose_the_public_key(environ: dict[str, str]) -> None:
    assert "Ed25519" not in repr(load_settings(environ))


def test_checkpoint_cli_settings_load(
    cli_environ: dict[str, str], checkpoint_store: Path, checkpoint_signing_key_file: Path
) -> None:
    settings = load_checkpoint_cli_settings(cli_environ)
    assert settings.database_url == DATABASE_URL
    assert {p.id for p in settings.api_keys.principals} >= {"ops.admin"}
    assert (settings.store_dir, settings.signing_key_file) == (
        checkpoint_store,
        checkpoint_signing_key_file,
    )
    assert "test-only-password" not in repr(settings)


def test_checkpoint_cli_settings_do_not_need_service_only_variables(
    cli_environ: dict[str, str],
) -> None:
    for variable in (DATABASE_URL_VARIABLE, VOCABULARY_FILE_VARIABLE):
        assert variable not in cli_environ
    load_checkpoint_cli_settings(cli_environ)


@pytest.mark.parametrize(
    "variable",
    [
        CHECKPOINT_DATABASE_URL_VARIABLE,
        API_KEYS_FILE_VARIABLE,
        CHECKPOINT_STORE_DIR_VARIABLE,
        CHECKPOINT_SIGNING_KEY_FILE_VARIABLE,
    ],
)
def test_checkpoint_cli_required_variables_fail_fast(
    cli_environ: dict[str, str], variable: str
) -> None:
    del cli_environ[variable]
    with pytest.raises(ConfigurationError, match=f"^{variable} must be set$"):
        load_checkpoint_cli_settings(cli_environ)


def test_checkpoint_cli_signing_key_must_name_a_file(
    cli_environ: dict[str, str], tmp_path: Path
) -> None:
    cli_environ[CHECKPOINT_SIGNING_KEY_FILE_VARIABLE] = str(tmp_path / "missing.pem")
    with pytest.raises(
        ConfigurationError, match=f"^{CHECKPOINT_SIGNING_KEY_FILE_VARIABLE} must name a file$"
    ):
        load_checkpoint_cli_settings(cli_environ)


def test_checkpoint_cli_settings_do_not_read_the_signing_key(
    cli_environ: dict[str, str], checkpoint_signing_key_file: Path
) -> None:
    # The key is read only after the operator is authorized (CP3), so its content is not checked.
    checkpoint_signing_key_file.write_bytes(b"not a key")
    load_checkpoint_cli_settings(cli_environ)
