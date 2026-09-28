"""Shared test fixtures.

All API keys here are deterministic, obviously fake test values. Their SHA-256 digests are
computed in the fixtures; no real credential is used or stored. Checkpoint signing keys are
generated per test and written only under the test's temporary directory.
"""

import hashlib
from collections.abc import Callable, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi.testclient import TestClient

from audit_log_service.config.api_keys import ApiKeyConfiguration, load_api_key_configuration

FAKE_KEYS: Mapping[str, str] = MappingProxyType(
    {
        "writer": "test-only-writer-key",
        "auditor": "test-only-auditor-key",
        "regulator": "test-only-regulator-key",
        "administrator": "test-only-administrator-key",
        "administrator-rotated": "test-only-administrator-rotated-key",
    }
)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


WriteFile = Callable[[str, str], Path]


@pytest.fixture
def write_file(tmp_path: Path) -> WriteFile:
    def _write(name: str, content: str) -> Path:
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        return path

    return _write


@pytest.fixture
def fake_keys() -> Mapping[str, str]:
    return FAKE_KEYS


@pytest.fixture
def valid_api_key_toml() -> str:
    return f"""
[[principals]]
id = "svc-writer"
role = "writer"
key_sha256 = ["{sha256_hex(FAKE_KEYS["writer"])}"]

[[principals]]
id = "auditor-1"
role = "auditor"
key_sha256 = ["{sha256_hex(FAKE_KEYS["auditor"])}"]

[[principals]]
id = "regulator-1"
role = "regulator"
key_sha256 = ["{sha256_hex(FAKE_KEYS["regulator"])}"]

[[principals]]
id = "ops.admin"
role = "administrator"
key_sha256 = [
    "{sha256_hex(FAKE_KEYS["administrator"])}",
    "{sha256_hex(FAKE_KEYS["administrator-rotated"])}",
]
"""


@pytest.fixture
def api_key_configuration(write_file: WriteFile, valid_api_key_toml: str) -> ApiKeyConfiguration:
    return load_api_key_configuration(write_file("api-keys.toml", valid_api_key_toml))


def public_key_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def private_key_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


@pytest.fixture
def checkpoint_key() -> Ed25519PrivateKey:
    """An ephemeral checkpoint signing key, generated in memory for one test."""
    return Ed25519PrivateKey.generate()


@pytest.fixture
def checkpoint_store(tmp_path: Path) -> Path:
    store = tmp_path / "checkpoints"
    store.mkdir()
    return store


@pytest.fixture
def checkpoint_public_key_file(tmp_path: Path, checkpoint_key: Ed25519PrivateKey) -> Path:
    path = tmp_path / "checkpoint-public.pem"
    path.write_bytes(public_key_pem(checkpoint_key))
    return path


@pytest.fixture
def checkpoint_signing_key_file(tmp_path: Path, checkpoint_key: Ed25519PrivateKey) -> Path:
    path = tmp_path / "checkpoint-signing.pem"
    path.write_bytes(private_key_pem(checkpoint_key))
    return path


def api_client(app: Any) -> httpx.Client:
    """A TestClient typed as the httpx.Client it subclasses.

    The installed Starlette resolves its client types through `httpx2`, which this project does
    not use, so Pyright cannot see them; at runtime TestClient is an `httpx.Client`.
    """
    return cast(httpx.Client, TestClient(app))  # pyright: ignore[reportUnknownArgumentType]


@pytest.fixture
def make_client() -> Callable[[Any], httpx.Client]:
    return api_client
