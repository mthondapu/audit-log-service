"""Shared test fixtures.

All API keys here are deterministic, obviously fake test values. Their SHA-256 digests are
computed in the fixtures; no real credential is used or stored.
"""

import hashlib
from collections.abc import Callable, Mapping
from pathlib import Path
from types import MappingProxyType

import pytest

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
