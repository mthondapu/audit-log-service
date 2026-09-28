"""Tests for loading and validating the API-key configuration (D3e)."""

import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest

from audit_log_service.config.api_keys import load_api_key_configuration
from audit_log_service.config.errors import ConfigurationError
from audit_log_service.security.capabilities import ROLE_CAPABILITIES, Capability, Role

WriteFile = Callable[[str, str], Path]

HASH_A = hashlib.sha256(b"test-only-key-a").hexdigest()
HASH_B = hashlib.sha256(b"test-only-key-b").hexdigest()


def _load_error(write_file: WriteFile, content: str) -> str:
    path = write_file("api-keys.toml", content)
    with pytest.raises(ConfigurationError) as caught:
        load_api_key_configuration(path)
    return str(caught.value)


def test_valid_configuration_loads(write_file: WriteFile, valid_api_key_toml: str) -> None:
    configuration = load_api_key_configuration(write_file("api-keys.toml", valid_api_key_toml))

    by_id = {principal.id: principal for principal in configuration.principals}
    assert set(by_id) == {"svc-writer", "auditor-1", "regulator-1", "ops.admin"}
    assert by_id["svc-writer"].role is Role.WRITER
    assert by_id["svc-writer"].capabilities == frozenset({Capability.EVENTS_WRITE})
    assert by_id["ops.admin"].capabilities == ROLE_CAPABILITIES[Role.ADMINISTRATOR]
    assert len(by_id["ops.admin"].key_digests) == 2
    assert all(len(digest) == 32 for digest in by_id["ops.admin"].key_digests)


def test_repr_does_not_expose_key_hashes(write_file: WriteFile, valid_api_key_toml: str) -> None:
    configuration = load_api_key_configuration(write_file("api-keys.toml", valid_api_key_toml))
    texts = [repr(configuration), *(repr(p) for p in configuration.principals)]
    digests = [d for p in configuration.principals for d in p.key_digests]

    for text in texts:
        assert "key_digests" not in text
        for digest in digests:
            assert digest.hex() not in text
            assert repr(digest) not in text
    assert configuration.principals[0].id in repr(configuration.principals[0])


def test_missing_file_fails(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.toml"
    with pytest.raises(ConfigurationError, match="not found"):
        load_api_key_configuration(missing)


def test_unreadable_path_fails(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="not readable"):
        load_api_key_configuration(tmp_path)


def test_invalid_utf8_fails(tmp_path: Path) -> None:
    path = tmp_path / "api-keys.toml"
    path.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(ConfigurationError, match="not valid UTF-8"):
        load_api_key_configuration(path)


def test_malformed_toml_fails_without_echoing_content(write_file: WriteFile) -> None:
    message = _load_error(
        write_file, f'[[principals]]\nid = "svc-writer\nkey_sha256 = ["{HASH_A}"]'
    )
    assert "malformed TOML" in message
    assert HASH_A not in message


def test_empty_file_fails(write_file: WriteFile) -> None:
    assert "principals" in _load_error(write_file, "")


def test_no_principals_fails(write_file: WriteFile) -> None:
    assert "principals" in _load_error(write_file, "principals = []")


def test_unknown_top_level_field_fails(write_file: WriteFile) -> None:
    content = f"""
extra = true
[[principals]]
id = "svc-writer"
role = "writer"
key_sha256 = ["{HASH_A}"]
"""
    assert "extra" in _load_error(write_file, content)


def test_unknown_principal_field_fails(write_file: WriteFile) -> None:
    content = f"""
[[principals]]
id = "svc-writer"
role = "writer"
capabilities = ["events:redact"]
key_sha256 = ["{HASH_A}"]
"""
    message = _load_error(write_file, content)
    assert "capabilities" in message
    assert HASH_A not in message


def test_duplicate_principal_id_fails(write_file: WriteFile) -> None:
    content = f"""
[[principals]]
id = "svc-writer"
role = "writer"
key_sha256 = ["{HASH_A}"]

[[principals]]
id = "svc-writer"
role = "auditor"
key_sha256 = ["{HASH_B}"]
"""
    message = _load_error(write_file, content)
    assert "duplicate principal ID 'svc-writer'" in message
    assert HASH_A not in message
    assert HASH_B not in message


def test_duplicate_hash_across_principals_fails(write_file: WriteFile) -> None:
    content = f"""
[[principals]]
id = "svc-writer"
role = "writer"
key_sha256 = ["{HASH_A}"]

[[principals]]
id = "auditor-1"
role = "auditor"
key_sha256 = ["{HASH_A}"]
"""
    message = _load_error(write_file, content)
    assert "duplicate API-key hash" in message
    assert HASH_A not in message


def test_duplicate_hash_within_principal_fails(write_file: WriteFile) -> None:
    content = f"""
[[principals]]
id = "svc-writer"
role = "writer"
key_sha256 = ["{HASH_A}", "{HASH_A}"]
"""
    message = _load_error(write_file, content)
    assert "duplicate API-key hash" in message
    assert HASH_A not in message


@pytest.mark.parametrize(
    "bad_hash",
    [
        "REPLACE_WITH_SHA256_HEX_DIGEST",
        HASH_A.upper(),
        HASH_A[:-1],
        HASH_A + "0",
        "g" * 64,
    ],
)
def test_invalid_hash_format_fails_without_echoing_value(
    write_file: WriteFile, bad_hash: str
) -> None:
    content = f"""
[[principals]]
id = "svc-writer"
role = "writer"
key_sha256 = ["{bad_hash}"]
"""
    message = _load_error(write_file, content)
    assert "key_sha256" in message
    assert bad_hash not in message


def test_non_string_hash_fails(write_file: WriteFile) -> None:
    content = """
[[principals]]
id = "svc-writer"
role = "writer"
key_sha256 = [12345]
"""
    assert "key_sha256" in _load_error(write_file, content)


def test_unknown_role_fails(write_file: WriteFile) -> None:
    content = f"""
[[principals]]
id = "svc-writer"
role = "superuser"
key_sha256 = ["{HASH_A}"]
"""
    assert "role" in _load_error(write_file, content)


def test_principal_without_keys_fails(write_file: WriteFile) -> None:
    content = """
[[principals]]
id = "svc-writer"
role = "writer"
key_sha256 = []
"""
    assert "key_sha256" in _load_error(write_file, content)


def test_principal_missing_keys_field_fails(write_file: WriteFile) -> None:
    content = """
[[principals]]
id = "svc-writer"
role = "writer"
"""
    assert "key_sha256" in _load_error(write_file, content)


@pytest.mark.parametrize(
    "bad_id",
    ["", "Svc-Writer", "1writer", "svc writer", " svc-writer", "svc/writer", "a" * 65],
)
def test_invalid_principal_id_fails(write_file: WriteFile, bad_id: str) -> None:
    content = f"""
[[principals]]
id = "{bad_id}"
role = "writer"
key_sha256 = ["{HASH_A}"]
"""
    assert "id" in _load_error(write_file, content)


@pytest.mark.parametrize("good_id", ["a", "svc-orders", "ops.admin", "svc_writer-2", "a" * 64])
def test_valid_principal_ids_are_accepted(write_file: WriteFile, good_id: str) -> None:
    content = f"""
[[principals]]
id = "{good_id}"
role = "writer"
key_sha256 = ["{HASH_A}"]
"""
    configuration = load_api_key_configuration(write_file("api-keys.toml", content))
    assert configuration.principals[0].id == good_id
