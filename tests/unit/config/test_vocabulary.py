"""Tests for loading and validating the Scenario C vocabulary configuration."""

from collections.abc import Callable
from pathlib import Path

import pytest

from audit_log_service.config.errors import ConfigurationError
from audit_log_service.config.vocabulary import load_client_account_vocabulary

WriteFile = Callable[[str, str], Path]

VALID = """
resource_type = "CLIENT_ACCOUNT"

[[event_types]]
name = "TEST_ACCESS_A"
required_payload_keys = ["purpose", "channel"]

[[event_types]]
name = "TEST_ACCESS_B"
required_payload_keys = []
"""


def _load_error(write_file: WriteFile, content: str) -> str:
    path = write_file("vocabulary.toml", content)
    with pytest.raises(ConfigurationError) as caught:
        load_client_account_vocabulary(path)
    return str(caught.value)


def test_valid_vocabulary_loads(write_file: WriteFile) -> None:
    vocabulary = load_client_account_vocabulary(write_file("vocabulary.toml", VALID))

    assert vocabulary.resource_type == "CLIENT_ACCOUNT"
    assert dict(vocabulary.required_payload_keys) == {
        "TEST_ACCESS_A": frozenset({"purpose", "channel"}),
        "TEST_ACCESS_B": frozenset(),
    }


def test_missing_file_fails(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="not found"):
        load_client_account_vocabulary(tmp_path / "missing.toml")


def test_malformed_toml_fails(write_file: WriteFile) -> None:
    assert "malformed TOML" in _load_error(write_file, 'resource_type = "CLIENT_ACCOUNT')


def test_unknown_field_fails(write_file: WriteFile) -> None:
    assert "unexpected" in _load_error(write_file, VALID + "\nunexpected = 1\n")


def test_missing_resource_type_fails(write_file: WriteFile) -> None:
    content = """
[[event_types]]
name = "TEST_ACCESS_A"
required_payload_keys = []
"""
    assert "resource_type" in _load_error(write_file, content)


def test_no_event_types_fails(write_file: WriteFile) -> None:
    assert "event_types" in _load_error(
        write_file, 'resource_type = "CLIENT_ACCOUNT"\nevent_types = []\n'
    )


def test_duplicate_event_type_fails(write_file: WriteFile) -> None:
    content = """
resource_type = "CLIENT_ACCOUNT"

[[event_types]]
name = "TEST_ACCESS_A"
required_payload_keys = []

[[event_types]]
name = "TEST_ACCESS_A"
required_payload_keys = ["purpose"]
"""
    assert "duplicate event type 'TEST_ACCESS_A'" in _load_error(write_file, content)


def test_duplicate_required_key_fails(write_file: WriteFile) -> None:
    content = """
resource_type = "CLIENT_ACCOUNT"

[[event_types]]
name = "TEST_ACCESS_A"
required_payload_keys = ["purpose", "purpose"]
"""
    assert "duplicate required payload key" in _load_error(write_file, content)


@pytest.mark.parametrize("bad_name", ["", " TEST", "TEST ", "TEST\u0000A"])
def test_invalid_names_fail(write_file: WriteFile, bad_name: str) -> None:
    escaped = bad_name.replace("\u0000", "\\u0000")
    content = f"""
resource_type = "CLIENT_ACCOUNT"

[[event_types]]
name = "{escaped}"
required_payload_keys = []
"""
    assert "name" in _load_error(write_file, content)
