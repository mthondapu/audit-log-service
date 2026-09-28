"""The committed example configuration files behave as documented."""

from pathlib import Path

import pytest

from audit_log_service.config.api_keys import load_api_key_configuration
from audit_log_service.config.errors import ConfigurationError
from audit_log_service.config.vocabulary import load_client_account_vocabulary

CONFIG_DIR = Path(__file__).resolve().parents[3] / "config"


def test_api_key_example_is_not_deployable() -> None:
    with pytest.raises(ConfigurationError) as caught:
        load_api_key_configuration(CONFIG_DIR / "api-keys.example.toml")
    assert "key_sha256" in str(caught.value)


def test_vocabulary_example_is_valid() -> None:
    vocabulary = load_client_account_vocabulary(
        CONFIG_DIR / "client-account-vocabulary.example.toml"
    )
    assert vocabulary.resource_type == "CLIENT_ACCOUNT"
    assert vocabulary.required_payload_keys
