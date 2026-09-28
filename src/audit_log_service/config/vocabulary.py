"""Scenario C access-event vocabulary: a separate TOML file (D3, requirements FR-8).

Minimal structure::

    resource_type = "CLIENT_ACCOUNT"     # configured client-account resource type (SC-A1)

    [[event_types]]
    name = "..."                         # an access-event type in the configured vocabulary
    required_payload_keys = ["...", ...] # payload keys required for that event type

This module only loads and validates the file. Applying it to submitted events belongs to the
Scenario C validation phase.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from audit_log_service.config.errors import ConfigurationError, describe_validation_error
from audit_log_service.config.toml_file import read_toml_file

_DESCRIPTION = "Client-account vocabulary configuration"

# Non-empty, no surrounding whitespace, and no control characters. The exact event-type pattern is
# an implementation constraint that the event validation phase will apply.
_NAME_PATTERN = r"^[^\s\x00-\x1f\x7f](?:[^\x00-\x1f\x7f]*[^\s\x00-\x1f\x7f])?$"

VocabularyName = Annotated[str, StringConstraints(strict=True, pattern=_NAME_PATTERN)]


class _EventTypeEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: VocabularyName
    required_payload_keys: list[VocabularyName]


class _VocabularyFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_type: VocabularyName
    event_types: Annotated[list[_EventTypeEntry], Field(min_length=1)]


@dataclass(frozen=True, slots=True)
class ClientAccountVocabulary:
    """Validated Scenario C vocabulary, loaded once at startup."""

    resource_type: str
    required_payload_keys: Mapping[str, frozenset[str]]


def load_client_account_vocabulary(path: Path) -> ClientAccountVocabulary:
    """Load and validate the Scenario C vocabulary file, failing fast on any problem."""
    raw = read_toml_file(path, description=_DESCRIPTION)
    try:
        parsed = _VocabularyFile.model_validate(raw)
    except ValidationError as error:
        raise ConfigurationError(
            f"{_DESCRIPTION} is invalid: {path}: {describe_validation_error(error)}"
        ) from None

    required: dict[str, frozenset[str]] = {}
    for entry in parsed.event_types:
        if entry.name in required:
            raise ConfigurationError(
                f"{_DESCRIPTION} is invalid: {path}: duplicate event type '{entry.name}'"
            )
        keys = frozenset(entry.required_payload_keys)
        if len(keys) != len(entry.required_payload_keys):
            raise ConfigurationError(
                f"{_DESCRIPTION} is invalid: {path}: duplicate required payload key "
                f"for event type '{entry.name}'"
            )
        required[entry.name] = keys

    return ClientAccountVocabulary(
        resource_type=parsed.resource_type,
        required_payload_keys=MappingProxyType(required),
    )
