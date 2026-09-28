"""API-key configuration: a separate mounted TOML file (D3, ADR-0008).

Expected structure::

    [[principals]]
    id = "svc-orders"            # non-secret principal ID; becomes recordedBy
    role = "writer"              # exactly one approved prototype role
    key_sha256 = ["<64 lowercase hex>", ...]   # one or more SHA-256 digests of raw keys

Raw API keys never appear in this file. Validation failures never echo hash values.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from audit_log_service.config.errors import ConfigurationError, describe_validation_error
from audit_log_service.config.toml_file import read_toml_file
from audit_log_service.security.capabilities import ROLE_CAPABILITIES, Capability, Role

PRINCIPAL_ID_PATTERN = r"^[a-z][a-z0-9._-]{0,63}$"
SHA256_HEX_PATTERN = r"^[0-9a-f]{64}$"

_DESCRIPTION = "API-key configuration"

PrincipalId = Annotated[str, StringConstraints(strict=True, pattern=PRINCIPAL_ID_PATTERN)]
Sha256Hex = Annotated[str, StringConstraints(strict=True, pattern=SHA256_HEX_PATTERN)]


class _PrincipalEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: PrincipalId
    role: Role
    key_sha256: Annotated[list[Sha256Hex], Field(min_length=1)]


class _ApiKeyFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    principals: Annotated[list[_PrincipalEntry], Field(min_length=1)]


@dataclass(frozen=True, slots=True)
class ConfiguredPrincipal:
    """A principal from the API-key configuration, with its role's approved capabilities."""

    id: str
    role: Role
    capabilities: frozenset[Capability]
    # Excluded from repr so that printing or logging a configuration never exposes key hashes.
    key_digests: tuple[bytes, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class ApiKeyConfiguration:
    """Validated API-key configuration, loaded once at startup."""

    principals: tuple[ConfiguredPrincipal, ...]


def load_api_key_configuration(path: Path) -> ApiKeyConfiguration:
    """Load and validate the API-key configuration file, failing fast on any problem."""
    raw = read_toml_file(path, description=_DESCRIPTION)
    try:
        parsed = _ApiKeyFile.model_validate(raw)
    except ValidationError as error:
        raise ConfigurationError(
            f"{_DESCRIPTION} is invalid: {path}: {describe_validation_error(error)}"
        ) from None
    return _build_configuration(parsed, path)


def _build_configuration(parsed: _ApiKeyFile, path: Path) -> ApiKeyConfiguration:
    seen_ids: set[str] = set()
    owner_by_digest: dict[str, str] = {}
    principals: list[ConfiguredPrincipal] = []

    for entry in parsed.principals:
        if entry.id in seen_ids:
            raise ConfigurationError(
                f"{_DESCRIPTION} is invalid: {path}: duplicate principal ID '{entry.id}'"
            )
        seen_ids.add(entry.id)

        for digest in entry.key_sha256:
            previous_owner = owner_by_digest.get(digest)
            if previous_owner is not None:
                raise ConfigurationError(
                    f"{_DESCRIPTION} is invalid: {path}: duplicate API-key hash "
                    f"(principals '{previous_owner}' and '{entry.id}')"
                )
            owner_by_digest[digest] = entry.id

        principals.append(
            ConfiguredPrincipal(
                id=entry.id,
                role=entry.role,
                capabilities=ROLE_CAPABILITIES[entry.role],
                key_digests=tuple(bytes.fromhex(digest) for digest in entry.key_sha256),
            )
        )

    return ApiKeyConfiguration(principals=tuple(principals))
