"""Tests for capability-based authorization and the authenticate-then-authorize order."""

from collections.abc import Mapping

import pytest

from audit_log_service.config.api_keys import ApiKeyConfiguration
from audit_log_service.security.authentication import (
    AuthenticatedPrincipal,
    AuthenticationError,
    authenticate,
)
from audit_log_service.security.authorization import (
    AuthorizationError,
    authenticate_and_authorize,
    require_capability,
)
from audit_log_service.security.capabilities import ROLE_CAPABILITIES, Capability, Role


def _principal(role: Role) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        id="test-principal", role=role, capabilities=ROLE_CAPABILITIES[role]
    )


def test_role_capability_mapping_matches_the_approved_model() -> None:
    assert {
        Role.WRITER: {Capability.EVENTS_WRITE},
        Role.AUDITOR: {Capability.EVENTS_READ, Capability.CHAIN_VERIFY, Capability.EXPORT_CREATE},
        Role.REGULATOR: {
            Capability.EVENTS_READ,
            Capability.CHAIN_VERIFY,
            Capability.EXPORT_CREATE,
        },
        Role.ADMINISTRATOR: {
            Capability.EVENTS_READ,
            Capability.EVENTS_REDACT,
            Capability.RETENTION_RUN,
            Capability.CHECKPOINT_CREATE,
        },
    } == ROLE_CAPABILITIES


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("capability", list(Capability))
def test_capability_matrix(role: Role, capability: Capability) -> None:
    principal = _principal(role)
    if capability in ROLE_CAPABILITIES[role]:
        require_capability(principal, capability)
    else:
        with pytest.raises(AuthorizationError):
            require_capability(principal, capability)


def test_only_administrators_may_redact() -> None:
    allowed = {role for role in Role if Capability.EVENTS_REDACT in ROLE_CAPABILITIES[role]}
    assert allowed == {Role.ADMINISTRATOR}


def test_authorization_failure_follows_successful_authentication(
    api_key_configuration: ApiKeyConfiguration, fake_keys: Mapping[str, str]
) -> None:
    headers = [f"Bearer {fake_keys['writer']}"]
    principal = authenticate(headers, api_key_configuration)
    assert principal.id == "svc-writer"
    with pytest.raises(AuthorizationError):
        authenticate_and_authorize(headers, api_key_configuration, Capability.EVENTS_REDACT)


def test_authentication_is_checked_before_authorization(
    api_key_configuration: ApiKeyConfiguration,
) -> None:
    with pytest.raises(AuthenticationError):
        authenticate_and_authorize(
            ["Bearer unknown-test-key"], api_key_configuration, Capability.EVENTS_WRITE
        )


def test_authorized_principal_is_returned(
    api_key_configuration: ApiKeyConfiguration, fake_keys: Mapping[str, str]
) -> None:
    principal = authenticate_and_authorize(
        [f"Bearer {fake_keys['administrator']}"],
        api_key_configuration,
        Capability.EVENTS_REDACT,
    )
    assert principal.id == "ops.admin"
