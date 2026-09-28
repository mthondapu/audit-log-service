"""Capability-based authorization (requirements NFR-2, ADR-0008)."""

from collections.abc import Sequence

from audit_log_service.config.api_keys import ApiKeyConfiguration
from audit_log_service.security.authentication import AuthenticatedPrincipal, authenticate
from audit_log_service.security.capabilities import Capability


class AuthorizationError(Exception):
    """The authenticated principal lacks the required capability."""


def require_capability(principal: AuthenticatedPrincipal, capability: Capability) -> None:
    """Raise `AuthorizationError` unless the principal's role grants the capability."""
    if capability not in principal.capabilities:
        raise AuthorizationError


def authenticate_and_authorize(
    authorization_headers: Sequence[str],
    configuration: ApiKeyConfiguration,
    capability: Capability,
) -> AuthenticatedPrincipal:
    """Apply the first two steps of the approved order: authenticate, then authorize.

    Request validation and resource lookup must run only after this returns, so unauthorized
    callers receive neither validation feedback nor information about resources (D4).
    """
    principal = authenticate(authorization_headers, configuration)
    require_capability(principal, capability)
    return principal
