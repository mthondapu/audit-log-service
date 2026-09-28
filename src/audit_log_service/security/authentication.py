"""API-key authentication (D3, D4, ADR-0008).

`authenticate` reads the key from HTTP Authorization header values (`Bearer <key>`).
`authenticate_api_key` matches a raw key and is shared with the checkpoint CLI, which reads the key
from stdin rather than from a header (Phase 10 decision CP3).

Every failure raises the same `AuthenticationError`, with no detail about the cause, so callers
cannot tell a malformed credential from an unknown one or learn whether a principal exists.
"""

import hashlib
import hmac
import re
from collections.abc import Sequence
from dataclasses import dataclass

from audit_log_service.config.api_keys import ApiKeyConfiguration
from audit_log_service.security.capabilities import Capability, Role

# Exactly "Bearer", one ASCII space, and a non-empty token with no whitespace. The scheme is
# case-insensitive; surrounding whitespace, tabs, and repeated spaces are malformed.
_BEARER = re.compile(r"(?i:bearer) (\S+)")
# A raw key is non-empty and has no whitespace, the same token grammar as in the header.
_TOKEN = re.compile(r"\S+")


class AuthenticationError(Exception):
    """Authentication failed. Deliberately carries no detail about the reason."""


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """The principal resolved from a valid credential. `id` becomes `recordedBy`."""

    id: str
    role: Role
    capabilities: frozenset[Capability]


def authenticate(
    authorization_headers: Sequence[str], configuration: ApiKeyConfiguration
) -> AuthenticatedPrincipal:
    """Resolve the principal for the request's Authorization header values.

    `authorization_headers` holds every Authorization header value received, so that multiple
    headers can be rejected.
    """
    return authenticate_api_key(_extract_bearer_token(authorization_headers), configuration)


def authenticate_api_key(token: str, configuration: ApiKeyConfiguration) -> AuthenticatedPrincipal:
    """Resolve the principal for a raw API key.

    The key is hashed with SHA-256 and compared against every configured digest in constant time,
    without stopping at the first match.
    """
    if _TOKEN.fullmatch(token) is None:
        raise AuthenticationError
    try:
        encoded = token.encode("utf-8")
    except UnicodeEncodeError:  # an unpaired surrogate, possible only outside HTTP headers
        raise AuthenticationError from None
    presented_digest = hashlib.sha256(encoded).digest()

    matched: AuthenticatedPrincipal | None = None
    for principal in configuration.principals:
        for configured_digest in principal.key_digests:
            if hmac.compare_digest(presented_digest, configured_digest):
                matched = AuthenticatedPrincipal(
                    id=principal.id, role=principal.role, capabilities=principal.capabilities
                )

    if matched is None:
        raise AuthenticationError
    return matched


def _extract_bearer_token(authorization_headers: Sequence[str]) -> str:
    if len(authorization_headers) != 1:
        raise AuthenticationError
    match = _BEARER.fullmatch(authorization_headers[0])
    if match is None:
        raise AuthenticationError
    return match[1]
