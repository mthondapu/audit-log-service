"""Approved prototype capabilities and role-to-capability mapping.

The mapping is authoritative (requirements NFR-2, ADR-0008). The API-key configuration assigns each
principal exactly one role; it cannot grant arbitrary capabilities.
"""

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType


class Capability(StrEnum):
    EVENTS_WRITE = "events:write"
    EVENTS_READ = "events:read"
    CHAIN_VERIFY = "chain:verify"
    EVENTS_REDACT = "events:redact"
    RETENTION_RUN = "retention:run"
    EXPORT_CREATE = "export:create"
    CHECKPOINT_CREATE = "checkpoint:create"


class Role(StrEnum):
    WRITER = "writer"
    AUDITOR = "auditor"
    REGULATOR = "regulator"
    ADMINISTRATOR = "administrator"


ROLE_CAPABILITIES: Mapping[Role, frozenset[Capability]] = MappingProxyType(
    {
        Role.WRITER: frozenset({Capability.EVENTS_WRITE}),
        Role.AUDITOR: frozenset(
            {Capability.EVENTS_READ, Capability.CHAIN_VERIFY, Capability.EXPORT_CREATE}
        ),
        Role.REGULATOR: frozenset(
            {Capability.EVENTS_READ, Capability.CHAIN_VERIFY, Capability.EXPORT_CREATE}
        ),
        Role.ADMINISTRATOR: frozenset(
            {
                Capability.EVENTS_READ,
                Capability.EVENTS_REDACT,
                Capability.RETENTION_RUN,
                Capability.CHECKPOINT_CREATE,
            }
        ),
    }
)
