"""Chain verification for `GET /audit/verify` (requirements FR-3, Phase 7 decisions D1 to D4).

`verifiedAt` is the database clock (`clock_timestamp()`), read once at the start of verification
and written in the canonical timestamp form. The chain is loaded in one REPEATABLE READ, READ ONLY
transaction, so every record and payload value comes from a single snapshot; nothing is locked or
written. The unchanged integrity core (`verify_chain`) does all checking.

Not detected until later phases: deleted payload values (`PAYLOAD_VALUE_MISSING`, with retention
and redaction), and truncation or a consistent full rewrite (`CHAIN_TRUNCATED`, `ANCHOR_MISMATCH`,
with checkpoints).
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from sqlalchemy import Engine, func, select

from audit_log_service.integrity.timestamps import format_timestamp
from audit_log_service.integrity.verification import (
    VerificationResult,
    ViolationType,
    verify_chain,
)
from audit_log_service.persistence.audit_log import load_chain_entries

# Fixed per violation type, never derived from record data (FR-3). Approved wording (D3).
VIOLATION_MESSAGES: Mapping[ViolationType, str] = MappingProxyType(
    {
        ViolationType.SEQUENCE_DUPLICATE: (
            "The record's sequence number repeats that of an earlier record."
        ),
        ViolationType.SEQUENCE_GAP: (
            "The record's sequence number does not directly follow the preceding record, "
            "or the chain does not start at sequence 1."
        ),
        ViolationType.GENESIS_MISMATCH: "The first record's previousHash is not the genesis value.",
        ViolationType.PREVIOUS_HASH_MISMATCH: (
            "The record's previousHash does not match the preceding record's recordHash."
        ),
        ViolationType.CONTENT_HASH_MISMATCH: "The record's content does not match its contentHash.",
        ViolationType.PAYLOAD_VALUE_MISMATCH: (
            "A stored payload value does not match its commitment."
        ),
        ViolationType.RECORD_HASH_MISMATCH: (
            "The record's recordHash does not match its sequence, previousHash, and contentHash."
        ),
        ViolationType.RECORDED_AT_REGRESSION: (
            "The record's recordedAt is earlier than the preceding record's recordedAt."
        ),
    }
)


@dataclass(frozen=True, slots=True)
class ChainVerification:
    verified_at: str
    result: VerificationResult


def verify_audit_chain(engine: Engine) -> ChainVerification:
    """Verify the whole chain from genesis against one read-only snapshot."""
    with engine.connect() as connection:
        snapshot = connection.execution_options(
            isolation_level="REPEATABLE READ", postgresql_readonly=True
        )
        with snapshot.begin():
            database_now = snapshot.execute(select(func.clock_timestamp())).scalar_one()
            entries = load_chain_entries(snapshot)
    return ChainVerification(
        verified_at=format_timestamp(database_now), result=verify_chain(entries)
    )
