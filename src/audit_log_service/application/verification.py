"""Chain verification for `GET /audit/verify` (requirements FR-3, Phase 7 decisions D1 to D4).

`verifiedAt` is the database clock (`clock_timestamp()`), read once at the start of verification
and written in the canonical timestamp form. The chain is loaded in one REPEATABLE READ, READ ONLY
transaction, so every record and payload value comes from a single snapshot; nothing is locked or
written. The integrity core (`verify_chain`) does all checking.

Since Phase 10 (FR-4), the chain is compared with the latest checkpoint in the checkpoint store,
whose signature is verified with the trusted public key before it is used. The store is read
before the snapshot is opened (decision CP16): a checkpoint written in between refers to records
the snapshot then contains, so it cannot be mistaken for truncation. An invalid or unreadable store
raises `CheckpointStoreError`; nothing in it is trusted.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import Engine, func, select

from audit_log_service.integrity.checkpoints import SignedCheckpoint
from audit_log_service.integrity.timestamps import format_timestamp
from audit_log_service.integrity.verification import (
    ChainHead,
    VerificationResult,
    ViolationType,
    verify_chain,
)
from audit_log_service.persistence.audit_log import load_chain_entries
from audit_log_service.persistence.checkpoint_store import load_latest_checkpoint

# Fixed per violation type, never derived from record data (FR-3). Approved wording (Phase 7 D3;
# PAYLOAD_VALUE_MISSING in Phase 8; ANCHOR_MISMATCH and CHAIN_TRUNCATED in Phase 10, CP9).
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
        ViolationType.PAYLOAD_VALUE_MISSING: (
            "A payload value is missing without an authorizing redaction or retention event."
        ),
        ViolationType.RECORD_HASH_MISMATCH: (
            "The record's recordHash does not match its sequence, previousHash, and contentHash."
        ),
        ViolationType.RECORDED_AT_REGRESSION: (
            "The record's recordedAt is earlier than the preceding record's recordedAt."
        ),
        ViolationType.ANCHOR_MISMATCH: (
            "The record at the latest checkpoint's sequence does not match the checkpoint's "
            "recordHash."
        ),
        ViolationType.CHAIN_TRUNCATED: (
            "Records up to the latest checkpoint's sequence are missing from the end of the chain."
        ),
    }
)


@dataclass(frozen=True, slots=True)
class ChainVerification:
    verified_at: str
    result: VerificationResult


def verify_audit_chain(
    engine: Engine, store_dir: Path, public_key: Ed25519PublicKey
) -> ChainVerification:
    """Verify the whole chain from genesis against the latest checkpoint in the store."""
    latest = load_latest_checkpoint(store_dir, public_key)
    return verify_snapshot(engine, latest)


def verify_snapshot(engine: Engine, checkpoint: SignedCheckpoint | None) -> ChainVerification:
    """Verify the whole chain in one read-only snapshot, anchored by an already verified checkpoint.

    Callers must read the checkpoint before calling this, so the snapshot starts after it (CP16).
    """
    anchor = (
        None
        if checkpoint is None
        else ChainHead(
            sequence=checkpoint.checkpoint.sequence, record_hash=checkpoint.checkpoint.record_hash
        )
    )
    with engine.connect() as connection:
        snapshot = connection.execution_options(
            isolation_level="REPEATABLE READ", postgresql_readonly=True
        )
        with snapshot.begin():
            database_now = snapshot.execute(select(func.clock_timestamp())).scalar_one()
            entries = load_chain_entries(snapshot)
    return ChainVerification(
        verified_at=format_timestamp(database_now), result=verify_chain(entries, anchor)
    )
