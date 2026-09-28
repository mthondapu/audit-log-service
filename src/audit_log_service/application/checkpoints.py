"""Checkpoint creation for the checkpoint CLI (requirements FR-4, ADR-0006, Phase 10 decisions).

The caller has already authenticated and authorized the operator for `checkpoint:create` and
loaded the signing key. This module then:

1. validates the whole checkpoint store with the signing key's public key and takes the latest
   checkpoint, before opening the database snapshot (CP16);
2. verifies the whole chain in one read-only snapshot, anchored by that checkpoint;
3. refuses an empty or non-intact chain, so no checkpoint is signed over known-bad state (CP11);
4. reports `CHECKPOINT_CURRENT`, writing nothing, when the head is already checkpointed; and
5. otherwise signs the head, checks the signature, and writes the artifact to the store.

Creating a checkpoint appends nothing to the chain (CP12): the CLI's database access is read-only.
"""

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Engine

from audit_log_service.application.verification import verify_snapshot
from audit_log_service.integrity.checkpoints import (
    Checkpoint,
    key_id,
    sign_checkpoint,
    verify_checkpoint,
)
from audit_log_service.integrity.verification import Violation
from audit_log_service.persistence.checkpoint_store import (
    checkpoint_file_name,
    load_latest_checkpoint,
)
from audit_log_service.persistence.checkpoint_writer import write_checkpoint


class CheckpointOutcome(StrEnum):
    CHECKPOINT_CREATED = "CHECKPOINT_CREATED"
    CHECKPOINT_CURRENT = "CHECKPOINT_CURRENT"


@dataclass(frozen=True, slots=True)
class CheckpointResult:
    outcome: CheckpointOutcome
    checkpoint: Checkpoint
    file_name: str


class ChainNotIntactError(Exception):
    """Verification found a violation, so no checkpoint is signed."""

    def __init__(self, violation: Violation) -> None:
        super().__init__(violation.type.value)
        self.violation = violation


class EmptyChainError(Exception):
    """The chain has no records, so there is no head to checkpoint."""


def create_checkpoint(
    engine: Engine, store_dir: Path, private_key: Ed25519PrivateKey, operator: str
) -> CheckpointResult:
    """Verify the chain and checkpoint its head, or report that the head is already checkpointed."""
    public_key = private_key.public_key()
    latest = load_latest_checkpoint(store_dir, public_key)
    verification = verify_snapshot(engine, latest)
    result = verification.result
    if result.first_violation is not None:
        raise ChainNotIntactError(result.first_violation)
    head = result.head
    if head is None:
        raise EmptyChainError
    if (
        latest is not None
        and latest.checkpoint.sequence == head.sequence
        and latest.checkpoint.record_hash == head.record_hash
    ):
        return CheckpointResult(
            CheckpointOutcome.CHECKPOINT_CURRENT,
            latest.checkpoint,
            checkpoint_file_name(latest.checkpoint.sequence),
        )
    checkpoint = Checkpoint(
        sequence=head.sequence,
        record_hash=head.record_hash,
        created_at=verification.verified_at,
        created_by=operator,
        key_id=key_id(public_key),
    )
    signed = sign_checkpoint(private_key, checkpoint)
    verify_checkpoint(signed, public_key)
    file_name = write_checkpoint(store_dir, signed)
    return CheckpointResult(CheckpointOutcome.CHECKPOINT_CREATED, checkpoint, file_name)
