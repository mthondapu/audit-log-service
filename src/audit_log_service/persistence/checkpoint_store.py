"""Reading the checkpoint store (requirements FR-4, Phase 10 decisions CP6, CP8, and CP16).

The store is one directory outside the database. Only files named
``checkpoint-<sequence as 20 zero-padded digits>.json`` are checkpoint artifacts; other names are
ignored. Every matching file must parse, name the trusted key, carry a valid signature, and hold
the sequence in its name. Otherwise the whole store is invalid, and nothing is trusted (fail
closed). The latest checkpoint is the valid artifact with the highest sequence.

Callers read the store before opening their database snapshot, so every checkpoint they see covers
records the snapshot already contains (CP16).

This module only reads. Writing is in `checkpoint_writer`, which the service never imports.
"""

import os
import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from audit_log_service.integrity.checkpoints import (
    MAX_ARTIFACT_BYTES,
    CheckpointError,
    SignedCheckpoint,
    parse_artifact,
    verify_checkpoint,
)

_FILE_NAME = re.compile(r"checkpoint-(\d{20})\.json")


class CheckpointStoreError(Exception):
    """The store is unreadable or holds an invalid artifact.

    `file_name` names the offending file, if any. Nothing from an artifact's content is included.
    """

    def __init__(self, message: str, file_name: str | None = None) -> None:
        super().__init__(message)
        self.file_name = file_name


def checkpoint_file_name(sequence: int) -> str:
    return f"checkpoint-{sequence:020d}.json"


def load_latest_checkpoint(
    store_dir: Path, public_key: Ed25519PublicKey
) -> SignedCheckpoint | None:
    """Validate every artifact in the store and return the latest, or `None` if there is none."""
    try:
        names = sorted(entry.name for entry in os.scandir(store_dir))
    except OSError:
        raise CheckpointStoreError("the checkpoint store cannot be read") from None
    latest: SignedCheckpoint | None = None
    for name in names:
        match = _FILE_NAME.fullmatch(name)
        if match is None:
            continue
        signed = _load_artifact(store_dir / name, public_key)
        if signed.checkpoint.sequence != int(match[1]):
            raise CheckpointStoreError("a checkpoint's sequence does not match its file name", name)
        # Fixed-width names sort numerically, so the last valid artifact has the highest sequence.
        latest = signed
    return latest


def _load_artifact(path: Path, public_key: Ed25519PublicKey) -> SignedCheckpoint:
    try:
        with path.open("rb") as file:
            # One byte beyond the limit is enough for the parser to reject an oversized file.
            data = file.read(MAX_ARTIFACT_BYTES + 1)
    except OSError:
        raise CheckpointStoreError("a checkpoint artifact cannot be read", path.name) from None
    try:
        signed = parse_artifact(data)
        verify_checkpoint(signed, public_key)
    except CheckpointError as error:
        raise CheckpointStoreError(
            f"a checkpoint artifact is invalid ({error.failure.value})", path.name
        ) from None
    return signed
