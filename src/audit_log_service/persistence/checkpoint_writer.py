"""Writing checkpoints to the store (requirements FR-4, Phase 10 decision CP6).

Only the checkpoint CLI uses this module; the service never imports it. A checkpoint is written to
a temporary file in the store, flushed to disk, and then hard-linked to its final name. Linking
fails if the name already exists, so an existing checkpoint is never overwritten, and a reader
never sees a partly written artifact under a checkpoint name.
"""

import os
import secrets
from pathlib import Path

from audit_log_service.integrity.checkpoints import SignedCheckpoint, encode_artifact
from audit_log_service.persistence.checkpoint_store import checkpoint_file_name


class CheckpointExistsError(Exception):
    """A checkpoint with this sequence is already in the store."""


def write_checkpoint(store_dir: Path, signed: SignedCheckpoint) -> str:
    """Write a signed checkpoint under its sequence's name and return that name."""
    name = checkpoint_file_name(signed.checkpoint.sequence)
    # A leading dot and another suffix keep the temporary file outside the artifact name pattern.
    temporary = store_dir / f".{name}.{secrets.token_hex(8)}.tmp"
    with temporary.open("xb") as file:
        file.write(encode_artifact(signed))
        file.flush()
        os.fsync(file.fileno())
    try:
        os.link(temporary, store_dir / name)
    except FileExistsError:
        raise CheckpointExistsError(name) from None
    finally:
        temporary.unlink()
    return name
