"""The checkpoint store: validation, latest selection, and exclusive writes (FR-4, CP6)."""

import os
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_log_service.integrity.checkpoints import (
    Checkpoint,
    SignedCheckpoint,
    encode_artifact,
    key_id,
    sign_checkpoint,
)
from audit_log_service.persistence import checkpoint_writer
from audit_log_service.persistence.checkpoint_store import (
    CheckpointStoreError,
    checkpoint_file_name,
    load_latest_checkpoint,
)
from audit_log_service.persistence.checkpoint_writer import CheckpointExistsError, write_checkpoint


def _signed(key: Ed25519PrivateKey, sequence: int, **changes: Any) -> SignedCheckpoint:
    fields: dict[str, Any] = {
        "sequence": sequence,
        "record_hash": f"{sequence:064x}",
        "created_at": "2026-09-28T10:15:30.123456Z",
        "created_by": "ops.admin",
        "key_id": key_id(key.public_key()),
    }
    fields.update(changes)
    return sign_checkpoint(key, Checkpoint(**fields))


def test_file_names_are_twenty_digit_sequences() -> None:
    assert checkpoint_file_name(42) == "checkpoint-00000000000000000042.json"
    assert checkpoint_file_name(2**53 - 1) == "checkpoint-00009007199254740991.json"


def test_empty_store_has_no_checkpoint(
    checkpoint_store: Path, checkpoint_key: Ed25519PrivateKey
) -> None:
    assert load_latest_checkpoint(checkpoint_store, checkpoint_key.public_key()) is None


def test_latest_is_the_highest_sequence(
    checkpoint_store: Path, checkpoint_key: Ed25519PrivateKey
) -> None:
    for sequence in (9, 100, 10):
        write_checkpoint(checkpoint_store, _signed(checkpoint_key, sequence))

    latest = load_latest_checkpoint(checkpoint_store, checkpoint_key.public_key())

    assert latest == _signed(checkpoint_key, 100)


def test_unrelated_names_are_ignored(
    checkpoint_store: Path, checkpoint_key: Ed25519PrivateKey
) -> None:
    write_checkpoint(checkpoint_store, _signed(checkpoint_key, 3))
    for name in (
        "README.txt",
        "checkpoint-5.json",
        "checkpoint-00000000000000000005.json.bak",
        ".checkpoint-00000000000000000005.json.abc.tmp",
        "Checkpoint-00000000000000000005.json",
    ):
        (checkpoint_store / name).write_bytes(b"garbage")
    (checkpoint_store / "subdirectory").mkdir()

    latest = load_latest_checkpoint(checkpoint_store, checkpoint_key.public_key())

    assert latest is not None and latest.checkpoint.sequence == 3


@pytest.mark.parametrize(
    "content",
    ["garbage", "other-key", "bad-signature", "wrong-name"],
)
def test_invalid_matching_artifact_fails_closed(
    checkpoint_store: Path, checkpoint_key: Ed25519PrivateKey, content: str
) -> None:
    write_checkpoint(checkpoint_store, _signed(checkpoint_key, 9))
    name = checkpoint_file_name(3)
    other = Ed25519PrivateKey.generate()
    data = {
        "garbage": lambda: b"not json",
        "other-key": lambda: encode_artifact(_signed(other, 3)),
        "bad-signature": lambda: encode_artifact(
            SignedCheckpoint(_signed(checkpoint_key, 3).checkpoint, "0" * 128)
        ),
        "wrong-name": lambda: encode_artifact(_signed(checkpoint_key, 4)),
    }[content]()
    (checkpoint_store / name).write_bytes(data)

    with pytest.raises(CheckpointStoreError) as caught:
        load_latest_checkpoint(checkpoint_store, checkpoint_key.public_key())

    assert caught.value.file_name == name
    assert "not json" not in str(caught.value)


def test_error_names_the_failure_reason(
    checkpoint_store: Path, checkpoint_key: Ed25519PrivateKey
) -> None:
    other = Ed25519PrivateKey.generate()
    (checkpoint_store / checkpoint_file_name(3)).write_bytes(encode_artifact(_signed(other, 3)))
    with pytest.raises(CheckpointStoreError, match=r"invalid \(KEY_MISMATCH\)"):
        load_latest_checkpoint(checkpoint_store, checkpoint_key.public_key())


def test_oversized_artifact_fails_closed(
    checkpoint_store: Path, checkpoint_key: Ed25519PrivateKey
) -> None:
    (checkpoint_store / checkpoint_file_name(1)).write_bytes(b" " * (1024 * 1024))
    with pytest.raises(CheckpointStoreError, match="MALFORMED"):
        load_latest_checkpoint(checkpoint_store, checkpoint_key.public_key())


def test_matching_directory_name_fails_closed(
    checkpoint_store: Path, checkpoint_key: Ed25519PrivateKey
) -> None:
    (checkpoint_store / checkpoint_file_name(1)).mkdir()
    with pytest.raises(CheckpointStoreError, match="cannot be read") as caught:
        load_latest_checkpoint(checkpoint_store, checkpoint_key.public_key())
    assert caught.value.file_name == checkpoint_file_name(1)


def test_missing_store_is_unreadable(tmp_path: Path, checkpoint_key: Ed25519PrivateKey) -> None:
    with pytest.raises(CheckpointStoreError, match="cannot be read") as caught:
        load_latest_checkpoint(tmp_path / "missing", checkpoint_key.public_key())
    assert caught.value.file_name is None


def test_written_artifact_is_the_encoded_checkpoint(
    checkpoint_store: Path, checkpoint_key: Ed25519PrivateKey
) -> None:
    signed = _signed(checkpoint_key, 7)

    name = write_checkpoint(checkpoint_store, signed)

    assert name == checkpoint_file_name(7)
    assert (checkpoint_store / name).read_bytes() == encode_artifact(signed)
    assert sorted(p.name for p in checkpoint_store.iterdir()) == [name]  # no temporary file left


def test_existing_checkpoint_is_never_overwritten(
    checkpoint_store: Path, checkpoint_key: Ed25519PrivateKey
) -> None:
    first = _signed(checkpoint_key, 7)
    write_checkpoint(checkpoint_store, first)

    with pytest.raises(CheckpointExistsError, match=checkpoint_file_name(7)):
        write_checkpoint(checkpoint_store, _signed(checkpoint_key, 7, created_by="someone.else"))

    assert (checkpoint_store / checkpoint_file_name(7)).read_bytes() == encode_artifact(first)
    assert sorted(p.name for p in checkpoint_store.iterdir()) == [checkpoint_file_name(7)]


def test_artifact_is_flushed_to_disk_before_it_is_named(
    checkpoint_store: Path, checkpoint_key: Ed25519PrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    real_fsync, real_link = os.fsync, os.link

    def fsync(descriptor: int) -> None:
        events.append("fsync")
        real_fsync(descriptor)

    def link(source: Path, target: Path) -> None:
        events.append(f"link {Path(source).name.startswith('.')} {Path(target).name}")
        real_link(source, target)

    monkeypatch.setattr(checkpoint_writer.os, "fsync", fsync)
    monkeypatch.setattr(checkpoint_writer.os, "link", link)

    write_checkpoint(checkpoint_store, _signed(checkpoint_key, 1))

    assert events == ["fsync", f"link True {checkpoint_file_name(1)}"]


def test_failed_link_leaves_no_file(
    checkpoint_store: Path, checkpoint_key: Ed25519PrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    def link(_source: Path, _target: Path) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr(checkpoint_writer.os, "link", link)

    with pytest.raises(PermissionError):
        write_checkpoint(checkpoint_store, _signed(checkpoint_key, 1))
    assert list(checkpoint_store.iterdir()) == []


def test_temporary_file_is_outside_the_artifact_pattern(
    checkpoint_store: Path, checkpoint_key: Ed25519PrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    def link(source: Path, _target: Path) -> None:
        seen.append(Path(source).name)
        # A reader running now sees the temporary file and must ignore it.
        assert load_latest_checkpoint(checkpoint_store, checkpoint_key.public_key()) is None
        raise FileExistsError

    monkeypatch.setattr(checkpoint_writer.os, "link", link)
    with pytest.raises(CheckpointExistsError):
        write_checkpoint(checkpoint_store, _signed(checkpoint_key, 1))
    assert seen[0].startswith(".checkpoint-00000000000000000001.json.")
    assert seen[0].endswith(".tmp")
