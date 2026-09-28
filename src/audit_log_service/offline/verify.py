"""`audit-log-verify checkpoint --public-key <spki.pem> <artifact>...` (Phase 10 decision CP13).

Checks each supplied checkpoint artifact without the service, the database, or any `AUDIT_LOG_*`
setting: strict format, a `keyId` that is the fingerprint of the supplied public key, and the
Ed25519 signature. The public key is trusted as supplied; obtain it out of band.

One JSON line per artifact on stdout: `VALID` with the signed checkpoint fields, or `INVALID` with a
fixed reason (`MALFORMED`, `KEY_MISMATCH`, or `SIGNATURE_INVALID`). Exit codes: 0 every artifact is
valid, 1 at least one is invalid, 2 usage error (including an unreadable key or artifact file).

Export-bundle verification is added with exports (FR-7).
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn, TextIO

from audit_log_service.integrity.checkpoints import (
    MAX_ARTIFACT_BYTES,
    CheckpointError,
    KeyFormatError,
    load_public_key,
    parse_artifact,
    verify_checkpoint,
)

EXIT_VALID = 0
EXIT_INVALID = 1
EXIT_USAGE = 2


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise _UsageError(message)


def main() -> int:
    """Console entry point."""
    return run(sys.argv[1:], stdout=sys.stdout, stderr=sys.stderr)


def run(argv: Sequence[str], *, stdout: TextIO, stderr: TextIO) -> int:
    """Run the command and return its exit code."""
    parser = _Parser(prog="audit-log-verify", description="Verify audit log evidence offline.")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    checkpoint = commands.add_parser("checkpoint", help="verify signed checkpoint artifacts")
    checkpoint.add_argument("--public-key", required=True, type=Path, help="Ed25519 SPKI PEM file")
    checkpoint.add_argument("artifacts", nargs="+", type=Path, help="checkpoint artifact files")
    try:
        arguments = parser.parse_args(argv)
    except _UsageError as error:
        return _usage(stderr, str(error))

    key_path: Path = arguments.public_key
    try:
        public_key = load_public_key(key_path.read_bytes())
    except (OSError, KeyFormatError):
        return _usage(stderr, f"cannot read an Ed25519 SubjectPublicKeyInfo PEM key: {key_path}")

    all_valid = True
    artifact_paths: list[Path] = arguments.artifacts
    for path in artifact_paths:
        try:
            with path.open("rb") as file:
                data = file.read(MAX_ARTIFACT_BYTES + 1)
        except OSError:
            return _usage(stderr, f"cannot read artifact: {path}")
        try:
            signed = parse_artifact(data)
            verify_checkpoint(signed, public_key)
        except CheckpointError as error:
            all_valid = False
            line: dict[str, object] = {
                "file": str(path),
                "result": "INVALID",
                "reason": error.failure.value,
            }
        else:
            line = {"file": str(path), "result": "VALID", "checkpoint": signed.checkpoint.to_json()}
        stdout.write(json.dumps(line) + "\n")
    return EXIT_VALID if all_valid else EXIT_INVALID


def _usage(stderr: TextIO, message: str) -> int:
    stderr.write(f"usage error: {message}\n")
    return EXIT_USAGE
