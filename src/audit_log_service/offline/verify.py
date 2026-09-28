"""`audit-log-verify`: offline verification of checkpoints and export bundles (FR-4, FR-7).

Nothing here needs the service, the database, or any `AUDIT_LOG_*` setting. Public keys are trusted
as supplied; obtain them out of band. Output never contains payload values.

`audit-log-verify checkpoint --public-key <spki.pem> <artifact>...` (Phase 10 decision CP13):
one JSON line per artifact: `VALID` with the signed checkpoint fields, or `INVALID` with a fixed
reason (`MALFORMED`, `KEY_MISMATCH`, or `SIGNATURE_INVALID`).

`audit-log-verify export --public-key <export-spki.pem> <bundle.json>
[--checkpoint-public-key <cp-spki.pem> --checkpoint <artifact>...]` (Phase 11 decisions E12 to E15):
a summary line for the bundle (`VALID` or `INVALID`, `asOfSequence`, `recordCount`, and `keyId`
from the verified manifest, `violationCount`, and `firstViolation` as type, sequence, and record
identifier), then one line per checkpoint: `MATCH`, `MISMATCH`, or `NOT_APPLICABLE` against the
signed export evidence (L-D1), or `INVALID` with a fixed reason; an invalid checkpoint is never
used.

Exit codes: 0 everything is valid (for an export, no checkpoint mismatches or is invalid), 1
something is invalid, 2 usage error (including an unreadable key, artifact, or bundle file).
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn, TextIO

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from audit_log_service.integrity.checkpoints import (
    MAX_ARTIFACT_BYTES,
    CheckpointError,
    KeyFormatError,
    load_public_key,
    parse_artifact,
    verify_checkpoint,
)
from audit_log_service.integrity.exports import (
    MAX_BUNDLE_BYTES,
    AnchorResult,
    ExportVerification,
    anchor_checkpoint,
    verify_export,
)

EXIT_VALID = 0
EXIT_INVALID = 1
EXIT_USAGE = 2
# A checkpoint that matches, or cannot be anchored to this export, does not make it invalid (L-D1).
_ACCEPTED_ANCHORS = (AnchorResult.MATCH.value, AnchorResult.NOT_APPLICABLE.value)


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
    export = commands.add_parser("export", help="verify a signed export bundle")
    export.add_argument("--public-key", required=True, type=Path, help="export SPKI PEM file")
    export.add_argument("bundle", type=Path, help="export bundle file")
    export.add_argument("--checkpoint-public-key", type=Path, help="checkpoint SPKI PEM file")
    export.add_argument(
        "--checkpoint",
        dest="checkpoints",
        action="append",
        default=[],
        type=Path,
        help="checkpoint artifact file; may be repeated",
    )
    try:
        arguments = parser.parse_args(argv)
    except _UsageError as error:
        return _usage(stderr, str(error))
    if arguments.command == "checkpoint":
        return _verify_checkpoints(arguments.public_key, arguments.artifacts, stdout, stderr)
    return _verify_export(
        arguments.public_key,
        arguments.bundle,
        arguments.checkpoint_public_key,
        arguments.checkpoints,
        stdout,
        stderr,
    )


def _verify_checkpoints(
    key_path: Path, artifact_paths: list[Path], stdout: TextIO, stderr: TextIO
) -> int:
    try:
        public_key = _public_key(key_path)
    except _UsageError as error:
        return _usage(stderr, str(error))

    all_valid = True
    for path in artifact_paths:
        try:
            data = _read(path, MAX_ARTIFACT_BYTES, "artifact")
        except _UsageError as error:
            return _usage(stderr, str(error))
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
        _write(stdout, line)
    return EXIT_VALID if all_valid else EXIT_INVALID


def _verify_export(
    key_path: Path,
    bundle_path: Path,
    checkpoint_key_path: Path | None,
    checkpoint_paths: list[Path],
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    if checkpoint_paths and checkpoint_key_path is None:
        return _usage(stderr, "--checkpoint requires --checkpoint-public-key")
    try:
        public_key = _public_key(key_path)
        checkpoint_key = None if checkpoint_key_path is None else _public_key(checkpoint_key_path)
        bundle = _read(bundle_path, MAX_BUNDLE_BYTES, "bundle")
        artifacts = [
            (path, _read(path, MAX_ARTIFACT_BYTES, "artifact")) for path in checkpoint_paths
        ]
    except _UsageError as error:
        return _usage(stderr, str(error))

    verification = verify_export(bundle, public_key)
    manifest = verification.manifest
    violation = verification.first_violation
    _write(
        stdout,
        {
            "file": str(bundle_path),
            "result": "VALID" if verification.valid else "INVALID",
            "asOfSequence": None if manifest is None else manifest.as_of_sequence,
            "recordCount": None if manifest is None else manifest.record_count,
            "keyId": None if manifest is None else manifest.key_id,
            "violationCount": verification.violation_count,
            "firstViolation": None
            if violation is None
            else {
                "type": violation.type.value,
                "sequence": violation.sequence,
                "recordId": violation.record_id,
            },
        },
    )

    all_valid = verification.valid
    if checkpoint_key is not None:
        for path, data in artifacts:
            line = _checkpoint_line(path, data, checkpoint_key, verification)
            all_valid = all_valid and line["result"] in _ACCEPTED_ANCHORS
            _write(stdout, line)
    return EXIT_VALID if all_valid else EXIT_INVALID


def _checkpoint_line(
    path: Path,
    data: bytes,
    checkpoint_key: Ed25519PublicKey,
    verification: ExportVerification,
) -> dict[str, object]:
    try:
        signed = parse_artifact(data)
        verify_checkpoint(signed, checkpoint_key)
    except CheckpointError as error:
        return {"file": str(path), "result": "INVALID", "reason": error.failure.value}
    result = anchor_checkpoint(verification, signed.checkpoint)
    return {"file": str(path), "result": result.value, "sequence": signed.checkpoint.sequence}


def _public_key(path: Path) -> Ed25519PublicKey:
    try:
        return load_public_key(path.read_bytes())
    except (OSError, KeyFormatError):
        raise _UsageError(f"cannot read an Ed25519 SubjectPublicKeyInfo PEM key: {path}") from None


def _read(path: Path, limit: int, kind: str) -> bytes:
    try:
        with path.open("rb") as file:
            # One byte beyond the limit is enough for the parser to reject an oversized file.
            return file.read(limit + 1)
    except OSError:
        raise _UsageError(f"cannot read {kind}: {path}") from None


def _write(stdout: TextIO, line: dict[str, object]) -> None:
    stdout.write(json.dumps(line) + "\n")


def _usage(stderr: TextIO, message: str) -> int:
    stderr.write(f"usage error: {message}\n")
    return EXIT_USAGE
