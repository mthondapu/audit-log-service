"""`audit-log-verify export`: offline export verification (FR-7, Phase 11 decisions E12 to E15)."""

import io
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_log_service.integrity.checkpoints import (
    Checkpoint,
    encode_artifact,
    key_id,
    sign_checkpoint,
)
from audit_log_service.offline import verify

Run = Callable[..., tuple[int, list[dict[str, Any]], str]]
ExportBundleWriter = Callable[[Ed25519PrivateKey], tuple[Path, list[str]]]


@pytest.fixture
def run() -> Run:
    def run_verifier(*argv: str | Path) -> tuple[int, list[dict[str, Any]], str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        code = verify.run([str(arg) for arg in argv], stdout=stdout, stderr=stderr)
        lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
        return code, lines, stderr.getvalue()

    return run_verifier


@pytest.fixture
def checkpoint_file(tmp_path: Path) -> Callable[..., Path]:
    def write(key: Ed25519PrivateKey, sequence: int, record_hash: str) -> Path:
        checkpoint = Checkpoint(
            sequence=sequence,
            record_hash=record_hash,
            created_at="2026-09-28T10:15:30.123456Z",
            created_by="ops.admin",
            key_id=key_id(key.public_key()),
        )
        path = tmp_path / f"checkpoint-{sequence}-{record_hash[:4]}.json"
        path.write_bytes(encode_artifact(sign_checkpoint(key, checkpoint)))
        return path

    return write


def _checkpoint_args(key_file: Path, *paths: Path) -> list[str | Path]:
    arguments: list[str | Path] = ["--checkpoint-public-key", key_file]
    for path in paths:
        arguments += ["--checkpoint", path]
    return arguments


def test_valid_export_is_reported_with_its_signed_summary(
    run: Run,
    write_export_bundle: ExportBundleWriter,
    export_key: Ed25519PrivateKey,
    export_public_key_file: Path,
) -> None:
    bundle, _ = write_export_bundle(export_key)

    code, lines, errors = run("export", "--public-key", export_public_key_file, bundle)

    assert (code, errors) == (verify.EXIT_VALID, "")
    assert lines == [
        {
            "file": str(bundle),
            "result": "VALID",
            "asOfSequence": 3,
            "recordCount": 2,
            "keyId": key_id(export_key.public_key()),
            "violationCount": 0,
            "firstViolation": None,
        }
    ]


def test_tampered_export_is_invalid_and_never_prints_values(
    run: Run,
    write_export_bundle: ExportBundleWriter,
    export_key: Ed25519PrivateKey,
    export_public_key_file: Path,
) -> None:
    bundle, _ = write_export_bundle(export_key)
    document = json.loads(bundle.read_bytes())
    document["records"][1]["payloadValues"]["/card"]["value"] = "test-only-4112"
    bundle.write_text(json.dumps(document), encoding="utf-8")

    code, lines, _ = run("export", "--public-key", export_public_key_file, bundle)

    assert code == verify.EXIT_INVALID
    assert lines[0]["result"] == "INVALID"
    assert lines[0]["firstViolation"] == {
        "type": "PAYLOAD_VALUE_MISMATCH",
        "sequence": 3,
        "recordId": document["records"][1]["id"],
    }
    output = json.dumps(lines)
    assert "test-only-4111" not in output
    assert "test-only-4112" not in output


def test_untrusted_manifest_reports_no_manifest_fields(
    run: Run, write_export_bundle: ExportBundleWriter, export_public_key_file: Path
) -> None:
    bundle, _ = write_export_bundle(Ed25519PrivateKey.generate())

    code, lines, _ = run("export", "--public-key", export_public_key_file, bundle)

    assert code == verify.EXIT_INVALID
    assert lines[0] == {
        "file": str(bundle),
        "result": "INVALID",
        "asOfSequence": None,
        "recordCount": None,
        "keyId": None,
        "violationCount": 1,
        "firstViolation": {"type": "KEY_MISMATCH", "sequence": None, "recordId": None},
    }


def test_checkpoints_are_anchored_only_to_signed_export_evidence(
    run: Run,
    write_export_bundle: ExportBundleWriter,
    export_key: Ed25519PrivateKey,
    export_public_key_file: Path,
    checkpoint_key: Ed25519PrivateKey,
    checkpoint_public_key_file: Path,
    checkpoint_file: Callable[..., Path],
) -> None:
    bundle, hashes = write_export_bundle(export_key)
    at_as_of = checkpoint_file(checkpoint_key, 3, hashes[2])
    at_record = checkpoint_file(checkpoint_key, 1, hashes[0])
    not_included = checkpoint_file(checkpoint_key, 2, hashes[1])
    beyond = checkpoint_file(checkpoint_key, 7, "e" * 64)

    code, lines, _ = run(
        "export",
        "--public-key",
        export_public_key_file,
        bundle,
        *_checkpoint_args(checkpoint_public_key_file, at_as_of, at_record, not_included, beyond),
    )

    assert code == verify.EXIT_VALID
    assert [(line["file"], line["result"], line["sequence"]) for line in lines[1:]] == [
        (str(at_as_of), "MATCH", 3),
        (str(at_record), "MATCH", 1),
        (str(not_included), "NOT_APPLICABLE", 2),
        (str(beyond), "NOT_APPLICABLE", 7),
    ]


@pytest.mark.parametrize("sequence", [3, 1], ids=["at-as-of", "at-included-record"])
def test_mismatching_checkpoint_makes_the_result_invalid(
    run: Run,
    write_export_bundle: ExportBundleWriter,
    export_key: Ed25519PrivateKey,
    export_public_key_file: Path,
    checkpoint_key: Ed25519PrivateKey,
    checkpoint_public_key_file: Path,
    checkpoint_file: Callable[..., Path],
    sequence: int,
) -> None:
    bundle, _ = write_export_bundle(export_key)
    mismatching = checkpoint_file(checkpoint_key, sequence, "e" * 64)

    code, lines, _ = run(
        "export",
        "--public-key",
        export_public_key_file,
        bundle,
        *_checkpoint_args(checkpoint_public_key_file, mismatching),
    )

    assert code == verify.EXIT_INVALID
    assert lines[0]["result"] == "VALID"
    assert lines[1] == {"file": str(mismatching), "result": "MISMATCH", "sequence": sequence}


@pytest.mark.parametrize("problem", ["other-key", "malformed", "tampered"])
def test_invalid_checkpoint_is_reported_and_never_used(
    run: Run,
    write_export_bundle: ExportBundleWriter,
    export_key: Ed25519PrivateKey,
    export_public_key_file: Path,
    checkpoint_key: Ed25519PrivateKey,
    checkpoint_public_key_file: Path,
    checkpoint_file: Callable[..., Path],
    tmp_path: Path,
    problem: str,
) -> None:
    bundle, hashes = write_export_bundle(export_key)
    if problem == "other-key":
        path = checkpoint_file(Ed25519PrivateKey.generate(), 3, hashes[2])
        reason = "KEY_MISMATCH"
    elif problem == "malformed":
        path = tmp_path / "malformed.json"
        path.write_bytes(b"{}")
        reason = "MALFORMED"
    else:
        path = checkpoint_file(checkpoint_key, 3, hashes[2])
        document = json.loads(path.read_bytes())
        document["checkpoint"]["createdBy"] = "someone.else"
        path.write_text(json.dumps(document), encoding="utf-8")
        reason = "SIGNATURE_INVALID"

    code, lines, _ = run(
        "export",
        "--public-key",
        export_public_key_file,
        bundle,
        *_checkpoint_args(checkpoint_public_key_file, path),
    )

    assert code == verify.EXIT_INVALID
    assert lines[0]["result"] == "VALID"
    assert lines[1] == {"file": str(path), "result": "INVALID", "reason": reason}


def test_checkpoint_key_alone_is_accepted(
    run: Run,
    write_export_bundle: ExportBundleWriter,
    export_key: Ed25519PrivateKey,
    export_public_key_file: Path,
    checkpoint_public_key_file: Path,
) -> None:
    bundle, _ = write_export_bundle(export_key)
    code, lines, _ = run(
        "export",
        "--public-key",
        export_public_key_file,
        bundle,
        *_checkpoint_args(checkpoint_public_key_file),
    )
    assert (code, len(lines)) == (verify.EXIT_VALID, 1)


def test_checkpoint_without_its_key_is_a_usage_error(
    run: Run,
    write_export_bundle: ExportBundleWriter,
    export_key: Ed25519PrivateKey,
    export_public_key_file: Path,
    tmp_path: Path,
) -> None:
    bundle, _ = write_export_bundle(export_key)
    code, lines, errors = run(
        "export",
        "--public-key",
        export_public_key_file,
        bundle,
        "--checkpoint",
        tmp_path / "c.json",
    )
    assert (code, lines) == (verify.EXIT_USAGE, [])
    assert errors == "usage error: --checkpoint requires --checkpoint-public-key\n"


@pytest.mark.parametrize("missing", ["bundle", "key", "checkpoint-key", "checkpoint"])
def test_unreadable_export_inputs_are_usage_errors(
    run: Run,
    write_export_bundle: ExportBundleWriter,
    export_key: Ed25519PrivateKey,
    export_public_key_file: Path,
    checkpoint_public_key_file: Path,
    tmp_path: Path,
    missing: str,
) -> None:
    bundle, _ = write_export_bundle(export_key)
    absent = tmp_path / "absent"
    arguments: dict[str, list[str | Path]] = {
        "bundle": ["export", "--public-key", export_public_key_file, absent],
        "key": ["export", "--public-key", absent, bundle],
        "checkpoint-key": [
            "export",
            "--public-key",
            export_public_key_file,
            bundle,
            *_checkpoint_args(absent, bundle),
        ],
        "checkpoint": [
            "export",
            "--public-key",
            export_public_key_file,
            bundle,
            *_checkpoint_args(checkpoint_public_key_file, absent),
        ],
    }

    code, lines, errors = run(*arguments[missing])

    assert (code, lines) == (verify.EXIT_USAGE, [])
    assert errors.startswith("usage error: cannot read")
    assert str(absent) in errors


def test_export_usage_errors_exit_2(run: Run) -> None:
    code, lines, errors = run("export", "--public-key", "key.pem")
    assert (code, lines) == (verify.EXIT_USAGE, [])
    assert errors.startswith("usage error: ")
