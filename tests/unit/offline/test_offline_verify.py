"""`audit-log-verify checkpoint`: offline checkpoint verification (FR-4, Phase 10 decision CP13)."""

import io
import json
import sys
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


@pytest.fixture
def run() -> Run:
    def run_verifier(*argv: str | Path) -> tuple[int, list[dict[str, Any]], str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        code = verify.run([str(arg) for arg in argv], stdout=stdout, stderr=stderr)
        lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
        return code, lines, stderr.getvalue()

    return run_verifier


@pytest.fixture
def artifact(tmp_path: Path) -> Callable[..., Path]:
    def write(key: Ed25519PrivateKey, sequence: int = 5, name: str | None = None) -> Path:
        checkpoint = Checkpoint(
            sequence=sequence,
            record_hash=f"{sequence:064x}",
            created_at="2026-09-28T10:15:30.123456Z",
            created_by="ops.admin",
            key_id=key_id(key.public_key()),
        )
        path = tmp_path / (name or f"artifact-{sequence}.json")
        path.write_bytes(encode_artifact(sign_checkpoint(key, checkpoint)))
        return path

    return write


def test_valid_artifact_is_reported_with_its_signed_fields(
    run: Run,
    artifact: Callable[..., Path],
    checkpoint_key: Ed25519PrivateKey,
    checkpoint_public_key_file: Path,
) -> None:
    path = artifact(checkpoint_key)

    code, lines, errors = run("checkpoint", "--public-key", checkpoint_public_key_file, path)

    assert (code, errors) == (verify.EXIT_VALID, "")
    assert lines == [
        {
            "file": str(path),
            "result": "VALID",
            "checkpoint": {
                "scheme": "audit-log/v1",
                "sequence": 5,
                "recordHash": f"{5:064x}",
                "createdAt": "2026-09-28T10:15:30.123456Z",
                "createdBy": "ops.admin",
                "keyId": key_id(checkpoint_key.public_key()),
            },
        }
    ]


def test_each_artifact_gets_one_result_and_any_invalid_one_fails(
    run: Run,
    artifact: Callable[..., Path],
    checkpoint_key: Ed25519PrivateKey,
    checkpoint_public_key_file: Path,
    tmp_path: Path,
) -> None:
    valid = artifact(checkpoint_key, 5)
    other_key = artifact(Ed25519PrivateKey.generate(), 6)
    tampered = artifact(checkpoint_key, 7)
    document = json.loads(tampered.read_bytes())
    document["checkpoint"]["sequence"] = 8
    tampered.write_text(json.dumps(document), encoding="utf-8")
    malformed = tmp_path / "malformed.json"
    malformed.write_bytes(b"{}")

    code, lines, _ = run(
        "checkpoint",
        "--public-key",
        checkpoint_public_key_file,
        valid,
        other_key,
        tampered,
        malformed,
    )

    assert code == verify.EXIT_INVALID
    assert [(line["file"], line["result"], line.get("reason")) for line in lines] == [
        (str(valid), "VALID", None),
        (str(other_key), "INVALID", "KEY_MISMATCH"),
        (str(tampered), "INVALID", "SIGNATURE_INVALID"),
        (str(malformed), "INVALID", "MALFORMED"),
    ]


def test_invalid_result_contains_only_the_fixed_reason(
    run: Run, checkpoint_public_key_file: Path, tmp_path: Path
) -> None:
    path = tmp_path / "secret.json"
    path.write_text('{"checkpoint": "test-only-secret-content"}', encoding="utf-8")
    _, lines, _ = run("checkpoint", "--public-key", checkpoint_public_key_file, path)
    assert lines == [{"file": str(path), "result": "INVALID", "reason": "MALFORMED"}]


@pytest.mark.parametrize(
    "argv",
    [
        (),
        ("checkpoint",),
        ("checkpoint", "--public-key", "key.pem"),
        ("export", "bundle.json"),
    ],
    ids=["nothing", "no-key", "no-artifacts", "unknown-command"],
)
def test_usage_errors_exit_2(run: Run, argv: tuple[str, ...]) -> None:
    code, lines, errors = run(*argv)
    assert (code, lines) == (verify.EXIT_USAGE, [])
    assert errors.startswith("usage error: ")


@pytest.mark.parametrize("key_problem", ["missing", "not-a-key", "private-key"])
def test_unusable_public_key_is_a_usage_error(
    run: Run,
    artifact: Callable[..., Path],
    checkpoint_key: Ed25519PrivateKey,
    checkpoint_signing_key_file: Path,
    tmp_path: Path,
    key_problem: str,
) -> None:
    key_file = {
        "missing": tmp_path / "missing.pem",
        "not-a-key": artifact(checkpoint_key),
        "private-key": checkpoint_signing_key_file,
    }[key_problem]

    code, lines, errors = run("checkpoint", "--public-key", key_file, artifact(checkpoint_key))

    assert (code, lines) == (verify.EXIT_USAGE, [])
    assert errors == (
        f"usage error: cannot read an Ed25519 SubjectPublicKeyInfo PEM key: {key_file}\n"
    )
    assert "PRIVATE" not in errors


def test_unreadable_artifact_is_a_usage_error(
    run: Run, checkpoint_public_key_file: Path, tmp_path: Path
) -> None:
    missing = tmp_path / "missing.json"
    code, lines, errors = run("checkpoint", "--public-key", checkpoint_public_key_file, missing)
    assert (code, lines, errors) == (
        verify.EXIT_USAGE,
        [],
        f"usage error: cannot read artifact: {missing}\n",
    )


def test_main_runs_with_the_process_arguments(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    artifact: Callable[..., Path],
    checkpoint_key: Ed25519PrivateKey,
    checkpoint_public_key_file: Path,
) -> None:
    path = artifact(checkpoint_key)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "audit-log-verify",
            "checkpoint",
            "--public-key",
            str(checkpoint_public_key_file),
            str(path),
        ],
    )
    assert verify.main() == verify.EXIT_VALID
    assert json.loads(capsys.readouterr().out)["result"] == "VALID"
