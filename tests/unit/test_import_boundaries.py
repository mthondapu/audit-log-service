"""Import boundaries for the checkpoint trust model (FR-4, Phase 10 decisions CP1, CP8, CP13).

Each check runs in a fresh interpreter, so modules imported by other tests cannot hide a leak.
"""

import json
import os
import subprocess  # nosec B404 - runs this project's own modules with the test interpreter
import sys
from importlib.metadata import entry_points
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_log_service.integrity.checkpoints import (
    Checkpoint,
    encode_artifact,
    key_id,
    sign_checkpoint,
)

SERVICE_LIBRARIES = {
    "sqlalchemy",
    "fastapi",
    "starlette",
    "psycopg",
    "pydantic",
    "alembic",
    "uvicorn",
}
OFFLINE_MODULES = {
    "audit_log_service",
    "audit_log_service.offline",
    "audit_log_service.offline.verify",
    "audit_log_service.integrity",
    "audit_log_service.integrity.canonical",
    "audit_log_service.integrity.checkpoints",
    "audit_log_service.integrity.errors",
    "audit_log_service.integrity.timestamps",
}


def _run_python(code: str, cwd: Path) -> dict[str, object]:
    # No AUDIT_LOG_* variable reaches the child: it must not need any configuration.
    environment = {k: v for k, v in os.environ.items() if not k.startswith("AUDIT_LOG_")}
    completed = subprocess.run(  # nosec B603 - fixed arguments, no shell
        [sys.executable, "-c", code],
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    result: dict[str, object] = json.loads(completed.stdout.splitlines()[-1])
    return result


def test_offline_verifier_runs_without_service_modules_or_configuration(
    tmp_path: Path, checkpoint_key: Ed25519PrivateKey, checkpoint_public_key_file: Path
) -> None:
    checkpoint = Checkpoint(
        sequence=3,
        record_hash="ab" * 32,
        created_at="2026-09-28T10:15:30.123456Z",
        created_by="ops.admin",
        key_id=key_id(checkpoint_key.public_key()),
    )
    artifact = tmp_path / "artifact.json"
    artifact.write_bytes(encode_artifact(sign_checkpoint(checkpoint_key, checkpoint)))
    code = f"""
import io, json, sys
from audit_log_service.offline.verify import run
out, err = io.StringIO(), io.StringIO()
exit_code = run(["checkpoint", "--public-key", {str(checkpoint_public_key_file)!r},
                 {str(artifact)!r}], stdout=out, stderr=err)
print(json.dumps({{"exit": exit_code, "out": out.getvalue(), "modules": sorted(sys.modules)}}))
"""
    result = _run_python(code, tmp_path)

    assert result["exit"] == 0
    assert json.loads(str(result["out"]))["result"] == "VALID"
    modules = {str(name) for name in result["modules"]}  # type: ignore[union-attr]
    assert not {m for m in modules if m.split(".")[0] in SERVICE_LIBRARIES}
    assert {m for m in modules if m.split(".")[0] == "audit_log_service"} <= OFFLINE_MODULES


def test_service_never_imports_the_checkpoint_writer(tmp_path: Path) -> None:
    code = """
import json, sys
import audit_log_service.api.app
print(json.dumps({"modules": sorted(sys.modules)}))
"""
    modules = set(_run_python(code, tmp_path)["modules"])  # type: ignore[arg-type]

    assert "audit_log_service.persistence.checkpoint_store" in modules
    assert "audit_log_service.persistence.checkpoint_writer" not in modules
    assert "audit_log_service.application.checkpoints" not in modules
    assert "audit_log_service.cli.checkpoint" not in modules


def test_console_scripts_are_declared() -> None:
    scripts = {
        entry.name: entry.value
        for entry in entry_points(group="console_scripts")
        if entry.name.startswith("audit-log-")
    }
    assert scripts == {
        "audit-log-checkpoint": "audit_log_service.cli.checkpoint:main",
        "audit-log-verify": "audit_log_service.offline.verify:main",
    }
