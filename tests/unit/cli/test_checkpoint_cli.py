"""`audit-log-checkpoint`: arguments, credential input, authorization order, and exit codes.

These tests need no database: the database steps are replaced or fail on an in-memory engine. The
end-to-end flow against PostgreSQL is in tests/integration/test_checkpoint_cli.py.
"""

import io
import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Engine, create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from audit_log_service.application.checkpoints import (
    ChainNotIntactError,
    CheckpointOutcome,
    CheckpointResult,
    EmptyChainError,
)
from audit_log_service.cli import checkpoint as cli
from audit_log_service.config.errors import ConfigurationError
from audit_log_service.config.settings import (
    API_KEYS_FILE_VARIABLE,
    CHECKPOINT_DATABASE_URL_VARIABLE,
    CHECKPOINT_SIGNING_KEY_FILE_VARIABLE,
    CHECKPOINT_STORE_DIR_VARIABLE,
)
from audit_log_service.integrity.checkpoints import Checkpoint, key_id
from audit_log_service.integrity.verification import Violation, ViolationType
from audit_log_service.persistence.checkpoint_store import CheckpointStoreError
from audit_log_service.persistence.checkpoint_writer import CheckpointExistsError

DATABASE_URL = "postgresql+psycopg://checkpoint:test-only-password@127.0.0.1:1/audit_log"


class FakeStdin(io.StringIO):
    def __init__(self, text: str = "", *, tty: bool = False) -> None:
        super().__init__(text)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


class Outcome:
    def __init__(self, code: int, stdout: str, stderr: str) -> None:
        self.code, self.stdout, self.stderr = code, stdout, stderr


@pytest.fixture
def environ(
    write_file: Callable[[str, str], Path],
    valid_api_key_toml: str,
    checkpoint_store: Path,
    checkpoint_signing_key_file: Path,
) -> dict[str, str]:
    return {
        CHECKPOINT_DATABASE_URL_VARIABLE: DATABASE_URL,
        API_KEYS_FILE_VARIABLE: str(write_file("api-keys.toml", valid_api_key_toml)),
        CHECKPOINT_STORE_DIR_VARIABLE: str(checkpoint_store),
        CHECKPOINT_SIGNING_KEY_FILE_VARIABLE: str(checkpoint_signing_key_file),
    }


@pytest.fixture
def engines() -> list[str]:
    """URLs for which the CLI asked for an engine."""
    return []


@pytest.fixture
def run_cli(environ: dict[str, str], engines: list[str]) -> Callable[..., Outcome]:
    def run(
        *argv: str,
        stdin: str | None = "",
        tty: bool = False,
        prompt: Callable[[str], str] | None = None,
        environ_override: Mapping[str, str] | None = None,
    ) -> Outcome:
        stdout, stderr = io.StringIO(), io.StringIO()

        def engine_factory(url: str) -> Engine:
            engines.append(url)
            # In-memory SQLite has no has_table_privilege, so any database step fails there.
            return create_engine("sqlite://")

        def no_prompt(_text: str) -> str:
            raise AssertionError("prompted")

        code = cli.run(
            list(argv),
            environ=environ if environ_override is None else environ_override,
            stdin=None if stdin is None else FakeStdin(stdin, tty=tty),
            stdout=stdout,
            stderr=stderr,
            prompt=prompt or no_prompt,
            engine_factory=engine_factory,
        )
        return Outcome(code, stdout.getvalue(), stderr.getvalue())

    return run


def _admin(fake_keys: Mapping[str, str]) -> str:
    return fake_keys["administrator"] + "\n"


# Credential input (CP2).


def test_piped_key_is_one_line_without_its_line_break() -> None:
    assert cli.read_api_key(FakeStdin("key-1\nignored\n")) == "key-1"
    assert cli.read_api_key(FakeStdin("key-1\r\n")) == "key-1"
    assert cli.read_api_key(FakeStdin("key-1")) == "key-1"


def test_only_the_trailing_line_break_is_removed() -> None:
    assert cli.read_api_key(FakeStdin(" key-1 \n")) == " key-1 "
    assert cli.read_api_key(FakeStdin("key-1\r")) == "key-1\r"


@pytest.mark.parametrize("text", ["", "\n", "\r\n"], ids=["eof", "blank", "blank-crlf"])
def test_missing_key_is_empty(text: str) -> None:
    assert cli.read_api_key(FakeStdin(text)) == ""


def test_no_stdin_is_empty() -> None:
    assert cli.read_api_key(None) == ""


def test_terminal_uses_the_no_echo_prompt() -> None:
    prompts: list[str] = []

    def prompt(text: str) -> str:
        prompts.append(text)
        return "key-1"

    assert cli.read_api_key(FakeStdin("from-stdin\n", tty=True), prompt) == "key-1"
    assert prompts == ["Operator API key: "]


@pytest.mark.parametrize(
    "error", [EOFError(), OSError(), UnicodeDecodeError("utf-8", b"", 0, 1, "x")]
)
def test_unreadable_input_is_empty(error: Exception) -> None:
    def prompt(_text: str) -> str:
        raise error

    assert cli.read_api_key(FakeStdin(tty=True), prompt) == ""


def test_overlong_input_is_empty() -> None:
    limit = cli.MAX_API_KEY_LENGTH
    assert cli.read_api_key(FakeStdin("k" * limit + "\n")) == "k" * limit
    assert cli.read_api_key(FakeStdin("k" * (limit + 1) + "\n")) == ""
    assert cli.read_api_key(FakeStdin("k" * (limit + 5))) == ""


def test_key_is_never_read_from_arguments_or_the_environment(
    run_cli: Callable[..., Outcome], environ: dict[str, str], fake_keys: Mapping[str, str]
) -> None:
    key = fake_keys["administrator"]
    assert run_cli("create", key).code == cli.EXIT_USAGE
    assert run_cli("create", "--api-key", key).code == cli.EXIT_USAGE
    with_env = {**environ, "AUDIT_LOG_API_KEY": key, "AUDIT_LOG_OPERATOR_API_KEY": key}
    assert run_cli("create", stdin="", environ_override=with_env).code == cli.EXIT_AUTHENTICATION


# Arguments and configuration.


@pytest.mark.parametrize("argv", [(), ("delete",), ("create", "extra")], ids=str)
def test_usage_errors_exit_2(run_cli: Callable[..., Outcome], argv: tuple[str, ...]) -> None:
    outcome = run_cli(*argv)
    assert outcome.code == cli.EXIT_USAGE
    assert outcome.stderr.startswith("usage error: ")
    assert outcome.stdout == ""


def test_configuration_error_exits_2(
    run_cli: Callable[..., Outcome], environ: dict[str, str], engines: list[str]
) -> None:
    outcome = run_cli(
        "create",
        environ_override={
            k: v for k, v in environ.items() if k != CHECKPOINT_DATABASE_URL_VARIABLE
        },
    )
    assert outcome.code == cli.EXIT_USAGE
    assert outcome.stderr == (
        f"configuration error: {CHECKPOINT_DATABASE_URL_VARIABLE} must be set\n"
    )
    assert engines == []


def test_main_runs_with_the_process_arguments(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["audit-log-checkpoint"])
    assert cli.main() == cli.EXIT_USAGE
    assert capsys.readouterr().err.startswith("usage error: ")


# Authentication and authorization come first (CP3).


@pytest.mark.parametrize(
    "stdin", ["", "unknown-test-key\n", "Bearer test-only-administrator-key\n"]
)
def test_authentication_failure_exits_3_before_the_key_or_database(
    run_cli: Callable[..., Outcome],
    checkpoint_signing_key_file: Path,
    engines: list[str],
    stdin: str,
) -> None:
    checkpoint_signing_key_file.write_bytes(b"not a key")  # would be exit 2 if it were read
    outcome = run_cli("create", stdin=stdin)

    assert (outcome.code, outcome.stdout, outcome.stderr) == (
        cli.EXIT_AUTHENTICATION,
        "",
        "Authentication failed.\n",
    )
    assert engines == []


@pytest.mark.parametrize("role", ["writer", "auditor", "regulator"])
def test_other_roles_are_not_authorized_before_the_key_or_database(
    run_cli: Callable[..., Outcome],
    fake_keys: Mapping[str, str],
    checkpoint_signing_key_file: Path,
    engines: list[str],
    role: str,
) -> None:
    checkpoint_signing_key_file.write_bytes(b"not a key")
    outcome = run_cli("create", stdin=fake_keys[role] + "\n")

    assert (outcome.code, outcome.stdout, outcome.stderr) == (
        cli.EXIT_AUTHORIZATION,
        "",
        "Not authorized to create checkpoints.\n",
    )
    assert engines == []


def test_terminal_operator_is_prompted(
    run_cli: Callable[..., Outcome], fake_keys: Mapping[str, str], engines: list[str]
) -> None:
    def prompt(_text: str) -> str:
        return fake_keys["writer"]

    outcome = run_cli("create", tty=True, prompt=prompt)
    assert outcome.code == cli.EXIT_AUTHORIZATION
    assert engines == []


@pytest.mark.parametrize("problem", ["invalid", "public-key", "unreadable"])
def test_invalid_signing_key_exits_2_after_authorization(
    run_cli: Callable[..., Outcome],
    fake_keys: Mapping[str, str],
    checkpoint_signing_key_file: Path,
    checkpoint_public_key_file: Path,
    engines: list[str],
    monkeypatch: pytest.MonkeyPatch,
    problem: str,
) -> None:
    if problem == "invalid":
        checkpoint_signing_key_file.write_bytes(b"not a key")
    elif problem == "public-key":
        checkpoint_signing_key_file.write_bytes(checkpoint_public_key_file.read_bytes())
    else:
        real_read_bytes = Path.read_bytes

        def read_bytes(path: Path) -> bytes:
            if path == checkpoint_signing_key_file:
                raise PermissionError("denied")
            return real_read_bytes(path)

        monkeypatch.setattr(Path, "read_bytes", read_bytes)
    outcome = run_cli("create", stdin=_admin(fake_keys))

    assert outcome.code == cli.EXIT_USAGE
    assert engines == []
    assert outcome.stderr == (
        f"configuration error: {CHECKPOINT_SIGNING_KEY_FILE_VARIABLE} must name a readable, "
        "unencrypted Ed25519 private key in PKCS#8 PEM form\n"
    )


def test_database_failure_exits_5(
    run_cli: Callable[..., Outcome], fake_keys: Mapping[str, str], engines: list[str]
) -> None:
    outcome = run_cli("create", stdin=_admin(fake_keys))

    assert outcome.code == cli.EXIT_UNAVAILABLE
    assert outcome.stderr == "The database is unavailable (OperationalError).\n"
    assert engines == [DATABASE_URL]


# Outcomes of the database and store steps.


@pytest.fixture
def stub_steps(monkeypatch: pytest.MonkeyPatch) -> Callable[[Callable[..., Any]], list[Any]]:
    """Replace the privilege check and `create_checkpoint`; record the create arguments."""

    def install(create: Callable[..., Any]) -> list[Any]:
        calls: list[Any] = []

        def fake_create(*args: Any) -> Any:
            calls.append(args)
            return create(*args)

        def check_role(_engine: Engine) -> None:
            return None

        monkeypatch.setattr(cli, "check_checkpoint_role", check_role)
        monkeypatch.setattr(cli, "create_checkpoint", fake_create)
        return calls

    return install


def _raise(error: BaseException) -> Callable[..., Any]:
    def raiser(*_args: Any) -> Any:
        raise error

    return raiser


@pytest.mark.parametrize(
    ("error", "code", "message"),
    [
        (
            ChainNotIntactError(
                Violation(type=ViolationType.CHAIN_TRUNCATED, sequence=4, record_id=None)
            ),
            cli.EXIT_REFUSED,
            "Refused: the audit chain is not intact. CHAIN_TRUNCATED at sequence 4: Records up to "
            "the latest checkpoint's sequence are missing from the end of the chain.",
        ),
        (EmptyChainError(), cli.EXIT_REFUSED, "Refused: the audit chain is empty."),
        (
            CheckpointStoreError(
                "a checkpoint artifact is invalid (MALFORMED)", "checkpoint-x.json"
            ),
            cli.EXIT_UNAVAILABLE,
            "The checkpoint store is invalid or unreadable: a checkpoint artifact is invalid "
            "(MALFORMED) (checkpoint-x.json)",
        ),
        (
            CheckpointStoreError("the checkpoint store cannot be read"),
            cli.EXIT_UNAVAILABLE,
            "The checkpoint store is invalid or unreadable: the checkpoint store cannot be read",
        ),
        (
            CheckpointExistsError("checkpoint-00000000000000000004.json"),
            cli.EXIT_UNAVAILABLE,
            "A checkpoint already exists: checkpoint-00000000000000000004.json",
        ),
        (
            PermissionError("denied: C:/secret/path"),
            cli.EXIT_UNAVAILABLE,
            "The checkpoint could not be written to the store (PermissionError).",
        ),
        (
            OperationalError("SELECT", {}, Exception("password=test-only")),
            cli.EXIT_UNAVAILABLE,
            "The database is unavailable (OperationalError).",
        ),
        (
            PoolTimeoutError("pool"),
            cli.EXIT_UNAVAILABLE,
            "The database is unavailable (TimeoutError).",
        ),
        (
            ConfigurationError("AUDIT_LOG_CHECKPOINT_DATABASE_URL must use a read-only member"),
            cli.EXIT_USAGE,
            "configuration error: AUDIT_LOG_CHECKPOINT_DATABASE_URL must use a read-only member",
        ),
    ],
    ids=[
        "not-intact",
        "empty",
        "invalid-store",
        "unreadable-store",
        "exists",
        "write-failed",
        "database",
        "pool",
        "privileges",
    ],
)
def test_step_failures_map_to_exit_codes(
    run_cli: Callable[..., Outcome],
    fake_keys: Mapping[str, str],
    stub_steps: Callable[[Callable[..., Any]], list[Any]],
    error: BaseException,
    code: int,
    message: str,
) -> None:
    stub_steps(_raise(error))
    outcome = run_cli("create", stdin=_admin(fake_keys))
    assert (outcome.code, outcome.stdout, outcome.stderr) == (code, "", message + "\n")


@pytest.mark.parametrize("outcome_type", list(CheckpointOutcome))
def test_success_prints_one_json_line(
    run_cli: Callable[..., Outcome],
    fake_keys: Mapping[str, str],
    stub_steps: Callable[[Callable[..., Any]], list[Any]],
    checkpoint_store: Path,
    checkpoint_key: Ed25519PrivateKey,
    outcome_type: CheckpointOutcome,
) -> None:
    checkpoint = Checkpoint(
        sequence=4,
        record_hash="ab" * 32,
        created_at="2026-09-28T10:15:30.123456Z",
        created_by="ops.admin",
        key_id=key_id(checkpoint_key.public_key()),
    )
    calls = stub_steps(
        lambda *_args: CheckpointResult(
            outcome_type, checkpoint, "checkpoint-00000000000000000004.json"
        )
    )

    outcome = run_cli("create", stdin=_admin(fake_keys))

    assert outcome.code == cli.EXIT_OK
    assert json.loads(outcome.stdout) == {
        "outcome": outcome_type.value,
        "sequence": 4,
        "recordHash": "ab" * 32,
        "keyId": key_id(checkpoint_key.public_key()),
        "file": "checkpoint-00000000000000000004.json",
    }
    assert outcome.stdout.count("\n") == 1
    assert outcome.stderr == (
        f"checkpoint outcome={outcome_type.value} operator=ops.admin sequence=4 "
        f"keyId={key_id(checkpoint_key.public_key())}\n"
    )
    [(_, store_dir, private_key, operator)] = calls
    assert (store_dir, operator) == (checkpoint_store, "ops.admin")
    assert key_id(private_key.public_key()) == key_id(checkpoint_key.public_key())


def test_outputs_never_contain_the_api_key_or_key_material(
    run_cli: Callable[..., Outcome],
    fake_keys: Mapping[str, str],
    checkpoint_signing_key_file: Path,
) -> None:
    secrets = [fake_keys[name] for name in fake_keys]
    private_pem = checkpoint_signing_key_file.read_text(encoding="ascii")
    outputs: list[str] = []
    for stdin in [_admin(fake_keys), fake_keys["writer"] + "\n", "unknown-test-key\n"]:
        outcome = run_cli("create", stdin=stdin)
        outputs += [outcome.stdout, outcome.stderr]
    text = "".join(outputs)
    assert not any(secret in text for secret in secrets)
    assert "unknown-test-key" not in text
    assert "PRIVATE KEY" not in text and private_pem not in text
    assert "test-only-password" not in text


def test_database_connections_time_out(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    def recording_create_engine(url: str, **kwargs: Any) -> Engine:
        calls.append((url, kwargs))
        return create_engine("sqlite://")

    monkeypatch.setattr(cli, "create_engine", recording_create_engine)

    cli._create_engine(DATABASE_URL)  # pyright: ignore[reportPrivateUsage]

    assert calls == [(DATABASE_URL, {"connect_args": {"connect_timeout": 5}})]
