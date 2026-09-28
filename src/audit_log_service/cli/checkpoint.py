"""`audit-log-checkpoint create`: sign a checkpoint of the verified chain head (requirements FR-4).

Phase 10 decisions CP1 to CP4, CP11, and CP12. The command takes no options; settings come from the
environment (`load_checkpoint_cli_settings`). In order, it:

1. loads and validates its settings;
2. reads the operator's API key from stdin: with `getpass` (no echo) on a terminal, otherwise one
   line. The key is never taken from arguments or the environment;
3. authenticates the key and requires `checkpoint:create`;
4. only then reads the signing key;
5. checks that its database login cannot insert, update, delete, or truncate audit data; and
6. validates the store, verifies the chain against the latest checkpoint, and creates the next
   checkpoint (`create_checkpoint`).

The result is one JSON line on stdout. Errors are fixed messages on stderr, never the API key,
key material, or payload data. Exit codes: 0 created or already current, 1 refused because the
chain is not intact or is empty, 2 usage or configuration error, 3 authentication failed, 4 not
authorized, 5 database or checkpoint store unavailable.

The capability check attributes the checkpoint to an operator and keeps the tool from other API
principals. It is not a cryptographic control: whoever can read the signing key can sign.
"""

import argparse
import getpass
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import NoReturn, TextIO

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from audit_log_service.application.checkpoints import (
    ChainNotIntactError,
    EmptyChainError,
    create_checkpoint,
)
from audit_log_service.application.verification import VIOLATION_MESSAGES
from audit_log_service.config.errors import ConfigurationError
from audit_log_service.config.settings import (
    CHECKPOINT_DATABASE_URL_VARIABLE,
    CHECKPOINT_SIGNING_KEY_FILE_VARIABLE,
    load_checkpoint_cli_settings,
)
from audit_log_service.integrity.checkpoints import KeyFormatError, load_private_key
from audit_log_service.persistence.checkpoint_store import CheckpointStoreError
from audit_log_service.persistence.checkpoint_writer import CheckpointExistsError
from audit_log_service.security.authentication import AuthenticationError, authenticate_api_key
from audit_log_service.security.authorization import AuthorizationError, require_capability
from audit_log_service.security.capabilities import Capability

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
EXIT_AUTHENTICATION = 3
EXIT_AUTHORIZATION = 4
EXIT_UNAVAILABLE = 5

CONNECT_TIMEOUT_SECONDS = 5
# Longer input cannot be a configured key's preimage in practice and is rejected unread.
MAX_API_KEY_LENGTH = 4096
_PROMPT = "Operator API key: "
_TABLES = ("audit_records", "audit_payload_values")
_FORBIDDEN_PRIVILEGES = ("INSERT", "UPDATE", "DELETE", "TRUNCATE")

Prompt = Callable[[str], str]
EngineFactory = Callable[[str], Engine]


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise _UsageError(message)


def main() -> int:
    """Console entry point."""
    return run(sys.argv[1:], stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)


def run(
    argv: Sequence[str],
    *,
    environ: Mapping[str, str] = os.environ,
    stdin: TextIO | None = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    prompt: Prompt = getpass.getpass,
    engine_factory: EngineFactory | None = None,
) -> int:
    """Run the command and return its exit code."""
    parser = _Parser(prog="audit-log-checkpoint", description="Create signed checkpoints.")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    commands.add_parser("create", help="verify the chain and checkpoint its head")
    try:
        parser.parse_args(argv)
    except _UsageError as error:
        return _fail(stderr, EXIT_USAGE, f"usage error: {error}")

    try:
        settings = load_checkpoint_cli_settings(environ)
    except ConfigurationError as error:
        return _fail(stderr, EXIT_USAGE, f"configuration error: {error}")

    try:
        principal = authenticate_api_key(read_api_key(stdin, prompt), settings.api_keys)
    except AuthenticationError:
        return _fail(stderr, EXIT_AUTHENTICATION, "Authentication failed.")
    try:
        require_capability(principal, Capability.CHECKPOINT_CREATE)
    except AuthorizationError:
        return _fail(stderr, EXIT_AUTHORIZATION, "Not authorized to create checkpoints.")

    try:
        private_key = load_private_key(settings.signing_key_file.read_bytes())
    except (OSError, KeyFormatError):
        return _fail(
            stderr,
            EXIT_USAGE,
            f"configuration error: {CHECKPOINT_SIGNING_KEY_FILE_VARIABLE} must name a readable, "
            "unencrypted Ed25519 private key in PKCS#8 PEM form",
        )

    engine = (engine_factory or _create_engine)(settings.database_url)
    try:
        check_checkpoint_role(engine)
        result = create_checkpoint(engine, settings.store_dir, private_key, principal.id)
    except ConfigurationError as error:
        return _fail(stderr, EXIT_USAGE, f"configuration error: {error}")
    except ChainNotIntactError as error:
        violation = error.violation
        return _fail(
            stderr,
            EXIT_REFUSED,
            f"Refused: the audit chain is not intact. {violation.type.value} at sequence "
            f"{violation.sequence}: {VIOLATION_MESSAGES[violation.type]}",
        )
    except EmptyChainError:
        return _fail(stderr, EXIT_REFUSED, "Refused: the audit chain is empty.")
    except CheckpointStoreError as error:
        where = "" if error.file_name is None else f" ({error.file_name})"
        return _fail(
            stderr,
            EXIT_UNAVAILABLE,
            f"The checkpoint store is invalid or unreadable: {error}{where}",
        )
    except CheckpointExistsError as error:
        return _fail(stderr, EXIT_UNAVAILABLE, f"A checkpoint already exists: {error}")
    except OSError as error:
        return _fail(
            stderr,
            EXIT_UNAVAILABLE,
            f"The checkpoint could not be written to the store ({type(error).__name__}).",
        )
    except (DBAPIError, PoolTimeoutError) as error:
        return _fail(
            stderr, EXIT_UNAVAILABLE, f"The database is unavailable ({type(error).__name__})."
        )
    finally:
        engine.dispose()

    checkpoint = result.checkpoint
    output = {
        "outcome": result.outcome.value,
        "sequence": checkpoint.sequence,
        "recordHash": checkpoint.record_hash,
        "keyId": checkpoint.key_id,
        "file": result.file_name,
    }
    stdout.write(json.dumps(output) + "\n")
    # The operational record of the operator's action (CP12); the chain is not written.
    stderr.write(
        f"checkpoint outcome={result.outcome.value} operator={principal.id} "
        f"sequence={checkpoint.sequence} keyId={checkpoint.key_id}\n"
    )
    return EXIT_OK


def read_api_key(stdin: TextIO | None, prompt: Prompt = getpass.getpass) -> str:
    """Read the operator's API key: without echo on a terminal, otherwise one line of stdin.

    Only a trailing line break is removed. Missing or unreadable input yields an empty key, which
    authentication rejects.
    """
    if stdin is None:
        return ""
    try:
        line = prompt(_PROMPT) if stdin.isatty() else stdin.readline(MAX_API_KEY_LENGTH + 2)
    except (OSError, UnicodeDecodeError, EOFError):
        return ""
    if line.endswith("\r\n"):
        line = line[:-2]
    elif line.endswith("\n"):
        line = line[:-1]
    return "" if len(line) > MAX_API_KEY_LENGTH else line


def check_checkpoint_role(engine: Engine) -> None:
    """Refuse a database login that can insert, update, delete, or truncate audit data (CP4)."""
    with engine.connect() as connection:
        privileged = sorted(
            f"{privilege} on {table}"
            for table in _TABLES
            for privilege in _FORBIDDEN_PRIVILEGES
            if connection.execute(
                text("SELECT has_table_privilege(current_user, :table, :privilege)"),
                {"table": table, "privilege": privilege},
            ).scalar_one()
        )
    if privileged:
        raise ConfigurationError(
            f"{CHECKPOINT_DATABASE_URL_VARIABLE} must use a read-only member of "
            f"audit_log_checkpoint; the configured login has {', '.join(privileged)}"
        )


def _create_engine(url: str) -> Engine:
    return create_engine(url, connect_args={"connect_timeout": CONNECT_TIMEOUT_SECONDS})


def _fail(stderr: TextIO, code: int, message: str) -> int:
    stderr.write(message + "\n")
    return code
