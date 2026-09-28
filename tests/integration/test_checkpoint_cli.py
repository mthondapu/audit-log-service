"""`audit-log-checkpoint create` against PostgreSQL (FR-4, Phase 10 decisions CP1 to CP16).

The CLI connects through `audit_log_checkpoint` (SET ROLE, see conftest). Tampering is done with
the owner engine, outside the application path; no trigger is disabled, because none exists.
"""

import io
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from sqlalchemy import Engine, text
from sqlalchemy.exc import ProgrammingError

from audit_log_service.cli import checkpoint as cli
from audit_log_service.config.errors import ConfigurationError
from audit_log_service.config.settings import (
    API_KEYS_FILE_VARIABLE,
    CHECKPOINT_DATABASE_URL_VARIABLE,
    CHECKPOINT_SIGNING_KEY_FILE_VARIABLE,
    CHECKPOINT_STORE_DIR_VARIABLE,
)
from audit_log_service.integrity.checkpoints import key_id, parse_artifact, verify_checkpoint
from audit_log_service.integrity.hashing import AuditRecord
from audit_log_service.integrity.verification import ChainEntry
from audit_log_service.persistence.checkpoint_store import checkpoint_file_name
from audit_log_service.persistence.schema import CHECKPOINT_ROLE

Append = Callable[..., AuditRecord]
PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


class Outcome:
    def __init__(self, code: int, stdout: str, stderr: str) -> None:
        self.code, self.stdout, self.stderr = code, stdout, stderr

    def json(self) -> dict[str, Any]:
        result: dict[str, Any] = json.loads(self.stdout)
        return result


@pytest.fixture
def environ(
    write_file: Callable[[str, str], Path],
    valid_api_key_toml: str,
    checkpoint_store: Path,
    checkpoint_signing_key_file: Path,
) -> dict[str, str]:
    return {
        CHECKPOINT_DATABASE_URL_VARIABLE: "unused: the tests supply the engine",
        API_KEYS_FILE_VARIABLE: str(write_file("api-keys.toml", valid_api_key_toml)),
        CHECKPOINT_STORE_DIR_VARIABLE: str(checkpoint_store),
        CHECKPOINT_SIGNING_KEY_FILE_VARIABLE: str(checkpoint_signing_key_file),
    }


@pytest.fixture
def run_cli(
    environ: dict[str, str], checkpoint_engine: Engine, fake_keys: Mapping[str, str]
) -> Callable[..., Outcome]:
    def run(key: str = "administrator", engine: Engine | None = None) -> Outcome:
        stdout, stderr = io.StringIO(), io.StringIO()
        code = cli.run(
            ["create"],
            environ=environ,
            stdin=io.StringIO(fake_keys[key] + "\n"),
            stdout=stdout,
            stderr=stderr,
            engine_factory=lambda _url: engine or checkpoint_engine,
        )
        return Outcome(code, stdout.getvalue(), stderr.getvalue())

    return run


def _files(store: Path) -> list[str]:
    return sorted(path.name for path in store.iterdir())


def _truncate_after(owner_engine: Engine, sequence: int) -> None:
    with owner_engine.begin() as connection:
        connection.execute(
            text(
                "DELETE FROM audit_payload_values WHERE record_id IN "
                "(SELECT id FROM audit_records WHERE sequence > :sequence)"
            ),
            {"sequence": sequence},
        )
        connection.execute(
            text("DELETE FROM audit_records WHERE sequence > :sequence"), {"sequence": sequence}
        )


# The read-only database role (CP4, migration 0002).


def _granted(engine: Engine, table: str) -> set[str]:
    with engine.connect() as connection:
        return {
            privilege
            for privilege in PRIVILEGES
            if connection.execute(
                text("SELECT has_table_privilege(:role, :table, :privilege)"),
                {"role": CHECKPOINT_ROLE, "table": table, "privilege": privilege},
            ).scalar_one()
        }


def test_checkpoint_role_has_select_only(owner_engine: Engine) -> None:
    assert _granted(owner_engine, "audit_records") == {"SELECT"}
    assert _granted(owner_engine, "audit_payload_values") == {"SELECT"}
    with owner_engine.connect() as connection:
        can_login = connection.execute(
            text("SELECT rolcanlogin FROM pg_roles WHERE rolname = :role"),
            {"role": CHECKPOINT_ROLE},
        ).scalar_one()
    assert can_login is False


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO audit_payload_values VALUES (gen_random_uuid(), '/x', '1', 's')",
        "UPDATE audit_records SET actor_id = 'forged'",
        "DELETE FROM audit_records",
        "DELETE FROM audit_payload_values",
        "TRUNCATE audit_records",
        "SELECT * FROM alembic_version",
    ],
    ids=["insert", "update", "delete-records", "delete-values", "truncate", "migration-state"],
)
def test_checkpoint_role_is_refused_writes(
    append: Append, checkpoint_engine: Engine, statement: str
) -> None:
    append()
    with (
        pytest.raises(ProgrammingError, match="permission denied"),
        checkpoint_engine.begin() as connection,
    ):
        connection.execute(text(statement))


def test_privilege_check_accepts_the_checkpoint_role(checkpoint_engine: Engine) -> None:
    cli.check_checkpoint_role(checkpoint_engine)


def test_privilege_check_refuses_the_application_role(app_engine: Engine) -> None:
    with pytest.raises(ConfigurationError) as caught:
        cli.check_checkpoint_role(app_engine)
    assert str(caught.value) == (
        f"{CHECKPOINT_DATABASE_URL_VARIABLE} must use a read-only member of audit_log_checkpoint; "
        "the configured login has DELETE on audit_payload_values, INSERT on audit_payload_values, "
        "INSERT on audit_records"
    )


def test_privilege_check_refuses_the_owner(owner_engine: Engine) -> None:
    with pytest.raises(ConfigurationError, match="TRUNCATE on audit_records"):
        cli.check_checkpoint_role(owner_engine)


def test_cli_refuses_a_privileged_login_before_verifying(
    run_cli: Callable[..., Outcome], append: Append, app_engine: Engine, checkpoint_store: Path
) -> None:
    append()
    outcome = run_cli(engine=app_engine)
    assert outcome.code == cli.EXIT_USAGE
    assert outcome.stderr.startswith(f"configuration error: {CHECKPOINT_DATABASE_URL_VARIABLE}")
    assert _files(checkpoint_store) == []


# End-to-end creation (CP11).


def test_creates_a_signed_checkpoint_of_the_verified_head(
    run_cli: Callable[..., Outcome],
    append: Append,
    load: Callable[[], list[ChainEntry]],
    checkpoint_store: Path,
    checkpoint_key: Ed25519PrivateKey,
) -> None:
    for _ in range(3):
        append()
    head = load()[-1].record

    outcome = run_cli()

    assert outcome.code == cli.EXIT_OK
    name = checkpoint_file_name(3)
    assert outcome.json() == {
        "outcome": "CHECKPOINT_CREATED",
        "sequence": 3,
        "recordHash": head.record_hash,
        "keyId": key_id(checkpoint_key.public_key()),
        "file": name,
    }
    assert _files(checkpoint_store) == [name]
    signed = parse_artifact((checkpoint_store / name).read_bytes())
    verify_checkpoint(signed, checkpoint_key.public_key())
    assert (signed.checkpoint.sequence, signed.checkpoint.record_hash) == (3, head.record_hash)
    assert signed.checkpoint.created_by == "ops.admin"
    assert outcome.stderr == (
        f"checkpoint outcome=CHECKPOINT_CREATED operator=ops.admin sequence=3 "
        f"keyId={key_id(checkpoint_key.public_key())}\n"
    )


def test_unchanged_head_is_current_and_writes_nothing(
    run_cli: Callable[..., Outcome], append: Append, checkpoint_store: Path
) -> None:
    append()
    assert run_cli().code == cli.EXIT_OK
    before = (checkpoint_store / checkpoint_file_name(1)).read_bytes()

    outcome = run_cli()

    assert outcome.code == cli.EXIT_OK
    assert outcome.json()["outcome"] == "CHECKPOINT_CURRENT"
    assert outcome.json()["file"] == checkpoint_file_name(1)
    assert _files(checkpoint_store) == [checkpoint_file_name(1)]
    assert (checkpoint_store / checkpoint_file_name(1)).read_bytes() == before


def test_new_records_get_a_new_checkpoint(
    run_cli: Callable[..., Outcome], append: Append, checkpoint_store: Path
) -> None:
    append()
    run_cli()
    append()
    append()

    outcome = run_cli()

    assert (outcome.code, outcome.json()["outcome"], outcome.json()["sequence"]) == (
        cli.EXIT_OK,
        "CHECKPOINT_CREATED",
        3,
    )
    assert _files(checkpoint_store) == [checkpoint_file_name(1), checkpoint_file_name(3)]


def test_creation_appends_nothing_to_the_chain(
    run_cli: Callable[..., Outcome], append: Append, load: Callable[[], list[ChainEntry]]
) -> None:
    append()
    run_cli()
    assert len(load()) == 1


# Refusals (CP11).


def test_empty_chain_is_refused(run_cli: Callable[..., Outcome], checkpoint_store: Path) -> None:
    outcome = run_cli()
    assert (outcome.code, outcome.stdout, outcome.stderr) == (
        cli.EXIT_REFUSED,
        "",
        "Refused: the audit chain is empty.\n",
    )
    assert _files(checkpoint_store) == []


def test_tampered_chain_is_refused(
    run_cli: Callable[..., Outcome],
    append: Append,
    owner_engine: Engine,
    checkpoint_store: Path,
) -> None:
    append()
    append()
    with owner_engine.begin() as connection:
        connection.execute(text("UPDATE audit_records SET actor_id = 'forged' WHERE sequence = 2"))

    outcome = run_cli()

    assert outcome.code == cli.EXIT_REFUSED
    assert outcome.stderr == (
        "Refused: the audit chain is not intact. CONTENT_HASH_MISMATCH at sequence 2: "
        "The record's content does not match its contentHash.\n"
    )
    assert _files(checkpoint_store) == []


def test_chain_truncated_below_the_latest_checkpoint_is_refused(
    run_cli: Callable[..., Outcome],
    append: Append,
    owner_engine: Engine,
    checkpoint_store: Path,
) -> None:
    for _ in range(3):
        append()
    run_cli()
    _truncate_after(owner_engine, 1)

    outcome = run_cli()

    assert outcome.code == cli.EXIT_REFUSED
    assert outcome.stderr.startswith(
        "Refused: the audit chain is not intact. CHAIN_TRUNCATED at sequence 2: "
    )
    assert _files(checkpoint_store) == [checkpoint_file_name(3)]


def test_rewrite_past_the_latest_checkpoint_is_refused(
    run_cli: Callable[..., Outcome],
    append: Append,
    owner_engine: Engine,
    checkpoint_store: Path,
) -> None:
    append()
    append()
    run_cli()
    _truncate_after(owner_engine, 1)
    append(actor_id="forger")  # a consistent forged record at the checkpointed sequence
    append(actor_id="forger")

    outcome = run_cli()

    assert outcome.code == cli.EXIT_REFUSED
    assert outcome.stderr.startswith(
        "Refused: the audit chain is not intact. ANCHOR_MISMATCH at sequence 2: "
    )
    assert _files(checkpoint_store) == [checkpoint_file_name(2)]


def test_invalid_store_is_refused_before_signing(
    run_cli: Callable[..., Outcome], append: Append, checkpoint_store: Path
) -> None:
    append()
    (checkpoint_store / checkpoint_file_name(1)).write_bytes(b"corrupt")

    outcome = run_cli()

    assert outcome.code == cli.EXIT_UNAVAILABLE
    assert outcome.stderr == (
        "The checkpoint store is invalid or unreadable: a checkpoint artifact is invalid "
        f"(MALFORMED) ({checkpoint_file_name(1)})\n"
    )


def test_checkpoint_signed_with_another_key_is_refused(
    run_cli: Callable[..., Outcome],
    append: Append,
    checkpoint_store: Path,
    checkpoint_signing_key_file: Path,
    checkpoint_key: Ed25519PrivateKey,
) -> None:
    # A second key cannot extend a store signed with the first: every artifact must verify.
    append()
    run_cli()
    append()
    other = Ed25519PrivateKey.generate()
    checkpoint_signing_key_file.write_bytes(
        other.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )

    outcome = run_cli()

    assert outcome.code == cli.EXIT_UNAVAILABLE
    assert "KEY_MISMATCH" in outcome.stderr
    assert _files(checkpoint_store) == [checkpoint_file_name(1)]
    assert key_id(checkpoint_key.public_key()) != key_id(other.public_key())


# Access control (CP3).


@pytest.mark.parametrize("role", ["writer", "auditor", "regulator"])
def test_other_roles_cannot_create_checkpoints(
    environ: dict[str, str],
    fake_keys: Mapping[str, str],
    append: Append,
    checkpoint_store: Path,
    role: str,
) -> None:
    append()
    requested: list[str] = []

    def engine_factory(url: str) -> Engine:
        requested.append(url)
        raise AssertionError("the database must not be reached")

    stdout, stderr = io.StringIO(), io.StringIO()
    code = cli.run(
        ["create"],
        environ=environ,
        stdin=io.StringIO(fake_keys[role] + "\n"),
        stdout=stdout,
        stderr=stderr,
        engine_factory=engine_factory,
    )

    assert (code, stdout.getvalue(), stderr.getvalue()) == (
        cli.EXIT_AUTHORIZATION,
        "",
        "Not authorized to create checkpoints.\n",
    )
    assert requested == []
    assert _files(checkpoint_store) == []


def test_rotated_administrator_key_can_create_checkpoints(
    run_cli: Callable[..., Outcome], append: Append
) -> None:
    append()
    assert run_cli(key="administrator-rotated").code == cli.EXIT_OK


# Secret hygiene.


def test_outputs_contain_no_credentials_key_material_or_payload_values(
    run_cli: Callable[..., Outcome],
    append: Append,
    fake_keys: Mapping[str, str],
    checkpoint_signing_key_file: Path,
    owner_engine: Engine,
    checkpoint_store: Path,
) -> None:
    append(payload={"card": "test-only-card-4111"})
    outputs = [run_cli(), run_cli(), run_cli(key="writer")]
    with owner_engine.begin() as connection:
        connection.execute(text("UPDATE audit_records SET actor_id = 'forged'"))
    append()
    outputs.append(run_cli())

    text_out = "".join(o.stdout + o.stderr for o in outputs)
    artifacts = b"".join(path.read_bytes() for path in checkpoint_store.iterdir())
    private_pem = checkpoint_signing_key_file.read_bytes()
    for secret in fake_keys.values():
        assert secret not in text_out
        assert secret.encode() not in artifacts
    assert "test-only-card-4111" not in text_out
    assert b"test-only-card-4111" not in artifacts
    assert "PRIVATE KEY" not in text_out
    assert private_pem not in artifacts
    assert "user-7" not in text_out and "acct-42" not in text_out
