"""DEMONSTRATION ONLY: tamper with the audit chain directly in PostgreSQL (Phase 12 decision P5).

This is the separate tamper tooling of ADR-0009 and requirements §9 Scenario A. It never uses the
application API. It connects with `AUDIT_LOG_TAMPER_DATABASE_URL`, switches to the demo-only
`audit_log_tamper` role (scripts/provision_tamper_role.sql) with SET ROLE, and refuses to run unless
that role is in effect and is not a superuser and holds no server-file or program role.

    uv run python scripts/tamper_demo.py modify --sequence 3     # change a record's actorId
    uv run python scripts/tamper_demo.py delete --sequence 3     # delete a record in the middle
    uv run python scripts/tamper_demo.py insert --sequence 3     # insert a forged record at 3
    uv run python scripts/tamper_demo.py reorder --sequence 3    # swap records 3 and 4
    uv run python scripts/tamper_demo.py truncate --after 5      # delete every record after 5
    uv run python scripts/tamper_demo.py rewrite --sequence 3    # rewrite 3 and reseal the rest

`rewrite` recomputes every later hash with the integrity library, so the chain is consistent on
its own; only a checkpoint detects it (FR-4).

Limitation: in the local demonstration the login is the owner, a superuser. SET ROLE is checked
against the login, so such a session could RESET ROLE or SET ROLE back to the superuser; the
database does not enforce the switch. This tool never does so, and `check_tamper_role` verifies the
effective (current) role, not the login. A dedicated non-superuser login that is a member of
`audit_log_tamper` only is the production recommendation (ADR-0009).

Each change is one transaction. Output names only sequences and record identifiers. Exit codes:
0 done, 2 usage or configuration error.
"""

import argparse
import dataclasses
import os
import secrets
import sys
import uuid
from collections.abc import Callable, Mapping, Sequence
from typing import Any, NoReturn, TextIO

from sqlalchemy import Connection, Engine, create_engine, event, insert, text

from audit_log_service.integrity.hashing import AuditRecord, seal_record
from audit_log_service.integrity.timestamps import parse_timestamp
from audit_log_service.persistence.audit_log import load_chain_entries
from audit_log_service.persistence.schema import audit_records

DATABASE_URL_VARIABLE = "AUDIT_LOG_TAMPER_DATABASE_URL"
TAMPER_ROLE = "audit_log_tamper"
EXIT_OK = 0
EXIT_USAGE = 2
_OFFSET = 1_000_000_000


class TamperError(Exception):
    """The requested change is not possible, or the tamper role is not safe to use."""


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise _UsageError(message)


def main() -> int:
    return run(sys.argv[1:], environ=os.environ, stdout=sys.stdout, stderr=sys.stderr)


def run(
    argv: Sequence[str],
    *,
    environ: Mapping[str, str],
    stdout: TextIO,
    stderr: TextIO,
    engine: Engine | None = None,
) -> int:
    parser = _Parser(prog="tamper_demo.py", description="Demonstration-only tampering.")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    for name in ("modify", "delete", "insert", "reorder", "rewrite"):
        commands.add_parser(name).add_argument("--sequence", type=int, required=True)
    commands.add_parser("truncate").add_argument("--after", type=int, required=True)
    try:
        arguments = parser.parse_args(argv)
    except _UsageError as error:
        stderr.write(f"usage error: {error}\n")
        return EXIT_USAGE

    if engine is None:
        url = environ.get(DATABASE_URL_VARIABLE, "").strip()
        if not url:
            stderr.write(f"configuration error: {DATABASE_URL_VARIABLE} must be set\n")
            return EXIT_USAGE
        engine = tamper_engine(url)
    change = _CHANGES[arguments.command]
    target: int = arguments.after if arguments.command == "truncate" else arguments.sequence
    try:
        with engine.begin() as connection:
            check_tamper_role(connection)
            stdout.write(change(connection, target) + "\n")
    except TamperError as error:
        stderr.write(f"refused: {error}\n")
        return EXIT_USAGE
    finally:
        engine.dispose()
    return EXIT_OK


def tamper_engine(url: str) -> Engine:
    """An engine whose every connection acts as `audit_log_tamper`."""
    engine = create_engine(url)

    @event.listens_for(engine, "connect")
    def use_tamper_role(dbapi_connection: Any, _record: Any) -> None:  # pyright: ignore[reportUnusedFunction]
        dbapi_connection.execute(f"SET ROLE {TAMPER_ROLE}")
        dbapi_connection.commit()

    return engine


def check_tamper_role(connection: Connection) -> None:
    """Refuse unless the session acts as a safe `audit_log_tamper` (ADR-0009)."""
    row = connection.execute(
        text(
            "SELECT current_user, r.rolsuper, "
            "pg_has_role(current_user, 'pg_write_server_files', 'MEMBER'), "
            "pg_has_role(current_user, 'pg_execute_server_program', 'MEMBER') "
            "FROM pg_roles r WHERE r.rolname = current_user"
        )
    ).one()
    if row[0] != TAMPER_ROLE or any(row[1:]):
        raise TamperError(
            f"the session must act as {TAMPER_ROLE}, which must not be a superuser or hold "
            "server-file or program roles"
        )


def modify(connection: Connection, sequence: int) -> str:
    _require(connection, sequence)
    connection.execute(
        text("UPDATE audit_records SET actor_id = 'tampered-actor' WHERE sequence = :s"),
        {"s": sequence},
    )
    return f"modified the actorId of record {sequence}"


def delete(connection: Connection, sequence: int) -> str:
    _require(connection, sequence)
    _delete_where(connection, "one", sequence)
    return f"deleted record {sequence}"


def insert_forged(connection: Connection, sequence: int) -> str:
    """Shift records at and after `sequence` up by one and insert a forged record there.

    `previousHash` is unique, so the forger cannot reuse the real predecessor's hash; the forged
    record is sealed consistently with a random `previousHash`.
    """
    template = _require(connection, sequence)
    _shift(connection, sequence)
    forged_content = dataclasses.replace(
        template.content, id=str(uuid.uuid4()), actor_id="forged-actor", payload={}
    )
    forged = seal_record(forged_content, sequence, secrets.token_hex(32))
    content = forged.content
    connection.execute(
        insert(audit_records).values(
            id=uuid.UUID(content.id),
            sequence=sequence,
            previous_hash=forged.previous_hash,
            content_hash=forged.content_hash,
            record_hash=forged.record_hash,
            event_type=content.event_type,
            actor_id=content.actor_id,
            resource_type=content.resource_type,
            resource_id=content.resource_id,
            timestamp=None if content.timestamp is None else parse_timestamp(content.timestamp),
            recorded_at=parse_timestamp(content.recorded_at),
            recorded_by=content.recorded_by,
            committed_payload=content.payload,
        )
    )
    return f"inserted forged record {content.id} at sequence {sequence}"


def reorder(connection: Connection, sequence: int) -> str:
    _require(connection, sequence)
    _require(connection, sequence + 1)
    connection.execute(
        text("UPDATE audit_records SET sequence = sequence + :o WHERE sequence = :s"),
        {"o": _OFFSET, "s": sequence},
    )
    connection.execute(
        text("UPDATE audit_records SET sequence = :s WHERE sequence = :n"),
        {"s": sequence, "n": sequence + 1},
    )
    connection.execute(
        text("UPDATE audit_records SET sequence = :n WHERE sequence = :t"),
        {"n": sequence + 1, "t": sequence + _OFFSET},
    )
    return f"swapped records {sequence} and {sequence + 1}"


def truncate(connection: Connection, after: int) -> str:
    removed = _delete_where(connection, "after", after)
    return f"deleted {removed} record(s) after sequence {after}"


def rewrite(connection: Connection, sequence: int) -> str:
    """Change record `sequence` and reseal it and every later record, consistently."""
    chain = [entry.record for entry in load_chain_entries(connection)]
    if not 1 <= sequence <= len(chain) or chain[sequence - 1].sequence != sequence:
        raise TamperError(f"no record has sequence {sequence}")
    previous = chain[sequence - 2].record_hash if sequence > 1 else chain[0].previous_hash
    for index in range(sequence - 1, len(chain)):
        record = chain[index]
        content = record.content
        if index == sequence - 1:
            content = dataclasses.replace(content, actor_id="rewritten-actor")
        resealed = seal_record(content, record.sequence, previous)
        connection.execute(
            text(
                "UPDATE audit_records SET actor_id = :actor, previous_hash = :previous, "
                "content_hash = :content, record_hash = :record WHERE id = :id"
            ),
            {
                "actor": content.actor_id,
                "previous": resealed.previous_hash,
                "content": resealed.content_hash,
                "record": resealed.record_hash,
                "id": uuid.UUID(content.id),
            },
        )
        previous = resealed.record_hash
    return f"rewrote record {sequence} and resealed {len(chain) - sequence + 1} record(s)"


def _require(connection: Connection, sequence: int) -> AuditRecord:
    for entry in load_chain_entries(connection):
        if entry.record.sequence == sequence:
            return entry.record
    raise TamperError(f"no record has sequence {sequence}")


def _shift(connection: Connection, sequence: int) -> None:
    connection.execute(
        text("UPDATE audit_records SET sequence = sequence + :o WHERE sequence >= :s"),
        {"o": _OFFSET, "s": sequence},
    )
    connection.execute(
        text("UPDATE audit_records SET sequence = sequence - :o + 1 WHERE sequence >= :o"),
        {"o": _OFFSET},
    )


# Fixed statements for the two deletions this tool makes: one record, or every record after one.
_DELETE_STATEMENTS = {
    "one": (
        text(
            "DELETE FROM audit_payload_values WHERE record_id IN "
            "(SELECT id FROM audit_records WHERE sequence = :s)"
        ),
        text("DELETE FROM audit_records WHERE sequence = :s"),
    ),
    "after": (
        text(
            "DELETE FROM audit_payload_values WHERE record_id IN "
            "(SELECT id FROM audit_records WHERE sequence > :s)"
        ),
        text("DELETE FROM audit_records WHERE sequence > :s"),
    ),
}


def _delete_where(connection: Connection, which: str, sequence: int) -> int:
    values, records = _DELETE_STATEMENTS[which]
    connection.execute(values, {"s": sequence})
    return connection.execute(records, {"s": sequence}).rowcount


_CHANGES: dict[str, Callable[[Connection, int], str]] = {
    "modify": modify,
    "delete": delete,
    "insert": insert_forged,
    "reorder": reorder,
    "truncate": truncate,
    "rewrite": rewrite,
}


if __name__ == "__main__":
    sys.exit(main())
