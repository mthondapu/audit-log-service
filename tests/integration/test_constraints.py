"""Database constraints that protect the chain even if application logic were wrong."""

import dataclasses
import uuid
from collections.abc import Callable
from typing import Any

import pytest
from sqlalchemy import Engine
from sqlalchemy.exc import IntegrityError

from audit_log_service.integrity.hashing import AuditRecord

Append = Callable[..., AuditRecord]


def _copy(record: AuditRecord, **changes: Any) -> AuditRecord:
    content = dataclasses.replace(record.content, id=str(uuid.uuid4()))
    return dataclasses.replace(record, content=content, **changes)


def test_duplicate_sequence_is_rejected(
    append: Append, app_engine: Engine, insert_sealed: Any
) -> None:
    first = append()
    duplicate = _copy(first, previous_hash="a" * 64)

    with (
        pytest.raises(IntegrityError, match="uq_audit_records_sequence"),
        app_engine.begin() as connection,
    ):
        insert_sealed(connection, duplicate)


def test_duplicate_previous_hash_is_rejected(
    append: Append, app_engine: Engine, insert_sealed: Any
) -> None:
    first = append()
    fork = _copy(first, sequence=2)

    with (
        pytest.raises(IntegrityError, match="uq_audit_records_previous_hash"),
        app_engine.begin() as connection,
    ):
        insert_sealed(connection, fork)


@pytest.mark.parametrize("sequence", [0, -1])
def test_sequence_must_be_positive(
    append: Append, app_engine: Engine, insert_sealed: Any, sequence: int
) -> None:
    invalid = _copy(append(), sequence=sequence, previous_hash="b" * 64)

    with (
        pytest.raises(IntegrityError, match="ck_audit_records_sequence_positive"),
        app_engine.begin() as connection,
    ):
        insert_sealed(connection, invalid)
