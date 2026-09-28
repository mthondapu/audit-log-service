"""Concurrency tests: the PostgreSQL advisory lock serializes appends across connections."""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any

import pytest
from sqlalchemy import Engine, func, select, text
from sqlalchemy.exc import OperationalError

from audit_log_service.integrity.hashing import AuditRecord
from audit_log_service.integrity.timestamps import parse_timestamp
from audit_log_service.integrity.verification import ChainEntry, verify_chain
from audit_log_service.persistence import audit_log
from audit_log_service.persistence.audit_log import APPEND_LOCK_KEY, append_event

WRITERS = 8
APPENDS_PER_WRITER = 6


def test_concurrent_writers_produce_one_contiguous_unforked_chain(
    app_engine: Engine, new_event: Any, load: Any
) -> None:
    start = threading.Barrier(WRITERS)

    def writer(index: int) -> list[AuditRecord]:
        start.wait()
        records: list[AuditRecord] = []
        for _ in range(APPENDS_PER_WRITER):
            with app_engine.begin() as connection:
                records.append(append_event(connection, new_event(actor_id=f"writer-{index}")))
        return records

    with ThreadPoolExecutor(max_workers=WRITERS) as pool:
        results = list(pool.map(writer, range(WRITERS)))

    total = WRITERS * APPENDS_PER_WRITER
    appended = [record for records in results for record in records]
    entries: list[ChainEntry] = load()
    assert sorted(record.sequence for record in appended) == list(range(1, total + 1))
    assert len({record.previous_hash for record in appended}) == total
    assert [entry.record.sequence for entry in entries] == list(range(1, total + 1))
    result = verify_chain(entries)
    assert result.intact
    assert result.records_checked == total


def test_a_waiting_writer_links_to_the_record_committed_before_it(
    app_engine: Engine, new_event: Any
) -> None:
    first_appended = threading.Event()
    outcome: dict[str, Any] = {}

    def second_writer() -> None:
        first_appended.wait()
        with app_engine.begin() as connection:
            outcome["started"] = connection.execute(select(func.now())).scalar_one()
            outcome["record"] = append_event(connection, new_event(actor_id="second"))

    thread = threading.Thread(target=second_writer)
    thread.start()
    with app_engine.begin() as connection:
        first = append_event(connection, new_event(actor_id="first"))
        first_appended.set()
        thread.join(timeout=0.5)
        assert thread.is_alive(), "the second writer must wait for the append lock"
        released_at: datetime = connection.execute(select(func.clock_timestamp())).scalar_one()
    thread.join(timeout=10)

    second: AuditRecord = outcome["record"]
    assert second.sequence == first.sequence + 1
    assert second.previous_hash == first.record_hash
    # recordedAt is read after the lock is acquired, not at the start of the transaction.
    assert outcome["started"] < released_at <= parse_timestamp(second.content.recorded_at)


def test_lock_wait_is_bounded_by_the_lock_timeout(
    app_engine: Engine, owner_engine: Engine, new_event: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(audit_log, "_SET_LOCK_TIMEOUT", text("SET LOCAL lock_timeout = '200ms'"))

    with owner_engine.begin() as holder:
        holder.execute(select(func.pg_advisory_xact_lock(APPEND_LOCK_KEY)))
        with pytest.raises(OperationalError, match="lock timeout"), app_engine.begin() as conn:
            append_event(conn, new_event())

    with app_engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM audit_records")).scalar_one() == 0
