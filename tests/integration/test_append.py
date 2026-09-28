"""Integration tests for the serialized append path against PostgreSQL."""

import dataclasses
from collections.abc import Callable
from datetime import datetime
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import Connection, Engine, func, select, text
from sqlalchemy.exc import DataError

from audit_log_service.integrity.canonical import MAX_SAFE_INTEGER, canonicalize
from audit_log_service.integrity.commitments import values_open_commitments
from audit_log_service.integrity.errors import IntegrityInputError
from audit_log_service.integrity.hashing import (
    GENESIS_PREVIOUS_HASH,
    AuditRecord,
    EventContent,
    compute_content_hash,
    compute_record_hash,
    seal_record,
)
from audit_log_service.integrity.timestamps import parse_timestamp
from audit_log_service.integrity.verification import ChainEntry, verify_chain
from audit_log_service.persistence import audit_log
from audit_log_service.persistence.audit_log import (
    NewEvent,
    PersistenceUsageError,
    append_event,
    load_chain_entries,
)

Append = Callable[..., AuditRecord]
Load = Callable[[], list[ChainEntry]]


def _count_rows(engine: Engine) -> tuple[int, int]:
    with engine.connect() as connection:
        records = connection.execute(text("SELECT count(*) FROM audit_records")).scalar_one()
        values = connection.execute(text("SELECT count(*) FROM audit_payload_values")).scalar_one()
    return records, values


def _database_clock(connection: Connection) -> datetime:
    return connection.execute(select(func.clock_timestamp())).scalar_one()


def test_first_append_starts_the_chain_at_genesis(append: Append, load: Load) -> None:
    record = append()

    assert record.sequence == 1
    assert record.previous_hash == GENESIS_PREVIOUS_HASH == "0" * 64
    assert [entry.record for entry in load()] == [record]


def test_second_append_links_to_the_first(append: Append) -> None:
    first = append()
    second = append(actor_id="user-8")

    assert second.sequence == 2
    assert second.previous_hash == first.record_hash


def test_persisted_hashes_match_the_integrity_core(append: Append, load: Load) -> None:
    returned = [append(), append(timestamp="2026-09-28T15:00:00.123456Z"), append(payload={})]

    loaded = [entry.record for entry in load()]

    assert loaded == returned
    for record in loaded:
        assert compute_content_hash(record.content) == record.content_hash
        assert (
            compute_record_hash(record.sequence, record.previous_hash, record.content_hash)
            == record.record_hash
        )


def test_persisted_payload_values_open_their_commitments(append: Append, load: Load) -> None:
    payload: dict[str, Any] = {"amount": 12.5, "items": [{"sku": "A-1"}, None, []], "meta": {}}
    append(payload=payload)

    [entry] = load()

    assert values_open_commitments(entry.record.content.payload, entry.payload_values)
    assert {pointer: value.canonical_text for pointer, value in entry.payload_values.items()} == {
        "/amount": "12.5",
        "/items/0/sku": '"A-1"',
        "/items/1": "null",
    }
    assert entry.record.content.payload["meta"] == {}


def test_empty_payload_stores_no_values(append: Append, app_engine: Engine) -> None:
    append(payload={})
    assert _count_rows(app_engine) == (1, 0)


def test_loaded_chain_verifies(append: Append, load: Load) -> None:
    for index in range(5):
        append(actor_id=f"user-{index}", payload={"n": index})

    result = verify_chain(load())

    assert result.intact
    assert result.records_checked == 5
    assert result.head is not None
    assert result.head.sequence == 5


def test_multiple_appends_in_one_transaction(app_engine: Engine, new_event: Any) -> None:
    # Later operations reuse the append path inside their own transactions (ADR-0003).
    with app_engine.begin() as connection:
        first = append_event(connection, new_event())
        second = append_event(connection, new_event())

    assert (first.sequence, second.sequence) == (1, 2)
    assert second.previous_hash == first.record_hash


# --- recordedAt -------------------------------------------------------------------------------


def test_recorded_at_comes_from_the_database_clock(app_engine: Engine, new_event: Any) -> None:
    with app_engine.begin() as connection:
        before = _database_clock(connection)
        record = append_event(connection, new_event())
        after = _database_clock(connection)

    assert before <= parse_timestamp(record.content.recorded_at) <= after


def test_recorded_at_is_canonical_utc_whatever_the_session_time_zone(
    app_engine: Engine, new_event: Any
) -> None:
    with app_engine.begin() as connection:
        connection.execute(text("SET LOCAL TIME ZONE 'Asia/Kolkata'"))
        before = _database_clock(connection)
        record = append_event(connection, new_event())

    assert record.content.recorded_at.endswith("Z")
    assert parse_timestamp(record.content.recorded_at) >= before


def test_recorded_at_is_clamped_to_a_later_head(
    owner_engine: Engine, append: Append, load: Load, insert_sealed: Any, new_event: Any
) -> None:
    future = "2999-01-01T00:00:00.000000Z"
    head = seal_record(_content(future), 1, GENESIS_PREVIOUS_HASH)
    with owner_engine.begin() as connection:
        insert_sealed(connection, head)

    record = append()

    assert record.content.recorded_at == future
    assert verify_chain(load()).intact


def _content(recorded_at: str) -> EventContent:
    return EventContent(
        id="0f8fad5b-d9cb-469f-a165-70867728950e",
        event_type="CLIENT_ACCOUNT_VIEWED",
        actor_id="user-7",
        resource_type="CLIENT_ACCOUNT",
        resource_id="acct-42",
        timestamp=None,
        recorded_at=recorded_at,
        recorded_by="svc-writer",
        payload={},
    )


def test_recorded_at_never_moves_backwards(append: Append) -> None:
    records = [append() for _ in range(10)]
    times = [parse_timestamp(record.content.recorded_at) for record in records]
    assert times == sorted(times)


# --- Transactions and failures ----------------------------------------------------------------


def test_caller_rollback_leaves_nothing(app_engine: Engine, new_event: Any) -> None:
    with pytest.raises(RuntimeError, match="caller failure"), app_engine.begin() as connection:
        append_event(connection, new_event())
        raise RuntimeError("caller failure")

    assert _count_rows(app_engine) == (0, 0)


def test_failure_while_storing_payload_values_rolls_back_the_record(
    app_engine: Engine, new_event: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_args: Any) -> None:
        raise RuntimeError("value storage failed")

    monkeypatch.setattr(audit_log, "_insert_payload_values", fail)

    with pytest.raises(RuntimeError, match="value storage failed"), app_engine.begin() as conn:
        append_event(conn, new_event())

    assert _count_rows(app_engine) == (0, 0)


def test_database_error_rolls_back_the_whole_append(app_engine: Engine, new_event: Any) -> None:
    # PostgreSQL text cannot hold U+0000; FR-1 validation rejects it before this layer.
    with pytest.raises(DataError), app_engine.begin() as connection:
        append_event(connection, new_event(actor_id="user\x00-7"))

    assert _count_rows(app_engine) == (0, 0)


@pytest.mark.parametrize(
    "changes",
    [
        {"timestamp": "2026-09-28T15:00:00Z"},
        {"payload": {"amount": 1e16}},
        {"payload": {"amount": float("nan")}},
        {"payload": {"key": {1, 2}}},
    ],
    ids=["non-canonical-timestamp", "out-of-domain-number", "nan", "unsupported-type"],
)
def test_invalid_event_is_rejected_before_anything_is_written(
    app_engine: Engine, append: Append, new_event: Any, changes: dict[str, Any]
) -> None:
    with pytest.raises(IntegrityInputError), app_engine.begin() as connection:
        append_event(connection, new_event(**changes))

    assert _count_rows(app_engine) == (0, 0)
    assert append().sequence == 1


def test_append_requires_an_explicit_transaction(app_engine: Engine, new_event: Any) -> None:
    with (
        app_engine.connect() as connection,
        pytest.raises(PersistenceUsageError, match="explicit transaction"),
    ):
        append_event(connection, new_event())


def test_append_requires_read_committed(app_engine: Engine, new_event: Any) -> None:
    repeatable_read = app_engine.execution_options(isolation_level="REPEATABLE READ")
    with (
        repeatable_read.begin() as connection,
        pytest.raises(PersistenceUsageError, match="READ COMMITTED"),
    ):
        append_event(connection, new_event())


def test_load_of_an_empty_chain(load: Load) -> None:
    assert load() == []
    assert verify_chain(load()).intact


# --- Round trip through PostgreSQL --------------------------------------------------------------

_KEYS = st.text(alphabet=st.characters(exclude_categories=("Cs",), exclude_characters="\x00"))
_SCALARS = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-MAX_SAFE_INTEGER, max_value=MAX_SAFE_INTEGER)
    | st.floats(min_value=-MAX_SAFE_INTEGER, max_value=MAX_SAFE_INTEGER, allow_nan=False)
    | _KEYS
)
_PAYLOADS = st.dictionaries(
    _KEYS,
    st.recursive(
        _SCALARS,
        lambda children: (
            st.lists(children, max_size=3) | st.dictionaries(_KEYS, children, max_size=3)
        ),
        max_leaves=8,
    ),
    max_size=4,
)


@settings(
    max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(payload=_PAYLOADS)
def test_any_accepted_payload_round_trips_through_postgresql(
    app_engine: Engine, owner_engine: Engine, payload: dict[str, Any]
) -> None:
    with owner_engine.begin() as connection:
        connection.execute(text("TRUNCATE audit_payload_values, audit_records"))
    with app_engine.begin() as connection:
        appended = append_event(connection, dataclasses.replace(_BASE_EVENT, payload=payload))
    with app_engine.begin() as connection:
        [entry] = load_chain_entries(connection)

    assert entry.record == appended
    assert verify_chain([entry]).intact
    leaves = dict(_leaves(payload))
    assert set(entry.payload_values) == set(leaves)
    for pointer, value in entry.payload_values.items():
        assert value.canonical_text == canonicalize(leaves[pointer]).decode("utf-8")


_BASE_EVENT = NewEvent(
    event_type="CLIENT_ACCOUNT_VIEWED",
    actor_id="user-7",
    resource_type="CLIENT_ACCOUNT",
    resource_id="acct-42",
    timestamp=None,
    recorded_by="svc-writer",
    payload={},
)


def _leaves(node: Any, pointer: str = "") -> list[tuple[str, Any]]:
    if isinstance(node, dict):
        return [
            leaf
            for key, item in node.items()  # pyright: ignore[reportUnknownVariableType]
            for leaf in _leaves(item, f"{pointer}/{str(key).replace('~', '~0').replace('/', '~1')}")  # pyright: ignore[reportUnknownArgumentType]
        ]
    if isinstance(node, list):
        return [
            leaf
            for index, item in enumerate(node)  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
            for leaf in _leaves(item, f"{pointer}/{index}")
        ]
    return [(pointer, node)]
