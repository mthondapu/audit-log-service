"""Record representation: archived rendering and redacted paths (FR-2, Phase 9 decisions)."""

import uuid

from audit_log_service.api.schemas import represent
from audit_log_service.application.views import EventView
from audit_log_service.integrity.canonical import JsonValue
from audit_log_service.integrity.commitments import commit_payload
from audit_log_service.integrity.hashing import GENESIS_PREVIOUS_HASH, EventContent, seal_record
from audit_log_service.integrity.verification import ChainEntry

PAYLOAD: dict[str, JsonValue] = {"card": "4111", "nested": {"tags": ["x", "y"]}}


def _entry(drop: tuple[str, ...] = ()) -> ChainEntry:
    committed = commit_payload(PAYLOAD)
    content = EventContent(
        id=str(uuid.UUID(int=1)),
        event_type="ORDER_PLACED",
        actor_id="actor",
        resource_type="ORDER",
        resource_id="order-1",
        timestamp=None,
        recorded_at="2026-01-01T00:00:00.000000Z",
        recorded_by="svc",
        payload=committed.structure,
    )
    values = {p: v for p, v in committed.values.items() if p not in drop}
    return ChainEntry(seal_record(content, 1, GENESIS_PREVIOUS_HASH), values)


def test_active_record_shows_stored_values_and_the_redacted_paths_given() -> None:
    body = represent(EventView(_entry(drop=("/card",)), archived=False, redacted_paths=["/card"]))

    assert body["payload"] == {"card": None, "nested": {"tags": ["x", "y"]}}
    assert (body["redactedPaths"], body["archived"]) == (["/card"], False)


def test_archived_record_renders_every_value_null_even_before_the_purge() -> None:
    body = represent(EventView(_entry(), archived=True, redacted_paths=[]))

    assert body["payload"] == {"card": None, "nested": {"tags": [None, None]}}
    assert (body["redactedPaths"], body["archived"]) == ([], True)


def test_missing_values_alone_are_not_reported_as_redacted() -> None:
    body = represent(EventView(_entry(drop=("/card",)), archived=False, redacted_paths=[]))

    assert body["payload"]["card"] is None
    assert body["redactedPaths"] == []


def test_archived_record_keeps_redaction_authorized_paths() -> None:
    body = represent(EventView(_entry(drop=("/card",)), archived=True, redacted_paths=["/card"]))
    assert body["redactedPaths"] == ["/card"]
