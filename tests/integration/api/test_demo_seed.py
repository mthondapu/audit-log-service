"""Scenario C demonstration data, appended through the API by scripts/demo_setup.py (P6)."""

import io
from collections.abc import Callable, Iterator, Mapping
from types import ModuleType
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine

from audit_log_service.api.app import create_app
from audit_log_service.config.settings import Settings
from audit_log_service.integrity.verification import ChainEntry, verify_chain

Load = Callable[[], list[ChainEntry]]


@pytest.fixture
def api(
    settings: Settings, app_engine: Engine, make_client: Callable[[Any], httpx.Client]
) -> Iterator[httpx.Client]:
    with make_client(create_app(settings, app_engine)) as client:
        yield client


def test_seed_appends_the_scenario_c_events_through_the_api(
    load_script: Callable[[str], ModuleType],
    api: httpx.Client,
    fake_keys: Mapping[str, str],
    load: Load,
) -> None:
    demo = load_script("demo_setup")
    stdout = io.StringIO()

    code = demo.run(
        ["seed"],
        stdin=io.StringIO(fake_keys["writer"] + "\n"),
        stdout=stdout,
        stderr=io.StringIO(),
        client=api,
    )

    assert code == 0
    entries = load()
    assert len(entries) == len(demo.SCENARIO_C_EVENTS)
    assert {e.record.content.recorded_by for e in entries} == {"svc-writer"}
    assert verify_chain(entries).intact
    assert fake_keys["writer"] not in stdout.getvalue()


def test_seed_stops_at_a_rejected_append(
    load_script: Callable[[str], ModuleType], api: httpx.Client, load: Load
) -> None:
    demo = load_script("demo_setup")
    stderr = io.StringIO()
    code = demo.run(
        ["seed"],
        stdin=io.StringIO("unknown-test-key\n"),
        stdout=io.StringIO(),
        stderr=stderr,
        client=api,
    )
    assert code == 1
    assert "append rejected with 401" in stderr.getvalue()
    assert load() == []
