"""NFR-3 performance measurements (Phase 12 decisions P1 to P3, P9).

Measures the prototype's application operations against a real, throwaway PostgreSQL database and
reports observed results only; there are no targets or pass/fail thresholds. Production code is
not changed or instrumented: the script calls the same application functions the routes and CLIs
use, and times them from outside.

    AUDIT_LOG_BENCHMARK_SERVER_URL=postgresql+psycopg://postgres@127.0.0.1:55432/postgres \\
        uv run python scripts/benchmark.py --output local/benchmark-results.json

The server URL names a disposable PostgreSQL server as a role that can create databases and roles
(like AUDIT_LOG_TEST_DATABASE_URL). For each chain size the script creates a database, provisions
the group roles, migrates it, and seeds a correctly sealed chain with a benchmark-only bulk insert
as the owner. Appends are always measured through the real append path. Every database and the
temporary login role used by the HTTP sample are dropped at the end.

Method: per-request operations get warm-up iterations that are discarded, then measured ones
(p50/p95/p99, min, max, mean, throughput); heavy operations get one warm-up and five measured runs
(median, min, max). Peak Python memory is measured in a separate run with tracemalloc, because
tracing slows the code it measures. `--quick` shrinks everything for a smoke run.

The defaults are the finalized Phase 12 scope: chains of 1,000 and 10,000 records, retention with
10,000-value batches at 10,000 records, and the HTTP sample at 10,000 records. Only those sizes were
measured and reported (docs/performance.md). Larger sizes can be requested with `--sizes`,
`--extended`, and `--retention-large-batch`, but no results for them exist.
"""

import argparse
import contextlib
import hashlib
import json
import math
import os
import platform
import secrets
import socket
import statistics

# The HTTP sample starts this project's own service, with fixed arguments and no shell.
import subprocess  # nosec B404
import sys
import tempfile
import threading
import time
import tracemalloc
import uuid
from collections.abc import Callable, Generator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn

import httpx
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import URL, Engine, create_engine, event, insert, make_url, pool, text
from sqlalchemy.exc import OperationalError

from audit_log_service.application.checkpoints import create_checkpoint
from audit_log_service.application.events import (
    find_event,
    parse_submission,
    prepare_event,
    record_event,
)
from audit_log_service.application.exports import ExportPolicy, create_export
from audit_log_service.application.queries import parse_query, run_query
from audit_log_service.application.redactions import RedactionRequest, redact
from audit_log_service.application.retention import (
    RetentionIncompleteError,
    RetentionPolicy,
    run_retention,
)
from audit_log_service.application.verification import verify_audit_chain
from audit_log_service.config.vocabulary import load_client_account_vocabulary
from audit_log_service.integrity.canonical import JsonValue
from audit_log_service.integrity.commitments import commit_payload
from audit_log_service.integrity.exports import verify_export
from audit_log_service.integrity.hashing import GENESIS_PREVIOUS_HASH, EventContent, seal_record
from audit_log_service.integrity.timestamps import format_timestamp, parse_timestamp
from audit_log_service.integrity.verification import verify_chain
from audit_log_service.persistence.audit_log import load_chain_entries, read_only_snapshot
from audit_log_service.persistence.schema import (
    APPLICATION_ROLE,
    CHECKPOINT_ROLE,
    audit_payload_values,
    audit_records,
)

ROOT = Path(__file__).resolve().parents[1]
SERVER_URL_VARIABLE = "AUDIT_LOG_BENCHMARK_SERVER_URL"
VOCABULARY_FILE = ROOT / "config" / "client-account-vocabulary.example.toml"
ACTORS = 100  # actor-0 selects 1% of the seeded chain
RESOURCES = 10  # acct-0 selects 10%
OLD_START = datetime(2020, 1, 1, tzinfo=UTC)
SKEW = timedelta(minutes=5)
LARGE_VALUES = 200
BATCH = 1_000

Samples = list[float]


@dataclass(frozen=True, slots=True)
class Plan:
    """Repetitions: warm-up and measured iterations for light and heavy operations."""

    light_warmup: int
    light_repeat: int
    append_repeat: int
    heavy_warmup: int
    heavy_repeat: int
    redactions: int
    concurrent_appends: int
    writers: tuple[int, ...]

    @staticmethod
    def full() -> "Plan":
        return Plan(20, 200, 500, 1, 5, 100, 200, (1, 4, 8))

    @staticmethod
    def quick() -> "Plan":
        return Plan(2, 5, 5, 0, 2, 3, 5, (1, 2))


# --- Statistics ---------------------------------------------------------------------------------


def percentile(samples: Sequence[float], fraction: float) -> float:
    """Nearest-rank percentile of the samples (fraction between 0 and 1)."""
    ordered = sorted(samples)
    rank = max(1, min(len(ordered), math.ceil(fraction * len(ordered))))
    return ordered[rank - 1]


def latency_summary(samples: Sequence[float]) -> dict[str, float | int]:
    """Latency percentiles in milliseconds, and the throughput of sequential calls."""
    return {
        "count": len(samples),
        "p50_ms": round(percentile(samples, 0.50) * 1000, 3),
        "p95_ms": round(percentile(samples, 0.95) * 1000, 3),
        "p99_ms": round(percentile(samples, 0.99) * 1000, 3),
        "min_ms": round(min(samples) * 1000, 3),
        "max_ms": round(max(samples) * 1000, 3),
        "mean_ms": round(statistics.fmean(samples) * 1000, 3),
        "per_second": round(len(samples) / sum(samples), 1),
    }


def run_summary(samples: Sequence[float], items: int | None = None) -> dict[str, float | int]:
    """Median, min, and max seconds of heavy runs, and items per second at the median."""
    median = statistics.median(samples)
    summary: dict[str, float | int] = {
        "runs": len(samples),
        "median_s": round(median, 3),
        "min_s": round(min(samples), 3),
        "max_s": round(max(samples), 3),
    }
    if items is not None and median > 0:
        summary["items"] = items
        summary["items_per_second"] = round(items / median, 1)
    return summary


def measure(action: Callable[[int], object], warmup: int, repeat: int) -> Samples:
    """Time `action(iteration)`; the first `warmup` iterations are run and discarded."""
    samples: Samples = []
    for iteration in range(warmup + repeat):
        start = time.perf_counter()
        action(iteration)
        elapsed = time.perf_counter() - start
        if iteration >= warmup:
            samples.append(elapsed)
    return samples


def peak_memory_mib(action: Callable[[], object]) -> float:
    """Peak Python heap allocation during one run, in MiB (tracemalloc)."""
    tracemalloc.start()
    try:
        action()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return round(peak / (1024 * 1024), 1)


# --- Throwaway databases ------------------------------------------------------------------------


class Database:
    """A migrated database with owner, application-role, and checkpoint-role engines."""

    def __init__(self, server: URL) -> None:
        self.name = f"audit_log_bench_{secrets.token_hex(6)}"
        self._admin = create_engine(server, isolation_level="AUTOCOMMIT", poolclass=pool.NullPool)
        with self._admin.connect() as connection:
            provisioning = (ROOT / "scripts" / "provision_database_roles.sql").read_text("utf-8")
            connection.execute(text(provisioning))
            connection.execute(text(f'CREATE DATABASE "{self.name}"'))
        self.url = server.set(database=self.name)
        self.owner = create_engine(self.url)
        with self.owner.begin() as connection:
            config = Config(str(ROOT / "alembic.ini"))
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        self.app = _role_engine(self.url, APPLICATION_ROLE, pool_size=12)
        self.checkpoint = _role_engine(self.url, CHECKPOINT_ROLE, pool_size=2)

    def drop(self) -> None:
        for engine in (self.owner, self.app, self.checkpoint):
            engine.dispose()
        with self._admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{self.name}" WITH (FORCE)'))
        self._admin.dispose()


def _role_engine(url: URL, role: str, pool_size: int) -> Engine:
    engine = create_engine(url, pool_size=pool_size, max_overflow=4)

    @event.listens_for(engine, "connect")
    def use_role(dbapi_connection: Any, _record: Any) -> None:  # pyright: ignore[reportUnusedFunction]
        dbapi_connection.execute(f"SET ROLE {role}")
        dbapi_connection.commit()

    return engine


@contextlib.contextmanager
def database(server: URL) -> Generator[Database]:
    db = Database(server)
    try:
        yield db
    finally:
        db.drop()


def typical_payload(index: int) -> dict[str, JsonValue]:
    """A Scenario C access event: five scalar values, field names only (SC-A3)."""
    return {
        "purpose": "annual-review",
        "channel": ("web", "branch", "phone")[index % 3],
        "fieldsAccessed": ["email", "phone"],
        "ticket": index,
    }


def large_payload(index: int) -> dict[str, JsonValue]:
    return {f"f{position:03d}": f"value-{index}-{position}" for position in range(LARGE_VALUES)}


def seed(owner: Engine, size: int) -> tuple[list[str], datetime]:
    """Bulk-insert a sealed chain of `size` typical records; return their ids and recent start.

    Benchmark-only: the first half has old `recordedAt` values (eligible for a 30-day retention
    window), the second half is recent. Each record is sealed with the integrity library, so the
    chain verifies exactly as an appended one does.
    """
    ids: list[str] = []
    previous = GENESIS_PREVIOUS_HASH
    recent_start = datetime.now(UTC) - timedelta(days=1)
    rows: list[dict[str, Any]] = []
    values: list[dict[str, Any]] = []
    for index in range(size):
        sequence = index + 1
        committed = commit_payload(typical_payload(index))
        recorded_at = (
            OLD_START + timedelta(seconds=index)
            if index < size // 2
            else recent_start + timedelta(milliseconds=index)
        )
        content = EventContent(
            id=str(uuid.uuid4()),
            event_type="CLIENT_ACCOUNT_VIEWED",
            actor_id=f"actor-{index % ACTORS}",
            resource_type="CLIENT_ACCOUNT",
            resource_id=f"acct-{index % RESOURCES}",
            timestamp=None,
            recorded_at=format_timestamp(recorded_at),
            recorded_by="bench-writer",
            payload=committed.structure,
        )
        record = seal_record(content, sequence, previous)
        previous = record.record_hash
        ids.append(content.id)
        rows.append(
            {
                "id": uuid.UUID(content.id),
                "sequence": sequence,
                "previous_hash": record.previous_hash,
                "content_hash": record.content_hash,
                "record_hash": record.record_hash,
                "event_type": content.event_type,
                "actor_id": content.actor_id,
                "resource_type": content.resource_type,
                "resource_id": content.resource_id,
                "timestamp": None,
                "recorded_at": parse_timestamp(content.recorded_at),
                "recorded_by": content.recorded_by,
                "committed_payload": content.payload,
            }
        )
        values += [
            {
                "record_id": uuid.UUID(content.id),
                "pointer": pointer,
                "canonical_value": value.canonical_text,
                "salt": value.salt,
            }
            for pointer, value in committed.values.items()
        ]
        if len(rows) == BATCH or sequence == size:
            with owner.begin() as connection:
                connection.execute(insert(audit_records), rows)
                connection.execute(insert(audit_payload_values), values)
            rows, values = [], []
    return ids, recent_start


# --- Operations ---------------------------------------------------------------------------------


def append_through_application(app: Engine, body: Mapping[str, Any], vocabulary: Any) -> None:
    """The route's path: validate, prepare, and record in one READ COMMITTED transaction."""
    new_event = prepare_event(parse_submission(dict(body)), "bench-writer", vocabulary)
    with app.begin() as connection:
        record_event(connection, new_event, SKEW)


def order_body(index: int, payload: dict[str, JsonValue]) -> dict[str, Any]:
    return {
        "eventType": "ORDER_PLACED",
        "actorId": f"buyer-{index % ACTORS}",
        "resourceType": "ORDER",
        "resourceId": f"order-{index}",
        "payload": payload,
    }


def query_once(app: Engine, parameters: Sequence[tuple[str, str]]) -> int:
    query = parse_query(parameters)
    with read_only_snapshot(app) as connection:
        return len(run_query(connection, query).events)


def walk_pages(app: Engine, parameters: Sequence[tuple[str, str]]) -> int:
    pages, cursor = 0, None
    while True:
        query = parse_query([*parameters, *([("cursor", cursor)] if cursor else [])])
        with read_only_snapshot(app) as connection:
            page = run_query(connection, query)
        pages += 1
        cursor = page.next_cursor
        if cursor is None:
            return pages


def concurrent_appends(
    app: Engine, vocabulary: Any, writers: int, per_writer: int
) -> dict[str, Any]:
    latencies: Samples = []
    timeouts = 0
    lock = threading.Lock()
    barrier = threading.Barrier(writers)

    def writer(number: int) -> None:
        nonlocal timeouts
        barrier.wait()
        for index in range(per_writer):
            start = time.perf_counter()
            try:
                append_through_application(
                    app, order_body(number * per_writer + index, typical_payload(index)), vocabulary
                )
            except OperationalError:
                with lock:
                    timeouts += 1
                continue
            with lock:
                latencies.append(time.perf_counter() - start)

    threads = [threading.Thread(target=writer, args=(number,)) for number in range(writers)]
    start = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    wall = time.perf_counter() - start
    with app.connect() as connection:
        intact = verify_chain(load_chain_entries(connection)).intact
    return {
        "writers": writers,
        "appends": len(latencies),
        "wall_s": round(wall, 3),
        "appends_per_second": round(len(latencies) / wall, 1),
        "latency": latency_summary(latencies),
        "lock_timeouts": timeouts,
        "chain_intact_after": intact,
    }


def retention_to_completion(app: Engine, batch_size: int) -> dict[str, Any]:
    """Run bounded retention until its purge completes, as an operator would (FR-5)."""
    policy = RetentionPolicy(window=timedelta(days=30), batch_size=batch_size, max_batches=20)
    with app.connect() as connection:
        before = connection.execute(text("SELECT count(*) FROM audit_payload_values")).scalar_one()
    runs = 0
    start = time.perf_counter()
    while True:
        runs += 1
        try:
            run_retention(app, policy, "bench-admin")
        except RetentionIncompleteError:
            continue
        break
    elapsed = time.perf_counter() - start
    with app.connect() as connection:
        after = connection.execute(text("SELECT count(*) FROM audit_payload_values")).scalar_one()
        intact = verify_chain(load_chain_entries(connection)).intact
    purged = before - after
    return {
        "batch_size": batch_size,
        "max_batches": 20,
        "runs": runs,
        "values_purged": purged,
        "total_s": round(elapsed, 3),
        "values_per_second": round(purged / elapsed, 1) if elapsed else None,
        "chain_intact_after": intact,
    }


# --- Benchmarks ---------------------------------------------------------------------------------


def benchmark_size(server: URL, size: int, plan: Plan, workdir: Path) -> dict[str, Any]:
    """Every operation at one chain size, on a fresh database."""
    vocabulary = load_client_account_vocabulary(VOCABULARY_FILE)
    result: dict[str, Any] = {"chain_size": size}
    with database(server) as db:
        start = time.perf_counter()
        ids, recent_start = seed(db.owner, size)
        result["seed_s"] = round(time.perf_counter() - start, 3)
        store = workdir / f"store-{size}"
        store.mkdir()
        checkpoint_key = Ed25519PrivateKey.generate()
        export_key = Ed25519PrivateKey.generate()

        result["append_typical"] = latency_summary(
            measure(
                lambda i: append_through_application(
                    db.app, order_body(i, typical_payload(i)), vocabulary
                ),
                plan.light_warmup,
                plan.append_repeat,
            )
        )
        large_ids_start = len(ids) + plan.light_warmup + plan.append_repeat
        result["append_large"] = latency_summary(
            measure(
                lambda i: append_through_application(
                    db.app, order_body(i, large_payload(i)), vocabulary
                ),
                plan.light_warmup,
                plan.redactions + plan.light_warmup,
            )
        )
        with db.app.connect() as connection:
            large_ids = [
                str(row[0])
                for row in connection.execute(
                    text("SELECT id FROM audit_records WHERE sequence > :s ORDER BY sequence"),
                    {"s": large_ids_start},
                )
            ]
        recent_from = format_timestamp(recent_start)
        recent_to = format_timestamp(recent_start + timedelta(hours=1))
        queries: dict[str, list[tuple[str, str]]] = {
            "actor_limit_50": [("actorId", "actor-0"), ("limit", "50")],
            "actor_limit_200": [("actorId", "actor-0"), ("limit", "200")],
            "resource_limit_50": [("resourceId", "acct-0"), ("limit", "50")],
            "event_type_limit_50": [("eventType", "CLIENT_ACCOUNT_VIEWED"), ("limit", "50")],
            "time_range_limit_50": [("from", recent_from), ("to", recent_to), ("limit", "50")],
        }
        result["query"] = {
            name: latency_summary(
                measure(
                    lambda _i, p=parameters: query_once(db.app, p),
                    plan.light_warmup,
                    plan.light_repeat,
                )
            )
            for name, parameters in queries.items()
        }
        walk = [("resourceId", "acct-0"), ("limit", "200")]
        result["pagination_walk_10pct_limit_200"] = {
            **run_summary(
                measure(lambda _i: walk_pages(db.app, walk), plan.heavy_warmup, plan.heavy_repeat)
            ),
            "pages": walk_pages(db.app, walk),
        }
        picks = [
            ids[(index * 7919) % len(ids)] for index in range(plan.light_warmup + plan.light_repeat)
        ]

        def get_by_id(i: int) -> None:
            with read_only_snapshot(db.app) as connection:
                find_event(connection, picks[i])

        result["get_by_id"] = latency_summary(
            measure(get_by_id, plan.light_warmup, plan.light_repeat)
        )

        with db.app.connect() as connection:
            chain_length = connection.execute(
                text("SELECT count(*) FROM audit_records")
            ).scalar_one()
        public = checkpoint_key.public_key()
        result["verify_no_checkpoint"] = {
            **run_summary(
                measure(
                    lambda _i: verify_audit_chain(db.app, store, public),
                    plan.heavy_warmup,
                    plan.heavy_repeat,
                ),
                chain_length,
            ),
            "peak_memory_mib": peak_memory_mib(lambda: verify_audit_chain(db.app, store, public)),
        }
        result["checkpoint_create"] = run_summary(
            measure(
                lambda _i: create_checkpoint(db.checkpoint, store, checkpoint_key, "bench-admin"),
                plan.heavy_warmup,
                plan.heavy_repeat,
            ),
            chain_length,
        )
        result["verify_with_checkpoint"] = run_summary(
            measure(
                lambda _i: verify_audit_chain(db.app, store, public),
                plan.heavy_warmup,
                plan.heavy_repeat,
            ),
            chain_length,
        )

        recent_ids = ids[size // 2 :]

        def redact_one(i: int) -> None:
            with db.app.begin() as connection:
                redact(
                    connection,
                    recent_ids[i],
                    RedactionRequest(paths=["/purpose"], reason="benchmark"),
                    "bench-admin",
                )

        def redact_ten(i: int) -> None:
            paths = [f"/f{position:03d}" for position in range(10)]
            with db.app.begin() as connection:
                redact(
                    connection,
                    large_ids[i],
                    RedactionRequest(paths=paths, reason="benchmark"),
                    "bench-admin",
                )

        result["redact_1_path"] = latency_summary(
            measure(redact_one, plan.light_warmup, plan.redactions)
        )
        result["redact_10_paths"] = latency_summary(
            measure(redact_ten, plan.light_warmup, plan.redactions)
        )

        policy = ExportPolicy(max_records=10_000, max_bytes=1024**3)
        export_public = export_key.public_key()
        result["export"] = {}
        result["offline_verify"] = {}
        for label, scope in (
            ("actor_1pct", {"actorId": "actor-0"}),
            # With the type, the selection stays exactly 10%: export events are AUDIT_LOG resources.
            ("resource_10pct", {"resourceId": "acct-0", "resourceType": "CLIENT_ACCOUNT"}),
        ):

            def export_once(_i: int, s: dict[str, str] = scope) -> bytes:
                return create_export(
                    db.app, s, export_key, policy, store, public, "bench-auditor"
                ).body

            bundle = export_once(0)
            records = len(json.loads(bundle)["records"])
            result["export"][label] = {
                **run_summary(measure(export_once, plan.heavy_warmup, plan.heavy_repeat), records),
                "bundle_bytes": len(bundle),
                "peak_memory_mib": peak_memory_mib(lambda s=scope: export_once(0, s)),
            }
            if not verify_export(bundle, export_public).valid:
                raise RuntimeError("the benchmark export did not verify")
            result["offline_verify"][label] = {
                **run_summary(
                    measure(
                        lambda _i, b=bundle: verify_export(b, export_public),
                        plan.heavy_warmup,
                        plan.heavy_repeat,
                    ),
                    records,
                ),
                "bundle_bytes": len(bundle),
                "peak_memory_mib": peak_memory_mib(
                    lambda b=bundle: verify_export(b, export_public)
                ),
            }

        result["concurrent_append"] = [
            concurrent_appends(db.app, vocabulary, writers, plan.concurrent_appends)
            for writers in plan.writers
        ]
        result["retention_batch_500"] = retention_to_completion(db.app, 500)
    return result


def benchmark_retention_large_batch(server: URL, size: int) -> dict[str, Any]:
    with database(server) as db:
        seed(db.owner, size)
        return {"chain_size": size, **retention_to_completion(db.app, 10_000)}


def benchmark_extended(server: URL, size: int, plan: Plan, workdir: Path) -> dict[str, Any]:
    """Verification, export, and offline verification only, at a larger chain size."""
    result: dict[str, Any] = {"chain_size": size}
    with database(server) as db:
        start = time.perf_counter()
        seed(db.owner, size)
        result["seed_s"] = round(time.perf_counter() - start, 3)
        store = workdir / f"store-extended-{size}"
        store.mkdir()
        public = Ed25519PrivateKey.generate().public_key()
        export_key = Ed25519PrivateKey.generate()
        result["verify_no_checkpoint"] = {
            **run_summary(
                measure(
                    lambda _i: verify_audit_chain(db.app, store, public),
                    plan.heavy_warmup,
                    plan.heavy_repeat,
                ),
                size,
            ),
            "peak_memory_mib": peak_memory_mib(lambda: verify_audit_chain(db.app, store, public)),
        }
        policy = ExportPolicy(max_records=10_000, max_bytes=1024**3)

        def export_once(_i: int) -> bytes:
            return create_export(
                db.app,
                {"resourceId": "acct-0", "resourceType": "CLIENT_ACCOUNT"},
                export_key,
                policy,
                store,
                public,
                "bench-auditor",
            ).body

        bundle = export_once(0)
        records = len(json.loads(bundle)["records"])
        result["export_resource_10pct"] = {
            **run_summary(measure(export_once, plan.heavy_warmup, plan.heavy_repeat), records),
            "bundle_bytes": len(bundle),
            "peak_memory_mib": peak_memory_mib(lambda: export_once(0)),
        }
        export_public = export_key.public_key()
        result["offline_verify_resource_10pct"] = {
            **run_summary(
                measure(
                    lambda _i: verify_export(bundle, export_public),
                    plan.heavy_warmup,
                    plan.heavy_repeat,
                ),
                records,
            ),
            "peak_memory_mib": peak_memory_mib(lambda: verify_export(bundle, export_public)),
        }
    return result


def benchmark_http(server: URL, size: int, plan: Plan, workdir: Path) -> dict[str, Any]:
    """Append and query through a real uvicorn process (framework and HTTP overhead)."""
    login = f"audit_log_bench_app_{secrets.token_hex(4)}"
    admin = create_engine(server, isolation_level="AUTOCOMMIT", poolclass=pool.NullPool)
    writer_key = secrets.token_urlsafe(32)
    auditor_key = secrets.token_urlsafe(32)
    with database(server) as db:
        seed(db.owner, size)
        with admin.connect() as connection:
            connection.execute(text(f"CREATE ROLE {login} LOGIN IN ROLE {APPLICATION_ROLE}"))
        try:
            config = _http_config(workdir, writer_key, auditor_key)
            port = _free_port()
            environment = {
                **{k: v for k, v in os.environ.items() if not k.startswith("AUDIT_LOG_")},
                "AUDIT_LOG_DATABASE_URL": db.url.set(
                    username=login, password=None
                ).render_as_string(hide_password=False),
                **config,
            }
            service_log = (workdir / "http-service.log").open("wb")
            process = subprocess.Popen(  # nosec B603
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "audit_log_service.api.app:create_app",
                    "--factory",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--no-access-log",
                ],
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=service_log,
            )
            try:
                with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=30) as client:
                    _wait_ready(client)
                    writer = {"Authorization": f"Bearer {writer_key}"}
                    auditor = {"Authorization": f"Bearer {auditor_key}"}
                    return {
                        "chain_size": size,
                        "append_typical": latency_summary(
                            measure(
                                lambda i: _expect(
                                    client.post(
                                        "/audit/events",
                                        json=order_body(i, typical_payload(i)),
                                        headers=writer,
                                    ),
                                    201,
                                ),
                                plan.light_warmup,
                                plan.light_repeat,
                            )
                        ),
                        "query_actor_limit_50": latency_summary(
                            measure(
                                lambda _i: _expect(
                                    client.get(
                                        "/audit/events",
                                        params=(("actorId", "actor-0"), ("limit", "50")),
                                        headers=auditor,
                                    ),
                                    200,
                                ),
                                plan.light_warmup,
                                plan.light_repeat,
                            )
                        ),
                        "health_ready": latency_summary(
                            measure(
                                lambda _i: _expect(client.get("/health/ready"), 200),
                                plan.light_warmup,
                                plan.light_repeat,
                            )
                        ),
                    }
            except RuntimeError:
                process.terminate()
                process.wait(timeout=30)
                service_log.close()
                sys.stderr.write((workdir / "http-service.log").read_text("utf-8", "replace"))
                raise
            finally:
                process.terminate()
                process.wait(timeout=30)
                service_log.close()
        finally:
            db.app.dispose()
            with admin.connect() as connection:
                connection.execute(text(f"DROP ROLE IF EXISTS {login}"))
            admin.dispose()


def _http_config(workdir: Path, writer_key: str, auditor_key: str) -> dict[str, str]:
    keys = workdir / "http-api-keys.toml"
    entries = [
        (name, role, hashlib.sha256(key.encode()).hexdigest())
        for name, role, key in (
            ("bench-writer", "writer", writer_key),
            ("bench-auditor", "auditor", auditor_key),
        )
    ]
    lines: list[str] = []
    for name, role, digest in entries:
        lines += ["[[principals]]", f'id = "{name}"', f'role = "{role}"']
        lines += [f'key_sha256 = ["{digest}"]', ""]
    keys.write_text("\n".join(lines), encoding="utf-8")
    store = workdir / "http-store"
    store.mkdir(exist_ok=True)
    public = workdir / "http-checkpoint-public.pem"
    public.write_bytes(
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    return {
        "AUDIT_LOG_API_KEYS_FILE": str(keys),
        "AUDIT_LOG_VOCABULARY_FILE": str(VOCABULARY_FILE),
        "AUDIT_LOG_CHECKPOINT_STORE_DIR": str(store),
        "AUDIT_LOG_CHECKPOINT_PUBLIC_KEY_FILE": str(public),
    }


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


def _wait_ready(client: httpx.Client) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        with contextlib.suppress(httpx.TransportError):
            if client.get("/health/ready").status_code == 200:
                return
        time.sleep(0.2)
    raise RuntimeError("the service did not become ready")


def _expect(response: httpx.Response, status: int) -> None:
    if response.status_code != status:
        raise RuntimeError(f"unexpected status {response.status_code}")


def environment_info(server: URL) -> dict[str, Any]:
    engine = create_engine(server, poolclass=pool.NullPool)
    with engine.connect() as connection:
        version = connection.execute(text("SHOW server_version")).scalar_one()
    engine.dispose()
    commit = _commit()
    return {
        "started": datetime.now(UTC).isoformat(timespec="seconds"),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "postgresql": version,
        "commit": commit,
    }


def _commit() -> str:
    """The checked-out commit, read from .git without running git."""
    try:
        head = (ROOT / ".git" / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref: "):
            ref = head.removeprefix("ref: ")
            loose = ROOT / ".git" / ref
            if loose.exists():
                return loose.read_text(encoding="utf-8").strip()[:12]
            for line in (ROOT / ".git" / "packed-refs").read_text(encoding="utf-8").splitlines():
                if line.endswith(" " + ref):
                    return line.split(" ", 1)[0][:12]
            return "unknown"
        return head[:12]
    except OSError:
        return "unknown"


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise _UsageError(message)


def parse_arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = _Parser(prog="benchmark.py", description="NFR-3 performance measurements.")
    parser.add_argument(
        "--sizes", type=int, nargs="*", default=[1_000, 10_000], help="chain sizes (all operations)"
    )
    parser.add_argument(
        "--extended",
        type=int,
        nargs="*",
        default=[],
        help="extra sizes for verification and export only (none by default)",
    )
    parser.add_argument(
        "--retention-large-batch",
        type=int,
        nargs="*",
        default=[10_000],
        help="sizes for retention with 10,000-value batches",
    )
    parser.add_argument("--http-size", type=int, default=10_000, help="0 skips the HTTP sample")
    parser.add_argument("--quick", action="store_true", help="tiny repetitions, for a smoke run")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if any(size < 20 for size in [*arguments.sizes, *arguments.extended]):
        parser.error("chain sizes must be at least 20")
    return arguments


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] = os.environ) -> int:
    try:
        arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
    except _UsageError as error:
        sys.stderr.write(f"usage error: {error}\n")
        return 2
    raw_server = environ.get(SERVER_URL_VARIABLE, "").strip()
    if not raw_server:
        sys.stderr.write(f"configuration error: {SERVER_URL_VARIABLE} must be set\n")
        return 2
    server = make_url(raw_server)
    plan = Plan.quick() if arguments.quick else Plan.full()
    results: dict[str, Any] = {"environment": environment_info(server), "quick": arguments.quick}
    output: Path = arguments.output
    sizes: list[dict[str, Any]] = []
    retention: list[dict[str, Any]] = []
    extended: list[dict[str, Any]] = []
    results.update(sizes=sizes, retention_batch_10000=retention, extended=extended)
    with tempfile.TemporaryDirectory() as directory:
        workdir = Path(directory)
        # Results are saved after every section, so a failure keeps everything measured so far.
        for size in arguments.sizes:
            _progress(f"chain size {size}")
            sizes.append(benchmark_size(server, size, plan, workdir))
            _save(output, results)
        for size in arguments.retention_large_batch:
            _progress(f"retention with batch 10000 at {size}")
            retention.append(benchmark_retention_large_batch(server, size))
            _save(output, results)
        for size in arguments.extended:
            _progress(f"extended size {size}")
            extended.append(benchmark_extended(server, size, plan, workdir))
            _save(output, results)
        if arguments.http_size:
            _progress(f"HTTP sample at {arguments.http_size}")
            results["http"] = benchmark_http(server, arguments.http_size, plan, workdir)
    results["finished"] = datetime.now(UTC).isoformat(timespec="seconds")
    _save(output, results)
    print(f"wrote {output}", file=sys.stderr)
    return 0


def _progress(section: str) -> None:
    print(f"benchmarking {section} ...", file=sys.stderr, flush=True)


def _save(output: Path, results: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
