"""scripts/benchmark.py: statistics and arguments (Phase 12 decision P1).

The measurements themselves run only when the script is run; they are not part of the test suite.
"""

import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest


@pytest.fixture
def benchmark(load_script: Callable[[str], ModuleType]) -> ModuleType:
    return load_script("benchmark")


def test_percentiles_use_the_nearest_rank(benchmark: ModuleType) -> None:
    samples = [float(value) for value in range(1, 101)]
    assert benchmark.percentile(samples, 0.50) == 50.0
    assert benchmark.percentile(samples, 0.95) == 95.0
    assert benchmark.percentile(samples, 0.99) == 99.0
    assert benchmark.percentile([7.0], 0.99) == 7.0


def test_latency_summary_is_in_milliseconds(benchmark: ModuleType) -> None:
    summary = benchmark.latency_summary([0.001, 0.002, 0.003, 0.004])
    assert summary["count"] == 4
    assert (summary["p50_ms"], summary["max_ms"], summary["min_ms"]) == (2.0, 4.0, 1.0)
    assert summary["per_second"] == 400.0


def test_run_summary_reports_items_per_second_at_the_median(benchmark: ModuleType) -> None:
    summary = benchmark.run_summary([2.0, 1.0, 4.0], items=100)
    assert summary == {
        "runs": 3,
        "median_s": 2.0,
        "min_s": 1.0,
        "max_s": 4.0,
        "items": 100,
        "items_per_second": 50.0,
    }
    assert "items" not in benchmark.run_summary([1.0])


def test_measure_discards_warm_up_iterations(benchmark: ModuleType) -> None:
    calls: list[int] = []
    samples = benchmark.measure(calls.append, warmup=3, repeat=4)
    assert calls == list(range(7))
    assert len(samples) == 4


def test_peak_memory_is_reported_in_mib(benchmark: ModuleType) -> None:
    peak = benchmark.peak_memory_mib(lambda: bytearray(4 * 1024 * 1024))
    assert peak >= 3.9


def test_default_arguments_are_the_finalized_scope(benchmark: ModuleType, tmp_path: Path) -> None:
    # The finalized Phase 12 benchmark scope: 1,000 and 10,000 records (docs/performance.md).
    arguments = benchmark.parse_arguments(["--output", str(tmp_path / "r.json")])
    assert arguments.sizes == [1_000, 10_000]
    assert arguments.extended == []
    assert arguments.retention_large_batch == [10_000]
    assert arguments.http_size == 10_000
    assert not arguments.quick
    full = benchmark.Plan.full()
    assert (full.light_warmup, full.light_repeat, full.heavy_warmup, full.heavy_repeat) == (
        20,
        200,
        1,
        5,
    )
    assert full.writers == (1, 4, 8)


@pytest.mark.parametrize(
    "argv", [[], ["--output", "r.json", "--sizes", "10"], ["--bogus"]], ids=str
)
def test_invalid_arguments_are_usage_errors(benchmark: ModuleType, argv: list[str]) -> None:
    with pytest.raises(benchmark._UsageError):  # pyright: ignore[reportPrivateUsage]
        benchmark.parse_arguments(argv)


def test_main_needs_the_server_url(
    benchmark: ModuleType, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    assert benchmark.main(["--output", str(tmp_path / "r.json")], environ={}) == 2
    assert "AUDIT_LOG_BENCHMARK_SERVER_URL must be set" in capsys.readouterr().err
    assert benchmark.main(["--bogus"], environ={}) == 2
    assert not (tmp_path / "r.json").exists()
    assert sys.argv  # untouched


def test_commit_is_read_without_running_git(benchmark: ModuleType) -> None:
    commit: str = benchmark._commit()  # pyright: ignore[reportPrivateUsage]
    assert commit == "unknown" or len(commit) == 12
