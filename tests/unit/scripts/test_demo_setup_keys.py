"""scripts/demo_setup.py: demo API keys and argument handling (Phase 12 decision P6)."""

import io
import re
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

from audit_log_service.config.api_keys import load_api_key_configuration
from audit_log_service.security.authentication import authenticate_api_key
from audit_log_service.security.capabilities import Role


@pytest.fixture
def demo(load_script: Callable[[str], ModuleType]) -> ModuleType:
    return load_script("demo_setup")


class FakeStdin(io.StringIO):
    def __init__(self, text: str = "", *, tty: bool = False) -> None:
        super().__init__(text)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _run(demo: ModuleType, *argv: str, stdin: str = "") -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    code: int = demo.run(list(argv), stdin=FakeStdin(stdin), stdout=stdout, stderr=stderr)
    return code, stdout.getvalue(), stderr.getvalue()


def test_keys_writes_digests_and_prints_each_raw_key_once(demo: ModuleType, tmp_path: Path) -> None:
    output = tmp_path / "local" / "api-keys.toml"

    code, out, _ = _run(demo, "keys", "--output", str(output))

    assert code == demo.EXIT_OK
    raw = dict(re.findall(r"export (\w+)='([^']+)'", out))
    assert set(raw) == {"WRITER_KEY", "AUDITOR_KEY", "REGULATOR_KEY", "ADMIN_KEY"}
    assert all(len(key) >= 43 for key in raw.values())  # 32 random bytes, URL-safe base64
    written = output.read_text(encoding="utf-8")
    assert not any(key in written for key in raw.values())
    configuration = load_api_key_configuration(output)
    roles = {
        variable: authenticate_api_key(key, configuration).role for variable, key in raw.items()
    }
    assert roles == {
        "WRITER_KEY": Role.WRITER,
        "AUDITOR_KEY": Role.AUDITOR,
        "REGULATOR_KEY": Role.REGULATOR,
        "ADMIN_KEY": Role.ADMINISTRATOR,
    }


def test_keys_differ_on_every_run(demo: ModuleType, tmp_path: Path) -> None:
    _, first, _ = _run(demo, "keys", "--output", str(tmp_path / "a.toml"))
    _, second, _ = _run(demo, "keys", "--output", str(tmp_path / "b.toml"))
    assert first != second


def test_existing_key_file_is_never_overwritten(demo: ModuleType, tmp_path: Path) -> None:
    output = tmp_path / "api-keys.toml"
    output.write_text("existing", encoding="utf-8")

    code, out, err = _run(demo, "keys", "--output", str(output))

    assert (code, out) == (demo.EXIT_USAGE, "")
    assert "never overwritten" in err
    assert output.read_text(encoding="utf-8") == "existing"


@pytest.mark.parametrize("argv", [(), ("keys",), ("other",)], ids=str)
def test_usage_errors(demo: ModuleType, argv: tuple[str, ...]) -> None:
    code, _, err = _run(demo, *argv)
    assert code == demo.EXIT_USAGE
    assert err.startswith("usage error: ")


def test_seed_requires_a_key_on_stdin(demo: ModuleType) -> None:
    code, _, err = _run(demo, "seed", stdin="\n")
    assert code == demo.EXIT_USAGE
    assert "stdin" in err


def test_seed_prompts_without_echo_on_a_terminal(
    demo: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    prompts: list[str] = []

    def prompt(text: str) -> str:
        prompts.append(text)
        return ""

    monkeypatch.setattr(demo.getpass, "getpass", prompt)
    code: int = demo.run(
        ["seed"], stdin=FakeStdin(tty=True), stdout=io.StringIO(), stderr=io.StringIO()
    )
    assert (code, prompts) == (demo.EXIT_USAGE, ["Writer API key: "])


def test_seed_events_follow_the_example_vocabulary(demo: ModuleType) -> None:
    events = demo.SCENARIO_C_EVENTS
    account_events = [e for e in events if e["resourceType"] == "CLIENT_ACCOUNT"]
    assert {e["eventType"] for e in account_events} == {
        "CLIENT_ACCOUNT_VIEWED",
        "CLIENT_ACCOUNT_UPDATED",
        "CLIENT_ACCOUNT_ACCESS_DENIED",
    }
    assert {e["resourceId"] for e in account_events} == {"acct-1001", "acct-1002"}
