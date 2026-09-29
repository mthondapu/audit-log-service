"""Shared test fixtures.

All API keys here are deterministic, obviously fake test values. Their SHA-256 digests are
computed in the fixtures; no real credential is used or stored. Checkpoint signing keys are
generated per test and written only under the test's temporary directory.
"""

import hashlib
import importlib.util
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import Any, cast

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi.testclient import TestClient

from audit_log_service.config.api_keys import ApiKeyConfiguration, load_api_key_configuration
from audit_log_service.integrity.checkpoints import key_id
from audit_log_service.integrity.commitments import commit_payload
from audit_log_service.integrity.exports import (
    ExportRecord,
    Manifest,
    ManifestRecord,
    encode_bundle,
    sign_manifest,
)
from audit_log_service.integrity.hashing import GENESIS_PREVIOUS_HASH, EventContent, seal_record
from audit_log_service.integrity.verification import ChainEntry

FAKE_KEYS: Mapping[str, str] = MappingProxyType(
    {
        "writer": "test-only-writer-key",
        "auditor": "test-only-auditor-key",
        "regulator": "test-only-regulator-key",
        "administrator": "test-only-administrator-key",
        "administrator-rotated": "test-only-administrator-rotated-key",
    }
)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


WriteFile = Callable[[str, str], Path]


@pytest.fixture
def write_file(tmp_path: Path) -> WriteFile:
    def _write(name: str, content: str) -> Path:
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        return path

    return _write


@pytest.fixture
def fake_keys() -> Mapping[str, str]:
    return FAKE_KEYS


@pytest.fixture
def valid_api_key_toml() -> str:
    return f"""
[[principals]]
id = "svc-writer"
role = "writer"
key_sha256 = ["{sha256_hex(FAKE_KEYS["writer"])}"]

[[principals]]
id = "auditor-1"
role = "auditor"
key_sha256 = ["{sha256_hex(FAKE_KEYS["auditor"])}"]

[[principals]]
id = "regulator-1"
role = "regulator"
key_sha256 = ["{sha256_hex(FAKE_KEYS["regulator"])}"]

[[principals]]
id = "ops.admin"
role = "administrator"
key_sha256 = [
    "{sha256_hex(FAKE_KEYS["administrator"])}",
    "{sha256_hex(FAKE_KEYS["administrator-rotated"])}",
]
"""


@pytest.fixture
def api_key_configuration(write_file: WriteFile, valid_api_key_toml: str) -> ApiKeyConfiguration:
    return load_api_key_configuration(write_file("api-keys.toml", valid_api_key_toml))


def public_key_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def private_key_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


@pytest.fixture
def checkpoint_key() -> Ed25519PrivateKey:
    """An ephemeral checkpoint signing key, generated in memory for one test."""
    return Ed25519PrivateKey.generate()


@pytest.fixture
def checkpoint_store(tmp_path: Path) -> Path:
    store = tmp_path / "checkpoints"
    store.mkdir()
    return store


@pytest.fixture
def checkpoint_public_key_file(tmp_path: Path, checkpoint_key: Ed25519PrivateKey) -> Path:
    path = tmp_path / "checkpoint-public.pem"
    path.write_bytes(public_key_pem(checkpoint_key))
    return path


@pytest.fixture
def checkpoint_signing_key_file(tmp_path: Path, checkpoint_key: Ed25519PrivateKey) -> Path:
    path = tmp_path / "checkpoint-signing.pem"
    path.write_bytes(private_key_pem(checkpoint_key))
    return path


@pytest.fixture
def export_key() -> Ed25519PrivateKey:
    """An ephemeral export signing key, separate from the checkpoint key (E7)."""
    return Ed25519PrivateKey.generate()


@pytest.fixture
def export_public_key_file(tmp_path: Path, export_key: Ed25519PrivateKey) -> Path:
    path = tmp_path / "export-public.pem"
    path.write_bytes(public_key_pem(export_key))
    return path


ExportBundleWriter = Callable[[Ed25519PrivateKey], tuple[Path, list[str]]]


@pytest.fixture
def write_export_bundle(tmp_path: Path) -> ExportBundleWriter:
    """Write a signed three-record export of `{"actorId": "actor-a"}` (records 1 and 3).

    Returns the bundle path and the record hashes of the whole chain, by position.
    """

    def write(key: Ed25519PrivateKey) -> tuple[Path, list[str]]:
        chain: list[ChainEntry] = []
        for sequence, actor in enumerate(("actor-a", "actor-b", "actor-a"), start=1):
            committed = commit_payload({"card": "test-only-4111", "n": sequence})
            content = EventContent(
                id=str(uuid.UUID(int=sequence)),
                event_type="ORDER_PLACED",
                actor_id=actor,
                resource_type="ORDER",
                resource_id="order-1",
                timestamp=None,
                recorded_at=f"2026-01-01T00:00:0{sequence}.000000Z",
                recorded_by="svc-writer",
                payload=committed.structure,
            )
            previous = chain[-1].record.record_hash if chain else GENESIS_PREVIOUS_HASH
            chain.append(ChainEntry(seal_record(content, sequence, previous), committed.values))
        records = [
            ExportRecord(entry=entry, archived=False, redacted_paths=())
            for entry in chain
            if entry.record.content.actor_id == "actor-a"
        ]
        manifest = Manifest(
            scope={"actorId": "actor-a"},
            as_of_sequence=3,
            as_of_record_hash=chain[-1].record.record_hash,
            generated_at="2026-09-28T12:00:00.000000Z",
            requested_by="auditor-1",
            record_count=len(records),
            records=tuple(
                ManifestRecord(
                    r.entry.record.sequence, r.entry.record.content.id, r.entry.record.record_hash
                )
                for r in records
            ),
            retention=None,
            key_id=key_id(key.public_key()),
        )
        path = tmp_path / "bundle.json"
        path.write_bytes(encode_bundle(manifest, sign_manifest(key, manifest), records))
        return path, [entry.record.record_hash for entry in chain]

    return write


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"


@pytest.fixture
def load_script() -> Callable[[str], ModuleType]:
    """Import a script from scripts/ by file name; the directory is not a package."""

    def load(name: str) -> ModuleType:
        spec = importlib.util.spec_from_file_location(f"scripts_{name}", SCRIPTS_DIR / f"{name}.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    return load


def api_client(app: Any) -> httpx.Client:
    """A TestClient typed as the httpx.Client it subclasses.

    The installed Starlette resolves its client types through `httpx2`, which this project does
    not use, so Pyright cannot see them; at runtime TestClient is an `httpx.Client`.
    """
    return cast(httpx.Client, TestClient(app))  # pyright: ignore[reportUnknownArgumentType]


@pytest.fixture
def make_client() -> Callable[[Any], httpx.Client]:
    return api_client
