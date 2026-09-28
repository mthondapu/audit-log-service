"""Scaffolding smoke test: the package is installed and importable."""

import audit_log_service


def test_package_is_importable() -> None:
    assert audit_log_service.__name__ == "audit_log_service"
