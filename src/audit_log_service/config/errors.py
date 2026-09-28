"""Configuration error type."""

from pydantic import ValidationError


class ConfigurationError(Exception):
    """Raised when configuration is missing, unreadable, malformed, or invalid.

    Messages identify the file, entry, and field, but never include configured values such as
    API-key hashes.
    """


def describe_validation_error(error: ValidationError) -> str:
    """Summarize a Pydantic validation error by location and message only, never by input value."""
    problems: list[str] = []
    for detail in error.errors(include_url=False, include_input=False, include_context=False):
        location = ".".join(str(part) for part in detail["loc"]) or "<root>"
        problems.append(f"{location}: {detail['msg']}")
    return "; ".join(problems)
