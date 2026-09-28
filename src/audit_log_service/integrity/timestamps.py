"""Canonical timestamp text for hash inputs (requirements §3 row 2, ADR-0002).

The only accepted form is ``YYYY-MM-DDTHH:MM:SS.ffffffZ``: UTC, exactly six fractional digits, and
a ``Z`` suffix. Hash inputs are never normalized silently; text in any other form is rejected.
"""

import re
from datetime import UTC, datetime

from audit_log_service.integrity.errors import IntegrityInputError

_CANONICAL = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")
_PARSE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def format_timestamp(moment: datetime) -> str:
    """Render a timezone-aware datetime as canonical UTC text with microsecond precision."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise IntegrityInputError("timestamp must be timezone-aware")
    utc = moment.astimezone(UTC).replace(tzinfo=None)
    return utc.isoformat(timespec="microseconds") + "Z"


def parse_timestamp(text: str) -> datetime:
    """Parse canonical timestamp text into an aware UTC datetime, rejecting any other form."""
    if _CANONICAL.fullmatch(text) is None:
        raise IntegrityInputError("timestamp is not in canonical form")
    try:
        naive = datetime.strptime(text, _PARSE_FORMAT)
    except ValueError:
        raise IntegrityInputError("timestamp is not a valid date and time") from None
    return naive.replace(tzinfo=UTC)


def is_canonical_timestamp(text: object) -> bool:
    """Whether a value is canonical timestamp text denoting a real date and time."""
    if not isinstance(text, str):
        return False
    try:
        parse_timestamp(text)
    except IntegrityInputError:
        return False
    return True
