"""Tests for canonical timestamp text (YYYY-MM-DDTHH:MM:SS.ffffffZ)."""

from datetime import UTC, datetime, timedelta, timezone

import pytest
from hypothesis import given
from hypothesis import strategies as st

from audit_log_service.integrity.errors import IntegrityInputError
from audit_log_service.integrity.timestamps import (
    format_timestamp,
    is_canonical_timestamp,
    parse_timestamp,
)


@pytest.mark.parametrize(
    ("moment", "expected"),
    [
        (datetime(2026, 9, 28, 16, 17, 6, 919000, tzinfo=UTC), "2026-09-28T16:17:06.919000Z"),
        (
            datetime(2026, 9, 28, 18, 0, tzinfo=timezone(timedelta(hours=2))),
            "2026-09-28T16:00:00.000000Z",
        ),
        (datetime(1, 1, 1, tzinfo=UTC), "0001-01-01T00:00:00.000000Z"),
    ],
    ids=["utc", "offset-normalized", "four-digit-year"],
)
def test_format_normalizes_to_utc_with_six_fractional_digits(
    moment: datetime, expected: str
) -> None:
    assert format_timestamp(moment) == expected


def test_naive_datetime_is_rejected() -> None:
    with pytest.raises(IntegrityInputError, match="timezone-aware"):
        format_timestamp(datetime(2026, 9, 28, 16, 0))


@pytest.mark.parametrize(
    "text",
    [
        "2026-09-28T16:17:06.919Z",
        "2026-09-28T16:17:06.9190000Z",
        "2026-09-28T16:17:06Z",
        "2026-09-28T16:17:06.919000+00:00",
        "2026-09-28T16:17:06.919000z",
        "2026-09-28 16:17:06.919000Z",
        "2026-02-30T16:17:06.919000Z",
        "2026-09-28T24:00:00.000000Z",
        " 2026-09-28T16:17:06.919000Z",
        "",
    ],
)
def test_non_canonical_text_is_rejected(text: str) -> None:
    assert not is_canonical_timestamp(text)
    with pytest.raises(IntegrityInputError):
        parse_timestamp(text)


def test_non_string_is_not_canonical() -> None:
    assert not is_canonical_timestamp(None)


_offsets = st.builds(
    timezone, st.timedeltas(min_value=timedelta(hours=-23), max_value=timedelta(hours=23))
)


@given(
    moment=st.datetimes(
        min_value=datetime(2, 1, 1), max_value=datetime(9998, 12, 31), timezones=_offsets
    )
)
def test_formatted_text_is_canonical_and_round_trips(moment: datetime) -> None:
    text = format_timestamp(moment)

    assert is_canonical_timestamp(text)
    assert parse_timestamp(text) == moment
    assert format_timestamp(parse_timestamp(text)) == text
