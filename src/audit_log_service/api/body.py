"""Reading JSON request bodies with the approved limits (Phase 5 decisions D1 and D4).

The body is read explicitly, after authentication and authorization, rather than by FastAPI's body
parameters. That keeps the D4 check order, and lets duplicate object keys be detected: the standard
JSON parser would silently keep the last one.
"""

import json
from typing import Any

from fastapi import Request

MAX_BODY_BYTES = 64 * 1024


class BodyError(Exception):
    """A request body could not be accepted. `status` is the HTTP status to return."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


class _DuplicateKeyError(ValueError):
    pass


async def read_json_body(request: Request) -> object:
    """Return the decoded JSON document, or raise `BodyError` with 415, 413, 400, or 422."""
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media_type != "application/json":
        raise BodyError(415, "The request body must be application/json.")

    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise BodyError(413, "The request body exceeds 64 KiB.")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise BodyError(413, "The request body exceeds 64 KiB.")

    try:
        return json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except _DuplicateKeyError:
        raise BodyError(422, "The request body contains a duplicate JSON object key.") from None
    except RecursionError:
        raise BodyError(422, "The request body is nested too deeply.") from None
    except ValueError:
        # Covers invalid UTF-8, JSON syntax errors, and NaN or Infinity literals.
        raise BodyError(400, "The request body is not valid JSON.") from None


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise _DuplicateKeyError
        document[key] = value
    return document


def _reject_constant(_name: str) -> float:
    raise ValueError("non-finite number literal")
