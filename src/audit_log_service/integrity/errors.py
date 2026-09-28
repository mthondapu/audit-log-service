"""Integrity input error type."""


class IntegrityInputError(ValueError):
    """Raised when a value cannot enter a hash input.

    Messages are fixed descriptions of the problem and never include the offending value, so that
    payload content, salts, and identifiers cannot leak through errors or logs.
    """
