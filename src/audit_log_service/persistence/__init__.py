"""PostgreSQL persistence for the audit log (ADR-0003, ADR-0004, ADR-0009).

The write operations are the serialized append and, for redaction, deletion of recoverable
payload values and their salts. There is no update or delete of audit records.
"""
