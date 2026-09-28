"""PostgreSQL persistence for the audit log (ADR-0003, ADR-0004, ADR-0009).

The only write operation is the serialized append. There is no update or delete of audit records.
"""
