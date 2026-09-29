-- DEMONSTRATION ONLY: the tamper actor for the Scenario A and checkpoint demonstrations
-- (requirements §9 Scenario A, ADR-0009, Phase 12 decision P5). Never provision it in production.
--
-- Run as the schema owner, after `alembic upgrade head` (the grants need the tables). Idempotent.
--
-- `audit_log_tamper` is a NOLOGIN group role that can change audit data directly, outside the
-- application. It is deliberately not a superuser and holds none of the server-file or program
-- roles, so it cannot write files on the database host, such as a checkpoint store (ADR-0009).
-- scripts/tamper_demo.py switches to it with SET ROLE and refuses to run if any of this is not so.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_log_tamper') THEN
        CREATE ROLE audit_log_tamper NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO audit_log_tamper;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_records, audit_payload_values TO audit_log_tamper;

DO $$
BEGIN
    IF EXISTS (
        SELECT FROM pg_roles
        WHERE rolname = 'audit_log_tamper'
          AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls OR rolcanlogin)
    ) OR pg_has_role('audit_log_tamper', 'pg_write_server_files', 'MEMBER')
      OR pg_has_role('audit_log_tamper', 'pg_execute_server_program', 'MEMBER')
      OR pg_has_role('audit_log_tamper', 'pg_read_server_files', 'MEMBER')
    THEN
        RAISE EXCEPTION 'audit_log_tamper must be a NOLOGIN, non-superuser role without server-file or program roles';
    END IF;
END
$$;
