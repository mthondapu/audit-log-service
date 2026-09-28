-- Owner-run provisioning of the audit log's database roles (ADR-0009).
--
-- Run once per PostgreSQL server, as a role with CREATEROLE, before `alembic upgrade head`.
-- Roles are server-wide, so migrations do not create them. The script is idempotent.
--
-- It creates only the NOLOGIN group roles that the migrations grant privileges to:
--   audit_log_app         the service (ADR-0009);
--   audit_log_checkpoint  the checkpoint CLI, read-only (ADR-0009 D4, requirements FR-4).
-- Login users are created outside source control, with a password set out of band, as members of
-- one of these roles:
--   CREATE ROLE <login_user> LOGIN IN ROLE audit_log_app;  -- then set its password separately
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_log_app') THEN
        CREATE ROLE audit_log_app NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_log_checkpoint') THEN
        CREATE ROLE audit_log_checkpoint NOLOGIN;
    END IF;
END
$$;
