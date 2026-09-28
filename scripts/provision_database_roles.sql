-- Owner-run provisioning of the audit log's database roles (ADR-0009).
--
-- Run once per PostgreSQL server, as a role with CREATEROLE, before `alembic upgrade head`.
-- Roles are server-wide, so migrations do not create them. The script is idempotent.
--
-- It creates only the NOLOGIN group role that the migrations grant privileges to. Login users are
-- created outside source control, with a password set out of band, as members of this role:
--   CREATE ROLE <login_user> LOGIN IN ROLE audit_log_app;  -- then set its password separately
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_log_app') THEN
        CREATE ROLE audit_log_app NOLOGIN;
    END IF;
END
$$;
