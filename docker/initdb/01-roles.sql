-- Runs once, on first container start, as the superuser.
--
-- Two roles on purpose:
--   skylock_owner -> owns the schema, runs migrations, can ALTER/REVOKE
--   skylock_app   -> what the API connects as; deliberately cannot UPDATE or
--                    DELETE the append-only tables (see migration 0002)
--
-- This is what makes "the audit log is immutable" a property of the database
-- rather than a promise in a code comment.

CREATE ROLE skylock_app WITH LOGIN PASSWORD 'skylock_app';

GRANT CONNECT ON DATABASE skylock TO skylock_app;
GRANT USAGE ON SCHEMA public TO skylock_app;

-- Default privileges for tables the owner creates later, during migrations.
ALTER DEFAULT PRIVILEGES FOR ROLE skylock_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO skylock_app;
ALTER DEFAULT PRIVILEGES FOR ROLE skylock_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO skylock_app;
