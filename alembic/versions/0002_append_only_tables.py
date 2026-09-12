"""Make booking_audit and security_events append-only at the database level

"Append-only" enforced by a code comment is a promise. Enforced by the database
it is a property, and that difference is the entire value of an audit trail: it
has to be trustworthy precisely in the case where the application is doing
something it shouldn't.

Two independent mechanisms, deliberately:

1. A BEFORE UPDATE/DELETE trigger that RAISEs. Applies to *every* role including
   the owner, and fails loudly rather than silently discarding the write. (A
   Postgres RULE ... DO INSTEAD NOTHING would report success while dropping the
   statement, which is worse than either allowing or refusing it.)
2. REVOKE UPDATE, DELETE from the application role. Defense in depth: even if a
   migration or a superuser drops the trigger, the role the API connects as
   still cannot modify history.

Recovering from a genuine mistake means an explicit, auditable act by the owner
role (disable trigger, correct, re-enable) rather than an ordinary UPDATE. That
friction is intentional.

Revision ID: 0002_append_only
Revises: 63319fb33306
Create Date: 2026-09-09

"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002_append_only"
down_revision: str | None = "63319fb33306"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Table and role names are module constants, never user input; the f-strings
# below are DDL templating, not query construction. Hence the S608 waivers.
APPEND_ONLY_TABLES = ("booking_audit", "security_events")

# The application role. Kept in sync with docker/initdb/01-roles.sql.
APP_ROLE = "skylock_app"


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION skylock_forbid_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION
                'Table % is append-only; % is not permitted',
                TG_TABLE_NAME, TG_OP
                USING ERRCODE = 'restrict_violation',
                      HINT = 'Correct history by appending a compensating row.';
        END;
        $$ LANGUAGE plpgsql;
        """
    )

    for table in APPEND_ONLY_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER {table}_append_only
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION skylock_forbid_mutation();
            """
        )
        # Ignore a missing role so the migration also runs against a scratch
        # database created without the two-role setup (e.g. some CI runners).
        op.execute(
            f"""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                    REVOKE UPDATE, DELETE ON {table} FROM {APP_ROLE};
                END IF;
            END $$;
            """  # noqa: S608
        )

    # TRUNCATE bypasses row-level triggers entirely, so block it separately.
    for table in APPEND_ONLY_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER {table}_no_truncate
            BEFORE TRUNCATE ON {table}
            FOR EACH STATEMENT EXECUTE FUNCTION skylock_forbid_mutation();
            """
        )
        op.execute(
            f"""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                    REVOKE TRUNCATE ON {table} FROM {APP_ROLE};
                END IF;
            END $$;
            """  # noqa: S608
        )


def downgrade() -> None:
    for table in APPEND_ONLY_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS {table}_no_truncate ON {table};")
        op.execute(f"DROP TRIGGER IF EXISTS {table}_append_only ON {table};")
        op.execute(
            f"""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                    GRANT UPDATE, DELETE ON {table} TO {APP_ROLE};
                END IF;
            END $$;
            """  # noqa: S608
        )
    op.execute("DROP FUNCTION IF EXISTS skylock_forbid_mutation();")
