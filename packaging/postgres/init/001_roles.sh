#!/bin/bash
# Harness Postgres bootstrap: lane roles + passwords, from container env.
# Runs FIRST in docker-entrypoint-initdb.d (001_* < 002_schemas.sql) because
# 002's GRANT statements require these roles to already exist — with
# ON_ERROR_STOP=1 a missing role would fail the whole init.
#
# All roles are LOGIN roles: each lane authenticates as itself, so journal
# attribution can derive from the authenticated identity, not self-report.
# No lane holds DELETE on journal/evidence — enforcement lives in
# owner-executed SECURITY DEFINER functions (003_functions.sql); only
# harness_operator may run engagement.purge().
set -e

HARNESS_DB_OPERATOR_PASSWORD="${HARNESS_DB_OPERATOR_PASSWORD:-harness_operator_change_me}"
HARNESS_DB_BRAIN_PASSWORD="${HARNESS_DB_BRAIN_PASSWORD:-harness_brain_change_me}"
HARNESS_DB_GATEWAY_PASSWORD="${HARNESS_DB_GATEWAY_PASSWORD:-harness_gateway_change_me}"
HARNESS_DB_REPL_PASSWORD="${HARNESS_DB_REPL_PASSWORD:-harness_repl_change_me}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Operator session: the only role allowed to run engagement.purge().
    -- Superuser-free on purpose; members of the entrypoint superuser can
    -- still do anything, which is fine — those creds never leave the host.
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'harness_operator') THEN
            CREATE ROLE harness_operator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
        END IF;
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'brain_lane') THEN
            CREATE ROLE brain_lane LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
        END IF;
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gateway_lane') THEN
            CREATE ROLE gateway_lane LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
        END IF;
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'repl_lane') THEN
            CREATE ROLE repl_lane LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
        END IF;
    END
    \$\$;

    ALTER ROLE harness_operator PASSWORD '$HARNESS_DB_OPERATOR_PASSWORD';
    ALTER ROLE brain_lane       PASSWORD '$HARNESS_DB_BRAIN_PASSWORD';
    ALTER ROLE gateway_lane     PASSWORD '$HARNESS_DB_GATEWAY_PASSWORD';
    ALTER ROLE repl_lane        PASSWORD '$HARNESS_DB_REPL_PASSWORD';

    -- Connect rights on this database (init scripts run after the db exists).
    GRANT CONNECT ON DATABASE "${POSTGRES_DB}" TO harness_operator, brain_lane, gateway_lane, repl_lane;
EOSQL