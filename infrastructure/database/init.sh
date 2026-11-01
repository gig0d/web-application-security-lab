#!/bin/sh
set -eu
# Password is generated as hex by scripts.lab; psql still quotes it as a SQL literal.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set=app_password="$APP_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE aegis_app LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT', :'app_password') \gexec
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE TEMPORARY ON DATABASE harbordesk FROM PUBLIC;
ALTER ROLE aegis_app SET statement_timeout = '2s';
ALTER ROLE aegis_app SET lock_timeout = '1s';
ALTER ROLE aegis_app SET idle_in_transaction_session_timeout = '5s';
SQL
