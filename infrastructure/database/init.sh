#!/bin/sh
set -eu
# Password is generated as hex by scripts.lab; psql still quotes it as a SQL literal.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set=app_password="$APP_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE aegis_app LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT', :'app_password') \gexec
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE TEMPORARY ON DATABASE harbordesk FROM PUBLIC;
SQL
