#!/bin/sh
set -eu

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname postgres <<-SQL
  DO \$\$
  BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${TRACKER_DB_USER}') THEN
      CREATE ROLE ${TRACKER_DB_USER} LOGIN PASSWORD '${TRACKER_DB_PASSWORD}';
    END IF;
  END
  \$\$;
  SELECT 'CREATE DATABASE ${TRACKER_DB_NAME} OWNER ${TRACKER_DB_USER}'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${TRACKER_DB_NAME}')\gexec
SQL

# Keep this script idempotent so an existing native-only installation can
# provision the optional database without replacing its PostgreSQL volume.
case "${TRACKER_DEPENDENCY_TRACK_ENABLED:-false}" in
  true|TRUE|1|yes|YES|on|ON)
    : "${DTRACK_DB_PASSWORD:?DTRACK_DB_PASSWORD is required when Dependency-Track is enabled}"
    psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname postgres <<-SQL
      DO \$\$
      BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DTRACK_DB_USER}') THEN
          CREATE ROLE ${DTRACK_DB_USER} LOGIN PASSWORD '${DTRACK_DB_PASSWORD}';
        END IF;
      END
      \$\$;
      SELECT 'CREATE DATABASE ${DTRACK_DB_NAME} OWNER ${DTRACK_DB_USER}'
        WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DTRACK_DB_NAME}')\gexec
SQL
    ;;
esac
