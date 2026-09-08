#!/bin/bash
# Provision/rotate the shared credential administrator. Run from the trusted
# operator compartment, never the MCP container. --direct uses native psql over
# the configured DB_HOST/DB_PORT (including the Qubes ConnectTCP forwarder).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="${COMPOSE_DIR:-$(cd "$SCRIPT_DIR/../deploy/compose-local" && pwd)}"
mode="${1:-compose}"
case "$mode" in
  compose|--direct) ;;
  *) echo "usage: COMPOSE_DIR=deployment-dir $0 [--direct]" >&2; exit 2;;
esac
[[ $# -le 1 ]] || { echo "unexpected argument" >&2; exit 2; }
cd "$COMPOSE_DIR"
[[ -f .env ]] || { echo "[upgrade-token-admin] .env not found" >&2; exit 1; }
set -a
# shellcheck disable=SC1091
. .env
set +a
: "${OPENBRAIN_TOKEN_ADMIN_PASSWORD:?set OPENBRAIN_TOKEN_ADMIN_PASSWORD in .env first}"

if [[ "$mode" == "--direct" ]]; then
  : "${DB_HOST:?set DB_HOST to the database/ConnectTCP forwarder}"
  : "${POSTGRES_PASSWORD:?set the migration credential POSTGRES_PASSWORD}"
  export PGPASSWORD="$POSTGRES_PASSWORD"
  psql_cmd=(psql -X -h "$DB_HOST" -p "${DB_PORT:-5432}"
    -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-openbrain}")
else
  compose_cmd=(docker compose --env-file .env)
  if ! "${compose_cmd[@]}" ps --status=running postgres | grep -q postgres; then
    echo "[upgrade-token-admin] no running postgres service; use --direct for an external database" >&2
    exit 1
  fi
  # Pass the environment NAME only, never the password in docker/psql argv.
  psql_cmd=("${compose_cmd[@]}" exec -T -e OPENBRAIN_TOKEN_ADMIN_PASSWORD postgres
    psql -X -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-openbrain}")
fi

# PostgreSQL reads the password from its process environment. Literal quoting
# is done by psql, not shell interpolation. --quiet suppresses command tags;
# errors do not include the generated password statement (ON_ERROR_STOP only).
"${psql_cmd[@]}" -q -v ON_ERROR_STOP=1 <<'SQL'
\getenv token_admin_password OPENBRAIN_TOKEN_ADMIN_PASSWORD
BEGIN;
SELECT 'CREATE ROLE openbrain_token_admin NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openbrain_token_admin')
\gexec
ALTER ROLE openbrain_token_admin WITH LOGIN NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'token_admin_password';
COMMIT;
SQL

echo "[upgrade-token-admin] LOGIN, password and restricted privilege flags reconciled"
echo "[upgrade-token-admin] apply migrations 08, 13 and 14 plus the final grants assertion; install the role-scoped HBA entries on a split database"
