#!/usr/bin/env bash
# Provision or rotate the dedicated corpus auth-event rollup role in an
# existing database. Fresh databases create it in db/00-roles.sh;
# docker-entrypoint init scripts do not rerun for an existing volume. A blank
# DB_HOST selects the in-Compose postgres service; a nonblank DB_HOST selects
# the external/native Postgres used by the split-Qubes deployment.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="${1:-$SCRIPT_DIR/../deploy/compose-local}"
DEPLOY_DIR="$(cd "$DEPLOY_DIR" && pwd)"
ENV_FILE="$DEPLOY_DIR/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[upgrade-auth-rollup] missing $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
. "$ENV_FILE"

: "${OPENBRAIN_AUTH_ROLLUP_PASSWORD:?set OPENBRAIN_AUTH_ROLLUP_PASSWORD in .env before running this upgrade}"
AUTH_ROLLUP_PASSWORD="$OPENBRAIN_AUTH_ROLLUP_PASSWORD"
DB_HOST="${DB_HOST:-}"
DB_PORT="${DB_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-openbrain}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"

# Strip every deployment secret before the first child. Each database client
# below receives only its authentication password plus the new role password;
# the latter is retrieved with \getenv and never appears in an argv.
export -n POSTGRES_PASSWORD OPENBRAIN_APP_PASSWORD \
  OPENBRAIN_READONLY_PASSWORD OPENBRAIN_TOKEN_ADMIN_PASSWORD \
  OPENBRAIN_AUTH_ROLLUP_PASSWORD 2>/dev/null || true

provision_role() {
  "$@" <<'EOSQL'
\getenv auth_rollup_password OPENBRAIN_AUTH_ROLLUP_PASSWORD
DO $provision$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'openbrain_auth_rollup'
  ) THEN
    CREATE ROLE openbrain_auth_rollup NOLOGIN NOSUPERUSER NOCREATEDB
      NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END;
$provision$;
ALTER ROLE openbrain_auth_rollup LOGIN NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'auth_rollup_password';
EOSQL
}

if [[ -n "$DB_HOST" ]]; then
  : "${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env for an external database}"
  command -v psql >/dev/null || {
    echo "[upgrade-auth-rollup] psql is required for external DB_HOST=$DB_HOST" >&2
    exit 1
  }
  provision_role env -i PATH="$PATH" \
    PGPASSWORD="$POSTGRES_PASSWORD" \
    OPENBRAIN_AUTH_ROLLUP_PASSWORD="$AUTH_ROLLUP_PASSWORD" \
    psql -X -w -v ON_ERROR_STOP=1 -h "$DB_HOST" -p "$DB_PORT" \
    -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f -
else
  cd "$DEPLOY_DIR"
  compose_cmd=(docker compose --env-file .env)

  if ! "${compose_cmd[@]}" ps --status=running postgres | grep -q postgres; then
    echo "[upgrade-auth-rollup] postgres service is not running in $DEPLOY_DIR" >&2
    exit 1
  fi

  export OPENBRAIN_AUTH_ROLLUP_PASSWORD="$AUTH_ROLLUP_PASSWORD"
  # The inner shell, not this host shell, expands its positional parameters.
  # shellcheck disable=SC2016
  provision_role \
    "${compose_cmd[@]}" exec -T -e OPENBRAIN_AUTH_ROLLUP_PASSWORD postgres \
    sh -eu -c \
    'exec psql -X -v ON_ERROR_STOP=1 -U "$1" -d "$2" -f -' \
    auth-rollup-provision "$POSTGRES_USER" "$POSTGRES_DB"
fi

unset AUTH_ROLLUP_PASSWORD OPENBRAIN_AUTH_ROLLUP_PASSWORD POSTGRES_PASSWORD
echo "[upgrade-auth-rollup] role provisioned; next apply db/12-auth-audit-grants.sql, then db/03-grants-assertion.sql"
