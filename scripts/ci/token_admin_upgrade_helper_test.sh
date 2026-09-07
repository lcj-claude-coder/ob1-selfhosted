#!/usr/bin/env bash
# Hermetic argument/secret-boundary checks for both administrator transports.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work=$(mktemp -d "${TMPDIR:-/tmp}/ob1-admin-helper.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/bin" "$work/deploy"
cat > "$work/deploy/.env" <<'ENV'
OPENBRAIN_TOKEN_ADMIN_PASSWORD='fixture-admin-pass'
POSTGRES_PASSWORD='fixture-owner-pass'
DB_HOST=127.0.0.1
DB_PORT=55439
POSTGRES_DB=openbrain
ENV
chmod 600 "$work/deploy/.env"
cat > "$work/bin/psql" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > "$CAPTURE_DIR/args"
cat > "$CAPTURE_DIR/sql"
[[ "$OPENBRAIN_TOKEN_ADMIN_PASSWORD" == fixture-admin-pass ]]
[[ "$PGPASSWORD" == fixture-owner-pass ]]
MOCK
cat > "$work/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *" ps "* ]]; then
  echo postgres
  exit 0
fi
printf '%s\n' "$@" > "$CAPTURE_DIR/args"
cat > "$CAPTURE_DIR/sql"
[[ "$OPENBRAIN_TOKEN_ADMIN_PASSWORD" == fixture-admin-pass ]]
MOCK
chmod +x "$work/bin/psql" "$work/bin/docker"
export CAPTURE_DIR="$work"
for mode in compose --direct; do
  PATH="$work/bin:$PATH" COMPOSE_DIR="$work/deploy" \
    bash "$repo_root/scripts/upgrade-enable-token-admin-role.sh" "$mode" > "$work/output" 2>&1
  if grep -qE 'fixture-(admin|owner)-pass' "$work/args" "$work/sql" "$work/output"; then
    echo "administrator password appeared in argv, SQL stream, or output" >&2
    exit 1
  fi
  grep -qF '\getenv token_admin_password OPENBRAIN_TOKEN_ADMIN_PASSWORD' "$work/sql"
  grep -qF 'BEGIN;' "$work/sql"
  grep -qF 'COMMIT;' "$work/sql"
  grep -qF 'NOREPLICATION NOBYPASSRLS' "$work/sql"
  if [[ "$mode" == --direct ]]; then
    grep -qxF '127.0.0.1' "$work/args"
    grep -qxF '55439' "$work/args"
  else
    grep -qxF 'OPENBRAIN_TOKEN_ADMIN_PASSWORD' "$work/args"
  fi
done
echo "credential administrator helper: both transports preserve transaction and password boundaries"
