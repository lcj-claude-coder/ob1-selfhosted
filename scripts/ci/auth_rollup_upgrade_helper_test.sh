#!/usr/bin/env bash
# Exercise the external/native-Postgres branch of the auth-rollup role helper
# without a real deployment. The DB-init smokes separately execute the role and
# grant SQL against Postgres; this pins secret confinement and target argv.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/ob1-auth-rollup-helper.XXXXXX")"
trap 'rm -rf -- "$test_root"' EXIT

deploy_dir="$test_root/deploy"
fake_bin="$test_root/bin"
install -d -m 0700 "$deploy_dir" "$fake_bin"

{
  printf 'DB_HOST=127.0.0.1\n'
  printf 'DB_PORT=55439\n'
  printf 'POSTGRES_USER=postgres\n'
  printf 'POSTGRES_DB=openbrain\n'
  printf 'POSTGRES_PASSWORD=ci-helper-admin-secret\n'
  printf 'OPENBRAIN_AUTH_ROLLUP_PASSWORD=ci-helper-rollup-secret\n'
  printf 'export OPENBRAIN_APP_PASSWORD=must-not-reach-psql\n'
  printf 'export OPENBRAIN_READONLY_PASSWORD=must-not-reach-psql\n'
  printf 'export OPENBRAIN_TOKEN_ADMIN_PASSWORD=must-not-reach-psql\n'
} > "$deploy_dir/.env"
chmod 0600 "$deploy_dir/.env"

cat > "$fake_bin/psql" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

[[ "${PGPASSWORD:-}" == ci-helper-admin-secret ]]
[[ "${OPENBRAIN_AUTH_ROLLUP_PASSWORD:-}" == ci-helper-rollup-secret ]]
for forbidden in OPENBRAIN_APP_PASSWORD OPENBRAIN_READONLY_PASSWORD \
  OPENBRAIN_TOKEN_ADMIN_PASSWORD; do
  [[ ! -v "$forbidden" ]]
done

argv=" $* "
[[ "$argv" == *" -X "* ]]
[[ "$argv" == *" -w "* ]]
[[ "$argv" == *" -h 127.0.0.1 "* ]]
[[ "$argv" == *" -p 55439 "* ]]
[[ "$argv" == *" -U postgres "* ]]
[[ "$argv" == *" -d openbrain "* ]]
[[ "$argv" != *"ci-helper-admin-secret"* ]]
[[ "$argv" != *"ci-helper-rollup-secret"* ]]

sql=
while IFS= read -r line || [[ -n "$line" ]]; do
  sql+="$line"$'\n'
done
[[ "$sql" == *"\\getenv auth_rollup_password OPENBRAIN_AUTH_ROLLUP_PASSWORD"* ]]
[[ "$sql" == *"CREATE ROLE openbrain_auth_rollup NOLOGIN NOSUPERUSER"* ]]
[[ "$sql" == *"ALTER ROLE openbrain_auth_rollup LOGIN NOSUPERUSER"* ]]
[[ "$sql" == *"PASSWORD :'auth_rollup_password'"* ]]
SH
chmod 0755 "$fake_bin/psql"

PATH="$fake_bin:$PATH" \
  bash "$REPO_ROOT/scripts/upgrade-enable-auth-rollup-role.sh" "$deploy_dir" \
  | grep -Fq "role provisioned"

echo "auth-rollup upgrade helper confined secrets and targeted external Postgres"
