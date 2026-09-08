#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${CI_REPO_ROOT:-}" || -z "${DB_INIT_CONTAINER:-}" ]]; then
  exec "$SCRIPT_DIR/run_db_init_smokes.sh" auth
fi
# Resolved relative to this script at runtime.
# shellcheck disable=SC1091
source "$SCRIPT_DIR/db_init_common.sh"

phase="${1:-all}"
case "$phase" in
  all|tokens|subjects|audit) ;;
  *)
    echo "usage: ${0##*/} [all|tokens|subjects|audit]" >&2
    exit 2
    ;;
esac

if [[ "$phase" == "all" || "$phase" == "tokens" ]]; then
smoke_step "Smoke test — native token lifecycle is hash-only and least-privilege"
bash scripts/ci/native_token_upgrade_smoke.sh
# Reapply the migration to pin the existing-database/idempotency path,
# re-check catalog grants, then exercise register/list/revoke through
# the real dedicated and application roles inside a rollback.
apply_sql db/08-access-tokens.sql >/dev/null
apply_sql db/14-native-token-principals.sql >/dev/null
apply_sql db/03-grants-assertion.sql >/dev/null
apply_sql db/access-tokens-smoke.sql >/dev/null
run_deno_db_smoke server/access_tokens_db_smoke.ts
run_deno_db_smoke server/native_token_scope_db_smoke.ts
echo "native token registration, driver hashing, redacted listing, one-way revocation, and grants passed"
fi

if [[ "$phase" == "all" || "$phase" == "audit" ]]; then
smoke_step "Smoke test — auth audit emitter records both outcomes end-to-end"
# Reapply the observability migration first to pin its documented
# in-place convergence on a live database, then drive the REAL
# auth_audit.ts emitter as openbrain_app through every row shape
# the middleware emits (all unit tests run it disabled), and pin
# the row-shape constraints via the malformed inserts.
apply_sql db/02-observability.sql >/dev/null
run_deno_db_smoke server/auth_audit_db_smoke.ts
smoke_step "Smoke test — pre-1.20 audit shape: refusal, migration, acceptance"
# The emitter smoke above proves fresh-install + idempotent replay;
# this one pins the load-bearing LEGACY convergence a real pre-1.20
# deployment goes through. It clones the initialized database
# (TEMPLATE, so every other schema contract is present), downgrades
# mcp_auth_events to the denied-only shape with legacy rows, and
# runs the full operator sequence: the REAL boot probe refuses with
# migration guidance -> db/02 converges the clone in place -> the
# probe accepts, the legacy rows survive backfilled as denied with
# reasons preserved, and the app role lands an allowed row.
UPGRADE_SMOKE_PHASE=refuse \
  run_deno_db_smoke server/auth_audit_upgrade_db_smoke.ts
super_psql_db openbrain_upgrade -v ON_ERROR_STOP=1 \
  < db/02-observability.sql >/dev/null
UPGRADE_SMOKE_PHASE=accept \
  run_deno_db_smoke server/auth_audit_upgrade_db_smoke.ts
smoke_step "Smoke test — middleware-to-audit seam lands the exact rows"
# Round-3 mutation testing showed the auth.ts -> auth_audit.ts
# wiring could regress silently (emitter calls removed or reason
# codes swapped) while every unit test stays green, because the
# middleware suites run with auditing disabled. This drives the
# REAL requireAuth over real RS256 tokens against the live database
# and asserts the exact rows per credential scenario, including
# subject_not_allowed precedence over the dual-credential collapse.
run_deno_db_smoke server/auth_middleware_audit_db_smoke.ts
fi

if [[ "$phase" == "all" || "$phase" == "subjects" ]]; then
smoke_step "Smoke test — OAuth admission, immediate revoke, and atomic legacy import"
# Remove only this disposable fixture's new schema to rehearse a real upgrade.
# The rollback must restore the pre-migration catalog with no half-installed gate.
super_psql -v ON_ERROR_STOP=1 -c 'DROP SCHEMA oauth_auth CASCADE' >/dev/null
{
  echo 'BEGIN;'
  cat db/13-oauth-subjects.sql db/03-grants-assertion.sql
  echo 'ROLLBACK;'
} | super_psql -v ON_ERROR_STOP=1 >/dev/null
super_psql -v ON_ERROR_STOP=1 -tAc \
  "SELECT to_regclass('oauth_auth.allowed_subject') IS NULL" | grep -qx t
apply_sql db/13-oauth-subjects.sql >/dev/null
apply_sql db/03-grants-assertion.sql >/dev/null
# Reconcile the dedicated role via the actual psql helper; test both initial
# enablement and reapply without copying real operator credentials.
super_psql -v ON_ERROR_STOP=1 -c \
  'ALTER ROLE openbrain_token_admin NOLOGIN CREATEDB' >/dev/null
docker exec "$DB_INIT_CONTAINER" mkdir -p /tmp/credential-admin-fixture
docker exec -i "$DB_INIT_CONTAINER" sh -c 'cat > /tmp/credential-admin-fixture/upgrade.sh' \
  < scripts/upgrade-enable-token-admin-role.sh
docker exec "$DB_INIT_CONTAINER" touch /tmp/credential-admin-fixture/.env
for attempt in 1 2; do
  docker exec -e COMPOSE_DIR=/tmp/credential-admin-fixture -e DB_HOST=127.0.0.1 \
    "$DB_INIT_CONTAINER" bash /tmp/credential-admin-fixture/upgrade.sh --direct
done
super_psql -v ON_ERROR_STOP=1 -tAc \
  "SELECT rolcanlogin AND NOT rolcreatedb FROM pg_roles WHERE rolname='openbrain_token_admin'" | grep -qx t
apply_sql db/03-grants-assertion.sql >/dev/null
run_deno_db_smoke server/oauth_subjects_db_smoke.ts
fi
