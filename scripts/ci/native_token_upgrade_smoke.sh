#!/usr/bin/env bash
# Disposable DB-init fixture only. Downgrade to 1.26's token schema, then test
# startup refusal, transaction rollback, replay, row preservation and ACL drift.
set -euo pipefail
: "${CI_REPO_ROOT:?run through run_db_init_smokes.sh}"
: "${DB_INIT_CONTAINER:?disposable container required}"
source "$CI_REPO_ROOT/scripts/ci/db_init_common.sh"
super_psql -tAc 'SELECT count(*)=0 FROM native_auth.access_token' | grep -qx t
super_psql -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
DROP FUNCTION native_auth.register_access_token(TEXT,BYTEA,TEXT,TEXT);
ALTER TABLE native_auth.access_token DROP COLUMN principal;
SQL
apply_sql db/08-access-tokens.sql >/dev/null
super_psql -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO native_auth.access_token(prefix,token_hash,label,created_at,revoked_at) VALUES
('ob1_LEGACY01',decode(repeat('77',32),'hex'),'legacy active','2026-01-01Z',NULL),
('ob1_LEGACY02',decode(repeat('88',32),'hex'),'legacy revoked','2026-01-01Z','2026-01-02Z');
SQL
run_deno_db_smoke server/native_token_upgrade_db_smoke.ts legacy
{
  echo 'BEGIN;'
  cat db/14-native-token-principals.sql db/03-grants-assertion.sql
  echo 'ROLLBACK;'
} | super_psql -v ON_ERROR_STOP=1 >/dev/null
super_psql -tAc "SELECT NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='native_auth.access_token'::regclass AND attname='principal' AND NOT attisdropped)" | grep -qx t
for attempt in 1 2; do
  apply_sql db/14-native-token-principals.sql >/dev/null
  apply_sql db/03-grants-assertion.sql >/dev/null
done
run_deno_db_smoke server/native_token_upgrade_db_smoke.ts ready
# Replaying only the older migration must not silently reopen principal-less
# registration while the new server is running against the same catalog.
apply_sql db/08-access-tokens.sql >/dev/null
run_deno_db_smoke server/native_token_upgrade_db_smoke.ts legacy
apply_sql db/14-native-token-principals.sql >/dev/null
apply_sql db/03-grants-assertion.sql >/dev/null
super_psql -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
DO $$ BEGIN
  IF (SELECT count(*) FROM native_auth.access_token WHERE principal IS NULL) <> 2
     OR NOT EXISTS(SELECT 1 FROM native_auth.access_token WHERE prefix='ob1_LEGACY01' AND revoked_at IS NULL)
     OR NOT EXISTS(SELECT 1 FROM native_auth.access_token WHERE prefix='ob1_LEGACY02' AND revoked_at='2026-01-02Z') THEN
    RAISE EXCEPTION 'legacy identity/revocation state changed during upgrade';
  END IF;
END $$;
DELETE FROM native_auth.access_token WHERE prefix IN ('ob1_LEGACY01','ob1_LEGACY02');
SQL
# A widened identity write grant must fail assertion, then converge on replay.
for role in openbrain_token_admin openbrain_readonly; do
  super_psql -c "GRANT UPDATE(principal) ON native_auth.access_token TO $role" >/dev/null
  if apply_sql db/03-grants-assertion.sql > /dev/null 2>&1; then
    echo "assertion accepted principal mutation by $role" >&2; exit 1
  fi
  apply_sql db/14-native-token-principals.sql >/dev/null
  apply_sql db/03-grants-assertion.sql >/dev/null
done
super_psql -c 'REVOKE SELECT(principal) ON native_auth.access_token FROM openbrain_app' >/dev/null
run_deno_db_smoke server/native_token_upgrade_db_smoke.ts unreadable
apply_sql db/14-native-token-principals.sql >/dev/null
apply_sql db/03-grants-assertion.sql >/dev/null
run_deno_db_smoke server/native_token_upgrade_db_smoke.ts ready
echo 'native-token migration rollback/replay, legacy preservation, boot checks and principal grant reconciliation passed'
