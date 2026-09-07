# OAuth subject admission

A valid issuer signature proves who minted a token. Open Brain separately checks
whether the operator admitted its exact, case-sensitive `sub`. Admission now
lives in `oauth_auth.allowed_subject`; every Bearer request reads the current
row after signature, issuer, audience, expiration and subject validation. A
missing or revoked row is rejected with the usual uniform 401. A database error
also fails closed. No admission decision is cached.

Use the operator-only `subject-admin` CLI on the trusted application host. It
uses the same `openbrain_token_admin` credential as `token-admin`. There is no
new HTTP or MCP administration endpoint, listener, or authentication provider.
The runtime receives only the application password and SELECT on the four
verification columns. The administrator can list admission metadata and invoke
fixed-search-path functions; it cannot read memories or token hashes, or
directly change the tables. Backups include subject labels, kinds and revocation
state.

## Commands

After provisioning the administrator below, run from the deployment directory:

```bash
docker compose --profile tools run --rm subject-admin allow 'issuer|operator' user 'Operator'
docker compose --profile tools run --rm subject-admin allow 'worker@clients' service 'Scheduled worker'
docker compose --profile tools run --rm subject-admin list --json
docker compose --profile tools run --rm subject-admin revoke 'worker@clients'
```

Subjects are identities, never tokens or client secrets. Obtain and verify the
exact subject as described in
[service accounts](service-account-oauth-client.md). Quote subjects in the
shell, including ones containing `|`. Labels are optional. `allow` also updates
the label/kind of an existing entry and **explicitly re-enrolls a revoked
entry**. `revoke` preserves its row and timestamps and takes effect on the next
request; already admitted in-flight requests may finish. Repeated revoke or an
unknown subject exits 1. Invalid command syntax exits 2. `--json` is a trailing
flag; to use a label literally named `--json`, supply it followed by another
`--json`.

`kind=service` supplies the classification for issuers without a signed grant
claim. Auth0's signed `gty=client-credentials` still selects `door=service`,
including for a row marked `user`; both paths require an active admission row.
The verified `sub` remains the personal-memory principal. Labels and kinds do
not change ownership or memory-space access.

## Upgrade an existing database

Migration 13 is required by the new server even when OAuth is disabled. Init
scripts run only on fresh data directories. For existing data, preserve the
previous server image and operator configuration, take and verify a backup, and
perform the following during a deployment window. Keep admission changes frozen
until the new server passes its smoke checks.

1. Put a distinct `OPENBRAIN_TOKEN_ADMIN_PASSWORD` in the deployment's
   owner-only `.env`. It is used only by the tools profile. The role is
   `NOLOGIN` by default until explicitly provisioned. For an external database,
   install the role-scoped HBA entries described below before enabling LOGIN.
   For a local Compose database, run:

   ```bash
   bash ../../scripts/upgrade-enable-token-admin-role.sh
   ```

   For an external database, including the Qubes app→DB ConnectTCP path, run
   native `psql` from the application host via the same helper:

   ```bash
   COMPOSE_DIR="$PWD" bash ../../../scripts/upgrade-enable-token-admin-role.sh --direct
   ```

   The second command is relative to `deploy/qubes/app-qube`. It uses `DB_HOST`,
   `DB_PORT`, `POSTGRES_DB`, `POSTGRES_USER` and `POSTGRES_PASSWORD` from
   `.env`. The helper reconciles LOGIN, password and restricted cluster flags in
   one transaction. Password values are passed through environment variables,
   never command arguments. It does not install or reload `pg_hba.conf`.

2. Apply migration 13 and the current grants assertion together as a PostgreSQL
   superuser (older databases must first apply the preceding migrations):

   ```bash
   docker compose exec -T postgres psql -X -v ON_ERROR_STOP=1 \
     --single-transaction -U postgres -d openbrain \
     -f /docker-entrypoint-initdb.d/13-oauth-subjects.sql \
     -f /docker-entrypoint-initdb.d/99-grants-assertion.sql
   ```

   Ensure the running database container has the new read-only migration mount
   before using these paths. Alternatively stream both checked-out files through
   `psql --single-transaction`. On Qubes, use the existing
   [native psql upgrade route](../deploy/qubes/app-qube/README.md#upgrading-an-existing-deployment)
   over ConnectTCP, with `-f` paths to the checkout's `db/13-oauth-subjects.sql`
   and `db/03-grants-assertion.sql`.

3. Build the tools with the reviewed source and import the legacy lists **before
   starting the new server**:

   ```bash
   docker compose build mcp subject-admin token-admin
   docker compose --profile tools run --rm subject-admin import-env --json
   docker compose --profile tools run --rm subject-admin list --json
   ```

   `import-env` reads `OAUTH_ALLOWED_SUBJECTS` and
   `OAUTH_SERVICE_ACCOUNT_SUBJECTS` from the tools container's environment. It
   imports only the admitted subjects, mapping the intersection with the service
   list to `kind=service`. Service-only entries do not gain admission. The
   import is atomic and serializes with other enrollment writes. Any existing
   row, **including a revoked row**, makes it skip the entire import. An empty
   allowed list is an error. A skipped import requires comparing the existing
   inventory with the intended subjects; it is not proof of a complete
   migration.

4. Verify the inventory, remove both legacy lists from `.env`, then recreate
   only the MCP service and smoke each existing client. Check the auth audit for
   the expected admitted subjects and `subject_not_allowed` failures. An empty
   or entirely revoked table rejects every Bearer and produces a loud boot
   warning. `/health` remains available.

The bridge is deliberately an explicit administrator step, rather than runtime
boot-time seeding: a read-only verifier must not hold enrollment credentials or
be able to resurrect access. During this transition release, legacy settings
still receive input validation and produce a deprecation warning if nonempty,
but **never authorize or classify requests**. Remove them now; the following
release can reject their presence entirely.

### Split Qubes administrator path

The shipped app-qube Compose file includes `subject-admin` and `token-admin` in
its inactive `tools` profile. Both use the existing host-side ConnectTCP
forwarder; neither depends on a local Postgres container. The DB qube remains
loopback-only. Add the following role/database-scoped records to its persistent
`pg_hba.conf`, using the existing db-qube administration path, then reload:

```conf
host openbrain openbrain_token_admin 127.0.0.1/32 scram-sha-256
host openbrain openbrain_token_admin ::1/128 scram-sha-256
```

They are also in the shipped
[HBA snippet](../deploy/qubes/db-qube/pg_hba.snippet.conf). Keep the existing
app→DB dom0 policy; no new qrexec channel or network listener is needed. Verify
the admin can list subjects in `openbrain`, and that connecting to the
`postgres` maintenance database as that role fails with no HBA entry. Keep the
role `NOLOGIN` until its credential and HBA setup are complete. Enabling the
admin login does not enable native-token HTTP authentication: the Qubes server
remains `ENABLE_NATIVE_TOKENS=false`.

### Rollback and restore

A failed migration transaction leaves the existing schema intact. Migration 13
is additive and may remain present during an application rollback. Restore the
previous server image and its reviewed environment together. A stale legacy
allowlist can undo revocations: if admission changed after rollout, reconcile
that previous allowlist with the **current active database rows** before
restarting the older server. Do not blindly restore a pre-revocation snapshot.

Revoke the new administrator's login
(`ALTER ROLE openbrain_token_admin NOLOGIN`) and remove its two HBA entries if
rolling back its provisioning, provided no existing token administrator depended
on that login. Keep the preserved original LOGIN state when that role was
already in use. Restoring a full database backup also restores admission as of
the backup; review and reapply later revocations before reconnecting clients.
