# Connecting Kimi Code to an OAuth deployment

The public Funnel branch always requires OAuth. Single-host
[Pattern B](../deploy/compose-tailnet/README.md) also uses OAuth on the tailnet;
[split Qubes](../deploy/qubes/README.md) can optionally enable
[native tokens](native-access-tokens.md) on its private branch. This guide
covers the OAuth client path. The
[compose-tailnet runbook](../deploy/compose-tailnet/README.md#connect-claudeai--claude-mobile)
covers connecting **claude.ai / Claude mobile** (a confidential client), and
[codex-oauth-client.md](codex-oauth-client.md) covers a local **Codex CLI** (a
public PKCE client with a pre-registered client ID). This doc covers a third
client shape: a local [Kimi Code](https://www.kimi.com/code) CLI, which is
**also a public PKCE client — but one whose interactive login registers
exclusively through Dynamic Client Registration (DCR)**.

> **Unattended or multi-host? Prefer a service account instead.** If the caller
> is an automation rather than an interactive user — or you run Kimi Code on
> several machines and don't want one DCR-created application per login per host
> — use the
> [client-credentials service-account route](service-account-oauth-client.md)
> with Kimi Code's `bearerTokenEnvVar` plus a launch-time token-minting wrapper
> (sketch below). It needs no DCR window, no browser, and one pre-registered M2M
> application **per agent or automation boundary** — registered once, not once
> per login per host. Note that a service account authenticates as its own
> machine principal, not as the user: this doc's DCR flow remains the route for
> user-identity interactive logins.

Kimi Code's MCP server configuration (`mcp.json`) has no field for a
pre-registered OAuth client ID (still true as of CLI 0.38.0 — its HTTP-server
schema offers `url`, `auth`, `bearerTokenEnvVar`, headers, and
tool/timeout/enablement options, none of which carries a client ID), and its
OAuth flow requires the authorization server to advertise a
`registration_endpoint`. The pre-registered Native-client route that is
_preferred_ for Codex is therefore **not available** for interactive login here:
the time-boxed DCR procedure is the only interactive route. If a future Kimi
Code release adds a static client-ID option, prefer the pre-registered route
from the Codex doc instead.

Note the registration's lifetime: since CLI 0.33.0, each login flow binds its
callback listener to a random loopback port and **drops any cached client
registration whose `redirect_uris` don't contain that exact URI** before
starting — so every login re-registers. A DCR-created application therefore
can't be shared across hosts or reused for a later re-login on the same host;
only the stored refresh token carries a host's session forward. This is the
second reason multi-host setups should prefer the service-account route.

The two routes below carry separate verification notes. The **DCR login
procedure** was verified end-to-end on **2026-07-19** with **Kimi Code CLI
0.27.0** on a tailnet-connected Linux host: OAuth login, the 11-tool MCP
listing, read-only `session_*` calls, and a refresh token persisted in the
credential store. The **service-account wiring** (`bearerTokenEnvVar` plus a
mint-and-cache wrapper) was verified end-to-end on **2026-08-24** with **CLI
0.38.0**: token mint, MCP `initialize`, and tool listing with no DCR window and
no browser. The per-login re-registration behavior described above was confirmed
against the 0.38.0 binary (`invalidateStaleRegistration`).

> **Scope: Auth0, as we run it today.** Same caveat as the Codex doc — this
> documents the one provider this project operates (Auth0) and the two flows we
> use with it: public PKCE clients for interactive login, and
> `client_credentials` service accounts for automation. Kimi Code speaks
> standard OAuth 2.1 + PKCE + RFC 7591 DCR, so other OIDC providers almost
> certainly work — we just don't run them.

> **Tenant membership control comes first.** Same as the Codex doc: decide who
> may enroll in the tenant _before_ wiring up any client — the traps (an open
> social connection has **no** sign-up toggle; the Domain-Level promotion this
> doc's DCR window requires **persists** after DCR is disabled) are in
> [auth0-setup-dangers.md](auth0-setup-dangers.md).

> **Never put access tokens, refresh tokens, authorization codes, client
> secrets, or the contents of the credential store into git, issue comments,
> shell transcripts, or test artifacts.**

## Service-account wiring sketch (preferred for automation)

With an M2M application created and its subject enrolled per
[service-account-oauth-client.md](service-account-oauth-client.md), Kimi Code
itself runs no OAuth flow: the wrapper below performs the OAuth 2.0
`client_credentials` exchange out of band, and the CLI simply consumes the
resulting bearer token. Point the server entry at an environment variable that
holds a fresh access token:

```json
{
  "mcpServers": {
    "openbrain": {
      "url": "https://homebox.tailnet-name.ts.net/mcp",
      "bearerTokenEnvVar": "OPENBRAIN_MCP_TOKEN"
    }
  }
}
```

and wrap the CLI launch so the variable is always freshly minted (any language;
stdlib-only is fine — request `grant_type=client_credentials` with
`client_secret_post` against the tenant token endpoint, sending the exact API
`audience` the deployment expects (an audience-less Auth0 custom-API exchange
yields a token this deployment rejects), refuse token-endpoint redirects so a
307/308 cannot replay the credentials to a second URL, cache the JWT until near
expiry in an owner-only `0600` file written atomically, print it on stdout):

```sh
OPENBRAIN_MCP_TOKEN="$(ob1-mcp-token)" || exit 1   # mint-or-cache helper
export OPENBRAIN_MCP_TOKEN
exec kimi "$@"
```

Check the substitution's status on its own line, as above: a bare
`export OPENBRAIN_MCP_TOKEN="$(ob1-mcp-token)"` masks the helper's failure
(`export` exits 0 even when the substitution failed). A failed mint would launch
Kimi with an empty token, which the CLI rejects before connecting: the server
ends in a failed state with a missing/empty bearer-token configuration error,
not a 401 from the deployment. If you would rather never block the CLI on token
plumbing, warn and `unset OPENBRAIN_MCP_TOKEN` before `exec` instead of exiting
— Kimi itself then starts with this MCP server unavailable (an unset variable
does not fall back to DCR while `bearerTokenEnvVar` is configured) — but do one
or the other explicitly. The token cache holds a live bearer credential for its
remaining lifetime, so it deserves the same owner-only treatment as the
credentials file.

Keep the client ID + secret in a `0600` file the helper reads — never in
`mcp.json`, shell history, or command arguments. When `bearerTokenEnvVar` is
set, Kimi Code bypasses its OAuth/DCR machinery entirely, so no DCR window is
ever needed. Onboarding another host means creating that host's own M2M
application, enrolling its subject, and installing the helper with a fresh
credentials file — a few minutes of provider console work, still no DCR window.
Use **one application per agent or automation boundary**, not one shared across
hosts: the verified `sub` is the caller's personal-memory principal, and
separate clients keep revocation, rotation, and attribution narrow (identity
guidance in the service-account doc). A single application shared across hosts
is a documented exception only — every host then holds the same secret and all
calls arrive as one principal. The env var is read at process start, so a
session that outlives the token's lifetime needs a restart (resume is
sufficient) to pick up a fresh one.

Note that this repository's tracked helper,
[`scripts/verify-service-account.ts`](../scripts/verify-service-account.ts), is
a _smoke test_ for the same grant — it deliberately never prints the token, so
it proves the wiring end to end but cannot feed `bearerTokenEnvVar`. The
launch-time mint-and-cache helper is a separate small script, not that one.

## Boundaries

- Same as the Codex doc: this covers a **locally running Kimi Code process**
  that can already reach the deployment's `.ts.net` MCP URL. On a
  tailnet-connected host, MagicDNS resolves that hostname to the server's
  private tailnet address; OAuth still terminates at the provider, and the
  tailnet path is not an auth bypass. Caddy forwards OAuth on both allowed
  branches, strips native credentials publicly, and sets the trusted marker
  privately; the server still verifies every credential.
- This does **not** authorize cloud-hosted agent workers. Keep public cloud
  ingress disabled.
- Kimi Code supports `bearerTokenEnvVar` for HTTP MCP servers — a **static**
  token is not an alternative here, because this deployment enables no
  `x-brain-key` door. (A _short-lived OAuth bearer_ injected through
  `bearerTokenEnvVar` is exactly what the service-account sketch above does.)

## Prerequisites (interactive DCR route)

These checks precede the DCR login below. The service-account route skips this
section entirely — its prerequisites are the provider-side procedure in
[service-account-oauth-client.md](service-account-oauth-client.md).

1. Confirm the protected resource is healthy and advertises the expected issuer
   (same checks as the Codex doc):

   ```bash
   curl -i https://homebox.tailnet-name.ts.net/mcp
   curl -sS https://homebox.tailnet-name.ts.net/.well-known/oauth-protected-resource/mcp
   ```

   The first returns `401` with a `WWW-Authenticate: Bearer` challenge; the
   second names the exact MCP URL as `resource` and your Auth0 tenant as its
   authorization server.

2. Confirm the authorization server advertises DCR — Kimi Code hard-fails with
   `Incompatible auth server: does not support dynamic client registration` if
   the issuer metadata lacks a registration endpoint:

   ```bash
   curl -sS https://<your-tenant>.auth0.com/.well-known/openid-configuration | grep registration_endpoint
   ```

   An advertised endpoint does **not** mean DCR is _enabled_ — see the probe
   trap in [Troubleshooting](#troubleshooting). The actual toggle check is the
   login attempt itself.

## Enable the DCR window (operator step)

Kimi Code cannot use a pre-registered client for interactive login, so open a
**time-boxed** DCR window before login — the same procedure the Codex doc
documents as its fallback:

1. In the OpenBrain **Auth0 API → Settings**, set the **default third-party
   permissions** to the minimum OpenBrain needs (DCR-registered clients are
   third-party under Auth0's strict mode).
2. Promote the login connection to **Domain Level** — otherwise the
   DCR-registered client fails with `no connections enabled for the client`.
3. Enable **Dynamic Client Registration** (tenant **Settings → Advanced**).

Plan to disable DCR **immediately after** the login completes. Open DCR lets
anyone register a third-party application against your tenant during that
window, while the Domain-Level login connection remains available to third-party
applications after DCR is disabled. Treat both as deliberate exposure. The
registered client and its refresh token keep working after DCR is off. Since
every login re-registers (the registration-lifetime note above), the tenant
accumulates identically named `kimi-code (openbrain)` applications over time:
**do not delete** the one backing a live host's credential store — its
`client_id` is in that host's
`~/.kimi-code/credentials/mcp/openbrain-*-client.json`, and deleting it
invalidates the stored refresh token, killing the live session. Registrations
referenced by no live credential store are superseded and safe to remove. And
because registration is per login, not per host, this window is needed again for
each _additional_ Kimi Code host **and for any re-login on the same host**
(logout, credential loss, refresh-token expiry or revocation).

## Configure and log in

Add the server to the user-level `~/.kimi-code/mcp.json` (or
`$KIMI_CODE_HOME/mcp.json` when `KIMI_CODE_HOME` is set):

```json
{
  "mcpServers": {
    "openbrain": {
      "url": "https://homebox.tailnet-name.ts.net/mcp",
      "auth": "oauth"
    }
  }
}
```

`auth: "oauth"` marks the server for the OAuth login flow. No scopes field
exists. Against this deployment, the observed flow returned `offline_access` and
stored a refresh token, so no additional scope configuration was needed in Kimi
Code 0.27.0.

**MCP servers load at process start.** Restart the CLI after editing `mcp.json`
— resuming the previous session (`kimi resume`) is sufficient; a brand-new
conversation is not required. The new process shows the server in needs-auth
state.

Start the login from the TUI:

```
/mcp-config login openbrain
```

(An agent inside the session can run the same flow via the server's
`authenticate` tool.) The flow starts a callback server on a random `127.0.0.1`
port, registers the client over DCR, prints the Auth0 authorization URL, and
blocks up to 15 minutes for the callback. Complete login/consent in a browser on
the Kimi host. To use a browser on another machine, leave the login running,
read `<port>` from the current URL's `redirect_uri`
(`http://127.0.0.1:<port>/callback`), and start this local forward on the
browser machine before opening that exact URL:

```bash
ssh -N -L <port>:127.0.0.1:<port> <user>@<kimi-host>
```

The browser's callback to its own `127.0.0.1:<port>` then traverses the tunnel
to the Kimi host. If the URL must leave the terminal, hand it off through an
owner-only (`0600`) temporary file and delete it after the callback — never
relay it through chat, issues, logs, or a committed artifact.

Then disable DCR in Auth0 (keep the registered application).

## Credential store

Kimi Code stores MCP OAuth material under `~/.kimi-code/credentials/mcp/` as
three files per server — `<server>-<hash>-client.json` (the DCR registration),
`-discovery.json` (cached AS + resource metadata), and `-tokens.json`. Confirm
owner-only permissions **without printing them**:

```bash
stat -c '%a %U:%G %n' ~/.kimi-code/credentials/mcp/openbrain-*
```

Expect `600` throughout. The tokens file should contain a `refresh_token` key (a
keys-only check with `jq 'keys'` is safe; do not print values).

## Skill and process-restart discovery

Install the canonical session workflow as a personal skill by **symlink**,
rather than copying it and creating a second source of truth:

```bash
mkdir -p ~/.kimi-code/skills
ln -s /path/to/ob1-selfhosted/skills/session-tracker ~/.kimi-code/skills/session-tracker
```

Kimi Code scans `$KIMI_CODE_HOME/skills/` (default `~/.kimi-code/skills/`) and
`~/.agents/skills/` at user scope; the latter is shared across agent tools.
Restart the CLI after adding the server or skill; resuming the same conversation
is sufficient. Confirm `session-tracker` is listed and that OpenBrain exposes
the `session_*` tools (capture, lookup, search, list, status-update). See
[`skills/session-tracker/SKILL.md`](../skills/session-tracker/SKILL.md) for the
usage contract.

## Smoke test and staged-session import

Same as the Codex doc: read-only `session_search`/`session_lookup` first, then
the full `+++`-delimited TOML staging payload to `session_capture`, **recording
the returned integer `id`** back into the payload (omission on re-capture mints
a duplicate), and verifying the round-trip reports an _update_. Server-side
provenance should show `source = 'funnel'` for an interactive DCR login, or
`source = 'service'` for a client-credentials service account — in both cases
with a non-null `source_node` (the verified JWT subject). That label is an
authentication-door marker, not a network-path claim; the tailnet client is
expected to arrive via Caddy's `@tailnet` branch. The SQL check and the
Caddy-log path discrimination are in
[codex-oauth-client.md](codex-oauth-client.md#smoke-test-and-staged-session-import).

## Restart and refresh verification

Restart the CLI (resume is fine) and repeat a read-only lookup — this proves
persisted credentials and tool discovery. For refresh renewal: after the access
token expires, look up again with no browser step, then confirm a **`sertft`**
event for this client in Auth0 **Monitoring → Logs**. That event plus a
successful lookup is the proof. Do not log out to test renewal — logout clears
the stored credentials and tests _reauthorization_, not refresh.

## Troubleshooting

- **Login fails with `failed to start OAuth flow for "<server>":` and an empty
  detail** — the most likely cause is **DCR disabled** at the tenant. Kimi Code
  0.27.0 swallows the authorization server's error body
  (`dynamic client registration is disabled`) instead of surfacing it. Enable
  the DCR window and retry.
- **Probe trap: DCR looks open when it isn't.** Auth0's registration endpoint
  validates the request payload _before_ checking whether DCR is enabled, so a
  probe with a malformed `redirect_uris` gets a `400` validation error even with
  DCR off — only a well-formed request gets the real
  `dynamic client registration is disabled`. Don't conclude the window is open
  from a validation error.
- **`Incompatible auth server: does not support dynamic client registration`** —
  the issuer metadata has no registration endpoint at all. There is no Kimi Code
  workaround; the AS must support DCR (or a future Kimi Code must grow a static
  client-ID option).
- **Browser login succeeds but MCP returns 401 / audience mismatch** — confirm
  Auth0's **Resource Parameter Compatibility Profile** is enabled and the
  protected-resource `resource` exactly equals the Auth0 API identifier (same as
  the Codex doc).
- **`no connections enabled for the client` during login** — the login
  connection wasn't promoted to Domain Level for third-party clients.
- **No refresh token / browser login required after expiry** — not expected
  against this deployment (verified to issue one), but if it regresses: confirm
  the Auth0 API still enables **Allow Offline Access**, the application permits
  the `refresh_token` grant, and the refresh token hasn't been revoked or
  expired by policy. An access-only credential must be reauthorized once after
  correcting those settings.
- **Current session has no OpenBrain tools** — restart the CLI so it reloads
  `mcp.json`; resuming the same conversation is sufficient. Then confirm the
  personal skill symlink resolves.
- **`Address already in use` while starting the SSH forward** — another process
  owns that port on the browser machine. The local forwarding port must match
  the current `redirect_uri`, so stop the login, start a new one to obtain
  another random callback port, and build the forward from the new authorization
  URL.
