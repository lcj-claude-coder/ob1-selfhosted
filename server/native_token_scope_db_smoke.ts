// Disposable DB only: real token verification -> transport context -> scope ->
// forced RLS, for thoughts AND sessions. No embedding or production services.
import { assert, assertEquals } from "@std/assert";
import { Hono } from "hono";
import { Pool } from "postgres";
import {
  authenticateAccessToken,
  createAccessToken,
  revokeAccessToken,
} from "./access_tokens.ts";
import { authContextFromValues } from "./auth_context.ts";
import { withScopeClient } from "./scoped_db.ts";
import type { AppVariables } from "./auth.ts";

const host = Deno.env.get("DB_SMOKE_HOST") ?? "127.0.0.1";
const port = Number(Deno.env.get("DB_SMOKE_PORT") ?? "55439");
const appPassword = Deno.env.get("OPENBRAIN_APP_PASSWORD")!;
const common = { hostname: host, port, database: "openbrain" };
const ownerPool = new Pool({
  ...common,
  user: "postgres",
  password: Deno.env.get("POSTGRES_PASSWORD")!,
}, 1);
const adminPool = new Pool({
  ...common,
  user: "openbrain_token_admin",
  password: Deno.env.get("OPENBRAIN_TOKEN_ADMIN_PASSWORD")!,
}, 1);
const appPool = new Pool({
  ...common,
  user: "openbrain_app",
  password: appPassword,
}, 1);
for (
  const [key, value] of Object.entries({
    DB_HOST: host,
    DB_PORT: String(port),
    DB_NAME: "openbrain",
    DB_USER: "openbrain_app",
    DB_PASSWORD: appPassword,
    ENABLE_NATIVE_TOKENS: "true",
    REQUIRE_TAILNET_TOKEN_MARKER: "true",
    MCP_ACCESS_KEY: "k".repeat(64),
    MCP_ACCESS_KEY_PRINCIPAL: "legacy-owner",
    AUTH0_ISSUER: "",
    AUTH0_JWKS_URI: "",
    AUTH0_AUDIENCE: "",
    OAUTH_ALLOWED_SUBJECTS: "",
    OAUTH_SERVICE_ACCOUNT_SUBJECTS: "",
    OBS_AUTH_EVENTS_ENABLED: "true",
    METADATA_FALLBACK_POLICY: "off",
  })
) Deno.env.set(key, value);
const { createRequireAuth } = await import("./auth.ts");
const { resolveReadScope, resolveWriteScope } = await import("./scope.ts");
const { shutdownAuthAuditForTests, getAuditMetricsForTests } = await import(
  "./auth_audit.ts"
);

const prefixes: string[] = [];
const thoughtIds: string[] = [];
const sessionIds: string[] = [];
const app = new Hono<{ Variables: AppVariables }>();
app.use(
  "*",
  createRequireAuth((token) => authenticateAccessToken(appPool, token)),
);
app.all("/scope/:workspace", async (c) => {
  const auth = authContextFromValues(
    c.get("door"),
    c.get("sub"),
    c.get("tokenLabel"),
  );
  assert(auth);
  const input = {
    workspace_id: c.req.param("workspace"),
    visibility: "personal" as const,
  };
  if (c.req.method === "POST") {
    const scope = await resolveWriteScope(appPool, input, auth);
    await withScopeClient(appPool, scope, async (db) => {
      const thought = await db.queryObject<{ id: string }>(
        `INSERT INTO public.thoughts(content, workspace_id, visibility, owner_subject)
         VALUES ($1, $2, 'personal', $3) RETURNING id`,
        [auth.sub, scope.workspaceId, scope.ownerSubject],
      );
      thoughtIds.push(thought.rows[0].id);
      const session = await db.queryObject<{ id: bigint }>(
        `INSERT INTO sessions.session(title, workspace_id, visibility, owner_subject)
         VALUES ($1, $2, 'personal', $3) RETURNING id`,
        [auth.sub, scope.workspaceId, scope.ownerSubject],
      );
      sessionIds.push(String(session.rows[0].id));
    });
  }
  const scope = await resolveReadScope(appPool, input, auth);
  return c.json(
    await withScopeClient(appPool, scope, async (db) => ({
      principal: scope.principal,
      thoughts: (await db.queryObject<{ content: string }>(
        "SELECT content FROM public.thoughts WHERE id = ANY($1::uuid[])",
        [thoughtIds],
      )).rows.map((r) => r.content),
      sessions: (await db.queryObject<{ title: string }>(
        "SELECT title FROM sessions.session WHERE id = ANY($1::bigint[])",
        [sessionIds],
      )).rows.map((r) => r.title),
    })),
  );
});
app.get("/blocked-native", (c) => c.text("must not reach"));
app.onError((_error, c) => c.text("scope refused", 400));

const call = (token: string, workspace: string, method = "GET") =>
  app.request(`/scope/${workspace}`, {
    method,
    headers: { "x-brain-key": token, "x-openbrain-tailnet": "1" },
  });
try {
  // Same label, different principals: labels must never partition ownership.
  const alice = await createAccessToken(adminPool, "agent", "native:alice");
  prefixes.push(alice.prefix);
  const bob = await createAccessToken(adminPool, "agent", "native:bob");
  prefixes.push(bob.prefix);
  for (const workspace of ["default", "sensitive"]) {
    for (const token of [alice, bob]) {
      assertEquals((await call(token.token, workspace, "POST")).status, 200);
    }
    for (const token of [alice, bob]) {
      const response = await call(token.token, workspace);
      assertEquals(response.status, 200);
      assertEquals(await response.json(), {
        principal: token.principal,
        thoughts: [token.principal],
        sessions: [token.principal],
      });
    }
  }
  const rotated = await createAccessToken(
    adminPool,
    "rotated label",
    "native:alice",
  );
  prefixes.push(rotated.prefix);
  await revokeAccessToken(adminPool, alice.prefix);
  assertEquals((await call(alice.token, "sensitive")).status, 401);
  for (const workspace of ["default", "sensitive"]) {
    assertEquals(await (await call(rotated.token, workspace)).json(), {
      principal: "native:alice",
      thoughts: ["native:alice"],
      sessions: ["native:alice"],
    });
  }
  // No marker, conflicting public marker, and duplicate marker all fail before
  // token admission. The real audit emitter must report missing_credentials.
  for (
    const extra of [{}, {
      "x-openbrain-tailnet": "1",
      "tailscale-funnel-request": "?1",
    }, { "x-openbrain-tailnet": "1, 1" }] as Record<string, string>[]
  ) {
    assertEquals(
      (await app.request("/blocked-native", {
        headers: { "x-brain-key": rotated.token, ...extra },
      })).status,
      401,
    );
  }
  for (let i = 0; i < 100 && getAuditMetricsForTests().inFlight > 0; i++) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assertEquals(getAuditMetricsForTests().inFlight, 0);
  const owner = await ownerPool.connect();
  try {
    const events = await owner.queryObject<{ reason: string }>(
      "SELECT reason FROM public.mcp_auth_events WHERE path='/blocked-native' ORDER BY id",
    );
    assertEquals(events.rows.map((r) => r.reason), [
      "missing_credentials",
      "missing_credentials",
      "missing_credentials",
    ]);
    // Simulate a retained pre-migration token: even a configured static-key
    // principal must not give it access to the static key owner's rows.
    await owner.queryArray(
      "UPDATE native_auth.access_token SET principal=NULL WHERE prefix=$1",
      [bob.prefix],
    );
  } finally {
    owner.release();
  }
  assertEquals(await authenticateAccessToken(appPool, bob.token), {
    label: "agent",
    principal: null,
  });
  assertEquals((await call(bob.token, "sensitive")).status, 400);
  console.log(
    "Native principals: thoughts/session RLS isolation, rotation, revocation, marker audit, and legacy fail-closed passed",
  );
} finally {
  await shutdownAuthAuditForTests();
  const owner = await ownerPool.connect();
  try {
    await owner.queryArray(
      "DELETE FROM public.thoughts WHERE id=ANY($1::uuid[])",
      [thoughtIds],
    );
    await owner.queryArray(
      "DELETE FROM sessions.session WHERE id=ANY($1::bigint[])",
      [sessionIds],
    );
    await owner.queryArray(
      "DELETE FROM native_auth.access_token WHERE prefix=ANY($1::text[])",
      [prefixes],
    );
    await owner.queryArray(
      "DELETE FROM public.mcp_auth_events WHERE path IN ('/blocked-native','/scope/default','/scope/sensitive')",
    );
  } finally {
    owner.release();
  }
  await appPool.end();
  await adminPool.end();
  await ownerPool.end();
}
