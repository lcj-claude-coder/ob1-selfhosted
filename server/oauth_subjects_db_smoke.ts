// Explicit disposable-DB integration smoke: run only through the DB-init runner.
import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "@std/assert";
import { Pool } from "postgres";
import {
  allowOAuthSubject,
  hasActiveOAuthSubjects,
  importOAuthSubjects,
  listOAuthSubjects,
  lookupOAuthSubject,
  revokeOAuthSubject,
} from "./oauth_subjects.ts";
import { makeAuthTestApp, makeJwksFixture } from "./api_test_support.ts";
import { probeDbAtBoot } from "./db_boot_probe.ts";

const common = {
  hostname: Deno.env.get("DB_SMOKE_HOST") ?? "127.0.0.1",
  port: Number(Deno.env.get("DB_SMOKE_PORT") ?? "55439"),
  database: "openbrain",
};
function poolFor(user: string, passwordVar: string) {
  const password = Deno.env.get(passwordVar);
  assert(password, `${passwordVar} required`);
  return new Pool({ ...common, user, password }, 2);
}
const owner = poolFor("postgres", "POSTGRES_PASSWORD");
const admin = poolFor(
  "openbrain_token_admin",
  "OPENBRAIN_TOKEN_ADMIN_PASSWORD",
);
const runtime = poolFor("openbrain_app", "OPENBRAIN_APP_PASSWORD");
const issuer = "https://subject-smoke.invalid/";
const audience = `${issuer}mcp`;
const jwksUrl = `${issuer}.well-known/jwks.json`;
Deno.env.set("DB_PASSWORD", "unit-config-only");
Deno.env.set("AUTH0_ISSUER", issuer);
Deno.env.set("AUTH0_AUDIENCE", audience);
Deno.env.set("AUTH0_JWKS_URI", jwksUrl);
Deno.env.set("OAUTH_ALLOWED_SUBJECTS", "legacy-only");
Deno.env.set("OAUTH_SERVICE_ACCOUNT_SUBJECTS", "legacy-only");
Deno.env.set("OBS_AUTH_EVENTS_ENABLED", "false");
Deno.env.set("ENABLE_NATIVE_TOKENS", "false");
Deno.env.delete("MCP_ACCESS_KEY");
Deno.env.set("METADATA_FALLBACK_POLICY", "off");
const fixture = await makeJwksFixture({ issuer, audience, jwksUrl });
const restoreFetch = fixture.installFetchMock();
const { createRequireAuth } = await import("./auth.ts");
const app = makeAuthTestApp(
  createRequireAuth(null, (sub) => lookupOAuthSubject(runtime, sub)),
  (c) => c.json({ sub: c.get("sub"), door: c.get("door") }),
);
const token = await fixture.signToken({ claims: { sub: "user-a" } });
async function request(bearer = token) {
  return await app.request("/", {
    headers: { authorization: `Bearer ${bearer}` },
  });
}
async function sql(pool: Pool, statement: string) {
  const client = await pool.connect();
  try {
    return await client.queryArray(statement);
  } finally {
    client.release();
  }
}
try {
  assertEquals(
    (await listOAuthSubjects(admin)).length,
    0,
    "requires empty fixture",
  );
  assertEquals(await hasActiveOAuthSubjects(runtime), false);
  await probeDbAtBoot(runtime, "disposable OAuth fixture");
  assertEquals((await request()).status, 401);
  assertEquals(
    (await request(await fixture.signToken({ claims: { sub: "legacy-only" } })))
      .status,
    401,
    "legacy environment cannot authorize or classify a caller",
  );

  // A malformed row aborts the WHOLE import, even when earlier rows were valid.
  await assertRejects(() => importOAuthSubjects(admin, ["user-a", ""], []));
  assertEquals(await listOAuthSubjects(admin), []);
  // Two concurrent imports serialize around a single empty-table decision.
  const imports = await Promise.all([
    importOAuthSubjects(admin, ["user-a", "machine-a"], [
      "machine-a",
      "never-admitted",
    ]),
    importOAuthSubjects(admin, ["user-a", "machine-a"], ["machine-a"]),
  ]);
  assertEquals(imports.sort(), [0, 2]);
  assertEquals(await lookupOAuthSubject(runtime, "never-admitted"), null);
  assertEquals(await lookupOAuthSubject(runtime, "USER-A"), null);
  assertEquals(await hasActiveOAuthSubjects(runtime), true);
  assertEquals((await request()).status, 200);
  assertEquals(await (await request()).json(), {
    sub: "user-a",
    door: "funnel",
  });
  const machine = await fixture.signToken({ claims: { sub: "machine-a" } });
  assertEquals(await (await request(machine)).json(), {
    sub: "machine-a",
    door: "service",
  });
  const signedGrant = await fixture.signToken({
    claims: { sub: "user-a", gty: "client-credentials" },
  });
  assertEquals(await (await request(signedGrant)).json(), {
    sub: "user-a",
    door: "service",
  });

  await revokeOAuthSubject(admin, "user-a");
  assertEquals(
    (await request()).status,
    401,
    "same token, next request, no restart",
  );
  assertEquals(await revokeOAuthSubject(admin, "user-a"), null);
  await revokeOAuthSubject(admin, "machine-a");
  assertEquals(await hasActiveOAuthSubjects(runtime), false);
  assertEquals(await importOAuthSubjects(admin, ["user-a", "new-user"], []), 0);
  assertEquals(
    (await request()).status,
    401,
    "all-revoked table must not be reseeded",
  );
  assertEquals(await lookupOAuthSubject(runtime, "new-user"), null);
  assert(
    (await listOAuthSubjects(admin)).every((row) => row.revoked_at !== null),
  );
  // Explicit allow is the only operator path that can reactivate admission.
  await allowOAuthSubject(admin, "user-a", "Human operator", "user");
  assertEquals((await request()).status, 200);
  await allowOAuthSubject(admin, "machine-a", "Worker", "service");
  assertEquals(await lookupOAuthSubject(runtime, "machine-a"), "service");

  // A healthy catalog and an active row do not prove the runtime can read all
  // lookup columns. Exercise the real boot probe under each narrowed grant.
  for (const column of ["subject", "kind", "revoked_at"]) {
    await sql(
      owner,
      `REVOKE SELECT(${column}) ON oauth_auth.allowed_subject FROM openbrain_app`,
    );
    try {
      if (column !== "revoked_at") {
        assertEquals(await hasActiveOAuthSubjects(runtime), true);
      }
      const error = await assertRejects(
        () => probeDbAtBoot(runtime, "disposable OAuth fixture"),
        Error,
      );
      assertStringIncludes(error.message, "required OAuth admission columns");
      assertStringIncludes(error.message, "db/13-oauth-subjects.sql");
      assertStringIncludes(error.message, "db/03-grants-assertion.sql");
      await assertRejects(() => lookupOAuthSubject(runtime, "user-a"));
    } finally {
      await sql(
        owner,
        `GRANT SELECT(${column}) ON oauth_auth.allowed_subject TO openbrain_app`,
      );
    }
    await probeDbAtBoot(runtime, "disposable OAuth fixture");
    assertEquals((await request()).status, 200);
  }

  for (
    const statement of [
      "SELECT content FROM public.thoughts LIMIT 1",
      "SELECT title FROM sessions.session LIMIT 1",
      "SELECT token_hash FROM native_auth.access_token LIMIT 1",
      "INSERT INTO oauth_auth.allowed_subject(subject,kind) VALUES ('bypass','user')",
      "DELETE FROM oauth_auth.allowed_subject",
      "UPDATE oauth_auth.allowed_subject SET revoked_at=NULL",
    ]
  ) {
    await assertRejects(() => sql(admin, statement));
  }
  for (
    const statement of [
      "SELECT created_at FROM oauth_auth.allowed_subject",
      "SELECT * FROM oauth_auth.allow_subject('bypass',NULL,'user')",
      "SELECT * FROM oauth_auth.revoke_subject('user-a')",
      "SELECT oauth_auth.import_subjects(ARRAY['bypass'],ARRAY[]::text[])",
      "UPDATE oauth_auth.allowed_subject SET kind='service'",
    ]
  ) {
    await assertRejects(() => sql(runtime, statement));
  }
  // A transaction rollback preserves both admission and the caller's ownership.
  const transaction = await admin.connect();
  try {
    await transaction.queryArray("BEGIN");
    await transaction.queryArray(
      "SELECT * FROM oauth_auth.revoke_subject('user-a')",
    );
    await transaction.queryArray("ROLLBACK");
  } finally {
    transaction.release();
  }
  assertEquals((await request()).status, 200);
  // Database outage/error must never fall back to the legacy environment list.
  const failed = makeAuthTestApp(
    createRequireAuth(null, () => Promise.reject(new Error("DB unavailable"))),
  );
  assertEquals(
    (await failed.request("/", {
      headers: { authorization: `Bearer ${token}` },
    })).status,
    401,
  );
  console.log(
    "OAuth admission: real JWT/DB, concurrent atomic import, next-request revoke, classification, rollback, boot read grants and role boundaries passed",
  );
} finally {
  restoreFetch();
  await sql(owner, "TRUNCATE oauth_auth.allowed_subject");
  await Promise.all([owner.end(), runtime.end(), admin.end()]);
}
