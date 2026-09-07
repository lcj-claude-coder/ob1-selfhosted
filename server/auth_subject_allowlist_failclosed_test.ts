// The default middleware has no injected database admission lookup, so even a
// valid Bearer must fail closed. The static-key door on a mixed deployment
// still works. Empty/revoked database rows are tested separately by
// oauth_subjects_db_smoke.ts; this file pins missing-wiring behavior.

import { assertEquals } from "jsr:@std/assert@1";
import {
  makeAuthTestApp,
  makeJwksFixture,
  withEnv,
} from "./api_test_support.ts";

const BRAIN_KEY = "b".repeat(64);
const ISSUER = "https://test.invalid/";
const AUDIENCE = "https://test.invalid:8443/mcp";
const JWKS_URL = "https://test.invalid/.well-known/jwks.json";

const TEST_ENV = {
  DB_PASSWORD: "test-password",
  ENABLE_NATIVE_TOKENS: "false",
  MCP_ACCESS_KEY: BRAIN_KEY,
  AUTH0_ISSUER: ISSUER,
  AUTH0_JWKS_URI: JWKS_URL,
  AUTH0_AUDIENCE: AUDIENCE,
  OBS_AUTH_EVENTS_ENABLED: "false",
  METADATA_FALLBACK_POLICY: "off",
  JWKS_FETCH_TIMEOUT_MS: "2000",
};

Deno.test(
  "requireAuth fails closed without an injected admission lookup",
  withEnv([], TEST_ENV, runFailClosedAllowlistTest),
);

async function runFailClosedAllowlistTest(t: Deno.TestContext): Promise<void> {
  const fixture = await makeJwksFixture({
    issuer: ISSUER,
    audience: AUDIENCE,
    jwksUrl: JWKS_URL,
  });
  const restoreFetch = fixture.installFetchMock();
  const { requireAuth } = await import("./auth.ts");
  const app = makeAuthTestApp(requireAuth);

  try {
    await t.step(
      "fully valid Bearer → 401 (missing admission lookup)",
      async () => {
        const res = await app.request("/", {
          headers: {
            "authorization": `Bearer ${await fixture.signToken({
              claims: { sub: "auth0|any-user" },
            })}`,
          },
        });
        assertEquals(res.status, 401);
        const body = await res.json();
        assertEquals(body.error?.code, -32001);
      },
    );

    await t.step(
      "x-brain-key door is unaffected by the sealed OAuth door",
      async () => {
        const res = await app.request("/", {
          headers: { "x-brain-key": BRAIN_KEY },
        });
        assertEquals(res.status, 200);
      },
    );

    await t.step(
      "valid key + valid-but-unadmitted Bearer → 200 (either-valid holds)",
      async () => {
        // The dual-header contract is unchanged: a request authenticates if
        // EITHER credential is valid, and the key path short-circuits before
        // the Bearer is even examined.
        const res = await app.request("/", {
          headers: {
            "x-brain-key": BRAIN_KEY,
            "authorization": `Bearer ${await fixture.signToken({
              claims: { sub: "auth0|any-user" },
            })}`,
          },
        });
        assertEquals(res.status, 200);
      },
    );
  } finally {
    restoreFetch();
  }
}
