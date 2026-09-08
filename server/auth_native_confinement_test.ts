import { assertEquals } from "@std/assert";
import { authContextFromValues } from "./auth_context.ts";
import {
  makeAuthTestApp,
  makeJwksFixture,
  withEnv,
} from "./api_test_support.ts";
import type { AppVariables } from "./auth.ts";

Deno.test(
  "trusted proxy marker confines native tokens without suppressing OAuth",
  withEnv([], {
    DB_PASSWORD: "test-password",
    ENABLE_NATIVE_TOKENS: "true",
    REQUIRE_TAILNET_TOKEN_MARKER: "true",
    AUTH0_ISSUER: "https://issuer.test/",
    AUTH0_JWKS_URI: "https://issuer.test/jwks",
    AUTH0_AUDIENCE: "https://brain.test/mcp",
    OBS_AUTH_EVENTS_ENABLED: "false",
    METADATA_FALLBACK_POLICY: "off",
  }, async () => {
    const fixture = await makeJwksFixture({
      issuer: "https://issuer.test/",
      jwksUrl: "https://issuer.test/jwks",
      audience: "https://brain.test/mcp",
    });
    const restore = fixture.installFetchMock();
    try {
      const { createRequireAuth } = await import("./auth.ts");
      let lookups = 0;
      const middleware = createRequireAuth(() => {
        lookups++;
        return Promise.resolve({ label: "worker", principal: "native:worker" });
      }, () => Promise.resolve("user"));
      const app = makeAuthTestApp<{ Variables: AppVariables }>(
        middleware,
        (c) =>
          c.json(
            authContextFromValues(
              c.get("door"),
              c.get("sub"),
              c.get("tokenLabel"),
            ),
          ),
      );
      const variants: Record<string, string>[] = [
        {},
        { "x-openbrain-tailnet": "" },
        { "x-openbrain-tailnet": "true" },
        { "x-openbrain-tailnet": "1, 1" },
        { "x-openbrain-tailnet": "1", "tailscale-funnel-request": "?1" },
        { "x-openbrain-tailnet": "1", "tailscale-funnel-request": "" },
      ];
      for (const headers of variants) {
        const response = await app.request("/", {
          headers: { "x-brain-key": "valid-token", ...headers },
        });
        assertEquals(response.status, 401);
      }
      assertEquals(
        lookups,
        0,
        "untrusted routes must not even look up a token",
      );
      const admitted = await app.request("/", {
        headers: { "x-brain-key": "valid-token", "x-openbrain-tailnet": "1" },
      });
      assertEquals(admitted.status, 200);
      assertEquals(await admitted.json(), {
        door: "tailnet",
        sub: "native:worker",
        tokenLabel: "worker",
      });
      const jwt = await fixture.signToken({ claims: { sub: "auth0|user" } });
      for (const marker of [undefined, "1"]) {
        const headers = new Headers({
          "authorization": `Bearer ${jwt}`,
          "x-brain-key": "valid-token",
          "tailscale-funnel-request": "?1",
        });
        if (marker) headers.set("x-openbrain-tailnet", marker);
        const response = await app.request("/", { headers });
        assertEquals(response.status, 200);
        assertEquals(await response.json(), {
          door: "funnel",
          sub: "auth0|user",
          tokenLabel: null,
        });
      }
      assertEquals(lookups, 1);
    } finally {
      restore();
    }
  }),
);
