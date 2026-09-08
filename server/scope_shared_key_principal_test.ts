// Positive regression for the single-user local deployment: a shared key is
// not identity by itself, but the operator may bind that whole door to one
// stable server-owned principal so the seeded sensitive workspace is usable.

import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { asPool, FakePool, withEnv } from "./api_test_support.ts";

const { resolveReadScope, resolveWriteScope, trustedPrincipal } = await withEnv(
  [],
  {
    DB_PASSWORD: "test-password",
    MCP_ACCESS_KEY: "k".repeat(64),
    MCP_ACCESS_KEY_PRINCIPAL: "local-owner",
    METADATA_FALLBACK_POLICY: "off",
  },
  () => import("./scope.ts"),
)();

Deno.test("configured shared-key principal owns sensitive personal scope", async () => {
  const pool = asPool(
    new FakePool((sql) =>
      sql.includes("FROM memory_scope.workspace")
        ? {
          rows: [{
            default_visibility: "personal",
            personal_only: true,
            project_exists: true,
          }],
        }
        : undefined
    ),
  );
  const auth = { door: "tailnet" as const, sub: null, tokenLabel: null };

  assertEquals(trustedPrincipal(auth), "local-owner");
  assertEquals(
    await resolveWriteScope(pool, { workspace_id: "sensitive" }, auth),
    {
      workspaceId: "sensitive",
      projectId: null,
      visibility: "personal",
      visibilities: ["personal"],
      principal: "local-owner",
      ownerSubject: "local-owner",
    },
  );
  assertEquals(
    await resolveReadScope(pool, { workspace_id: "sensitive" }, auth),
    {
      workspaceId: "sensitive",
      projectId: null,
      visibilities: ["personal"],
      principal: "local-owner",
    },
  );
});

Deno.test("native tokens never fall back to the shared key principal", async () => {
  const pool = asPool(
    new FakePool((sql) =>
      sql.includes("FROM memory_scope.workspace")
        ? {
          rows: [{
            default_visibility: "personal",
            personal_only: true,
            project_exists: true,
          }],
        }
        : undefined
    ),
  );
  const legacy = { door: "tailnet" as const, sub: null, tokenLabel: "legacy" };
  assertEquals(trustedPrincipal(legacy), null);
  await assertRejects(() =>
    resolveWriteScope(pool, { workspace_id: "sensitive" }, legacy)
  );
  await assertRejects(() =>
    resolveReadScope(pool, { workspace_id: "sensitive" }, legacy)
  );
  const native = { ...legacy, sub: "native:agent" };
  assertEquals(
    (await resolveWriteScope(pool, { workspace_id: "sensitive" }, native))
      .ownerSubject,
    "native:agent",
  );
});
