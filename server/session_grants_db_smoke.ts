// PostgreSQL regression for the production session write queries under the
// column-scoped grants established by db/11-session-update-grants.sql.
//
// This file is intentionally not named *_test.ts: the ordinary hermetic suite
// has no PostgreSQL dependency. The DB-init workflow runs it against its
// disposable, fully initialized pgvector container as the real
// openbrain_app role. It proves that fresh capture, full refresh, artifact
// reconciliation, and status updates still execute while direct session
// audience writes and artifact re-parenting are denied by ACLs.

import { assert, assertEquals, assertRejects } from "@std/assert";
import { Pool } from "postgres";
import type { PoolClient } from "postgres";

const host = Deno.env.get("DB_SMOKE_HOST") ?? "127.0.0.1";
const port = Number(Deno.env.get("DB_SMOKE_PORT") ?? "55439");
const adminPassword = Deno.env.get("POSTGRES_PASSWORD");
const appPassword = Deno.env.get("OPENBRAIN_APP_PASSWORD");

assert(adminPassword, "POSTGRES_PASSWORD is required");
assert(appPassword, "OPENBRAIN_APP_PASSWORD is required");
assert(Number.isInteger(port) && port > 0, "DB_SMOKE_PORT must be a port");

// session_queries.ts imports the production config graph through embeddings.
Deno.env.set("DB_PASSWORD", appPassword);
Deno.env.set("MCP_ACCESS_KEY", "session-grants-smoke-key".repeat(4));
Deno.env.set("METADATA_FALLBACK_POLICY", "off");

const {
  getSession,
  updateSessionStatus,
  upsertSession,
} = await import("./session_queries.ts");
const { parseSessionToml } = await import("./session_toml.ts");
const { withScopeClient } = await import("./scoped_db.ts");

const database = "openbrain";
const TITLE_PREFIX = "__session_grants_db_smoke";
const ZERO_VECTOR = new Array(768).fill(0);
const ONE_VECTOR = ZERO_VECTOR.map((_, index) => index === 0 ? 1 : 0);

const adminPool = new Pool(
  { hostname: host, port, database, user: "postgres", password: adminPassword },
  1,
);
const appPool = new Pool(
  {
    hostname: host,
    port,
    database,
    user: "openbrain_app",
    password: appPassword,
  },
  2,
);

const scope = {
  workspaceId: "default",
  projectId: null,
  visibility: "workspace" as const,
  visibilities: ["workspace" as const],
  principal: null,
  ownerSubject: null,
};

async function withAdmin<T>(
  operation: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await adminPool.connect();
  try {
    return await operation(client);
  } finally {
    client.release();
  }
}

async function cleanFixture(): Promise<void> {
  await withAdmin(async (client) => {
    await client.queryArray(
      "DELETE FROM sessions.session WHERE title LIKE $1",
      [`${TITLE_PREFIX}%`],
    );
  });
}

await cleanFixture();
try {
  const initialToml = `+++
title = "${TITLE_PREFIX}_initial"
status = "active"
summary = "initial capture"
tags = ["security"]

[[artifacts]]
kind = "note"
title = "initial artifact"
+++`;
  const initial = parseSessionToml(initialToml);
  const created = await upsertSession(appPool, {
    session: initial.session,
    artifacts: initial.artifacts,
    contentHash: "session-grants-smoke-hash-1",
    embedding: ZERO_VECTOR,
    provenance: { source: "service", sourceNode: "session-grants-smoke" },
    rawToml: initial.rawToml,
    scope,
  });
  assertEquals(created.created, true);
  assertEquals(created.workspace_id, "default");
  assertEquals(created.project_id, null);
  assertEquals(created.visibility, "workspace");

  const refreshedToml = `+++
id = ${created.id}
session_id = "session-grants-smoke-handle"
title = "${TITLE_PREFIX}_refreshed"
session_date = "2026-08-23"
goal = "exercise every production refresh assignment"
agent = "db-smoke"
agent_version = "1"
harness = "db-init"
machine = "fixture"
working_dir = "/fixture"
repo_url = "https://example.invalid/fixture"
branch = "fixture"
head = "deadbeef"
worktree = "/fixture"
started_at = "2026-08-23T00:00:00Z"
last_update = "2026-08-23T01:00:00Z"
ended_at = "2026-08-23T02:00:00Z"
status = "awaiting_review"
tags = ["security", "postgresql"]
linked_issues = ["EXAMPLE-123"]
related_sessions = ["123"]
next_actions = ["review"]
blockers = []
resume_context = "refresh context"
summary = "refreshed capture"
workspace_id = "default"
visibility = "workspace"

[[artifacts]]
kind = "pr"
title = "replacement artifact one"

[[artifacts]]
kind = "note"
title = "replacement artifact two"
detail = "delete-and-reinsert path"
+++`;
  const refreshed = parseSessionToml(refreshedToml);
  const updated = await upsertSession(appPool, {
    session: refreshed.session,
    artifacts: refreshed.artifacts,
    contentHash: "session-grants-smoke-hash-2",
    embedding: ONE_VECTOR,
    provenance: { source: "funnel", sourceNode: "auth0|session-smoke" },
    rawToml: refreshed.rawToml,
    scope,
  });
  assertEquals(updated.created, false);
  assertEquals(updated.id, created.id);
  assertEquals(updated.status, "awaiting_review");

  assertEquals(
    await updateSessionStatus(appPool, created.id, "done", scope),
    { id: created.id, status: "done" },
  );
  const record = await getSession(appPool, created.id, scope);
  assert(record);
  assertEquals(record.title, `${TITLE_PREFIX}_refreshed`);
  assertEquals(record.status, "done");
  assertEquals(record.source, "funnel");
  assertEquals(record.source_node, "auth0|session-smoke");
  assertEquals(record.workspace_id, "default");
  assertEquals(record.project_id, null);
  assertEquals(record.visibility, "workspace");
  assertEquals(record.artifacts.map((artifact) => artifact.title), [
    "replacement artifact one",
    "replacement artifact two",
  ]);

  await assertRejects(
    () =>
      withScopeClient(appPool, scope, async (client) => {
        await client.queryArray(
          `UPDATE sessions.session
           SET workspace_id = workspace_id
           WHERE id = $1`,
          [created.id],
        );
      }),
    Error,
    "permission denied",
  );
  await assertRejects(
    () =>
      withScopeClient(appPool, scope, async (client) => {
        await client.queryArray(
          `UPDATE sessions.artifact
           SET session_pk = session_pk
           WHERE session_pk = $1`,
          [created.id],
        );
      }),
    Error,
    "permission denied",
  );

  console.log(
    "session grant smoke: capture, refresh, artifact reconciliation, status, and ACL denials passed",
  );
} finally {
  await cleanFixture();
  await appPool.end();
  await adminPool.end();
}
