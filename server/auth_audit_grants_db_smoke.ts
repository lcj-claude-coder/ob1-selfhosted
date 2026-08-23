// Real-catalog regression for the auth-audit boot grant gate.
//
// This file is intentionally not named *_test.ts: the ordinary hermetic suite
// has no PostgreSQL dependency. The DB-init grants family runs it against its
// disposable, fully initialized pgvector container. Each case introduces
// security-relevant drift after db/03-grants-assertion.sql has already passed
// and proves the production boot probe refuses to serve until the drift is
// repaired.

import { assert, assertRejects, assertStringIncludes } from "@std/assert";
import { Pool, type PoolClient } from "postgres";
import { probeDbAtBoot } from "./db_boot_probe.ts";

const host = Deno.env.get("DB_SMOKE_HOST") ?? "127.0.0.1";
const port = Number(Deno.env.get("DB_SMOKE_PORT") ?? "55439");
const adminPassword = Deno.env.get("POSTGRES_PASSWORD");
const appPassword = Deno.env.get("OPENBRAIN_APP_PASSWORD");

assert(adminPassword, "POSTGRES_PASSWORD is required");
assert(appPassword, "OPENBRAIN_APP_PASSWORD is required");
assert(Number.isInteger(port) && port > 0, "DB_SMOKE_PORT must be a port");

const database = "openbrain";
const target = `${host}:${port}/${database}`;
const privilegedMutation =
  "memory_scope.move_thought(uuid,text,text,memory_scope.visibility,text,text)";

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
  1,
);

async function withAdmin(
  operation: (client: PoolClient) => Promise<void>,
): Promise<void> {
  const client = await adminPool.connect();
  try {
    await operation(client);
  } finally {
    client.release();
  }
}

async function adminSql(sql: string): Promise<void> {
  await withAdmin(async (client) => {
    await client.queryArray(sql);
  });
}

async function cleanDrift(): Promise<void> {
  await adminSql(`
    REVOKE TRUNCATE, REFERENCES, TRIGGER
      ON public.mcp_auth_events FROM openbrain_app;
    REVOKE GRANT OPTION FOR SELECT, INSERT
      ON public.mcp_auth_events FROM openbrain_app CASCADE;
    REVOKE SELECT (subject)
      ON public.mcp_auth_events FROM openbrain_app CASCADE;
    REVOKE SELECT, UPDATE
      ON SEQUENCE public.mcp_auth_events_id_seq FROM openbrain_app;
    REVOKE GRANT OPTION FOR USAGE
      ON SEQUENCE public.mcp_auth_events_id_seq FROM openbrain_app CASCADE;
    GRANT USAGE
      ON SEQUENCE public.mcp_auth_events_id_seq TO openbrain_app;

    REVOKE INSERT, UPDATE, TRUNCATE, REFERENCES, TRIGGER
      ON public.mcp_auth_events FROM openbrain_auth_rollup;
    REVOKE GRANT OPTION FOR SELECT, DELETE
      ON public.mcp_auth_events FROM openbrain_auth_rollup CASCADE;
    REVOKE ALL
      ON SEQUENCE public.mcp_auth_events_id_seq FROM openbrain_auth_rollup;
    REVOKE CREATE ON SCHEMA public FROM openbrain_auth_rollup CASCADE;
    REVOKE CREATE ON DATABASE openbrain FROM openbrain_auth_rollup CASCADE;
    REVOKE SELECT ON public.thoughts FROM openbrain_auth_rollup;
    REVOKE EXECUTE ON FUNCTION ${privilegedMutation}
      FROM openbrain_auth_rollup;
    REVOKE openbrain_readonly FROM openbrain_auth_rollup;
  `);
}

interface DriftCase {
  label: string;
  introduce: string;
  repair: string;
}

async function expectBootRefusal(drift: DriftCase): Promise<void> {
  await adminSql(drift.introduce);
  try {
    const error = await assertRejects(
      () => probeDbAtBoot(appPool, target),
      Error,
    );
    assertStringIncludes(error.message, "missing or widened auth-audit grants");
    assertStringIncludes(error.message, "db/12-auth-audit-grants.sql");
  } finally {
    await adminSql(drift.repair);
  }

  // Every repair returns to the exact accepted boundary before the next case.
  await probeDbAtBoot(appPool, target);
}

const driftCases: DriftCase[] = [
  {
    label: "application TRUNCATE",
    introduce: "GRANT TRUNCATE ON public.mcp_auth_events TO openbrain_app",
    repair: "REVOKE TRUNCATE ON public.mcp_auth_events FROM openbrain_app",
  },
  {
    label: "missing application sequence USAGE",
    introduce:
      "REVOKE USAGE ON SEQUENCE public.mcp_auth_events_id_seq FROM openbrain_app",
    repair:
      "GRANT USAGE ON SEQUENCE public.mcp_auth_events_id_seq TO openbrain_app",
  },
  {
    label: "rollup TRUNCATE",
    introduce:
      "GRANT TRUNCATE ON public.mcp_auth_events TO openbrain_auth_rollup",
    repair:
      "REVOKE TRUNCATE ON public.mcp_auth_events FROM openbrain_auth_rollup",
  },
  {
    label: "rollup DELETE grant option",
    introduce:
      "GRANT DELETE ON public.mcp_auth_events TO openbrain_auth_rollup WITH GRANT OPTION",
    repair:
      "REVOKE GRANT OPTION FOR DELETE ON public.mcp_auth_events FROM openbrain_auth_rollup CASCADE",
  },
  {
    label: "application column SELECT grant option",
    introduce:
      "GRANT SELECT (subject) ON public.mcp_auth_events TO openbrain_app WITH GRANT OPTION",
    repair:
      "REVOKE SELECT (subject) ON public.mcp_auth_events FROM openbrain_app CASCADE",
  },
  {
    label: "application sequence USAGE grant option",
    introduce:
      "GRANT USAGE ON SEQUENCE public.mcp_auth_events_id_seq TO openbrain_app WITH GRANT OPTION",
    repair:
      "REVOKE GRANT OPTION FOR USAGE ON SEQUENCE public.mcp_auth_events_id_seq FROM openbrain_app CASCADE",
  },
  {
    label: "rollup schema creation",
    introduce: "GRANT CREATE ON SCHEMA public TO openbrain_auth_rollup",
    repair: "REVOKE CREATE ON SCHEMA public FROM openbrain_auth_rollup CASCADE",
  },
  {
    label: "rollup database creation",
    introduce: "GRANT CREATE ON DATABASE openbrain TO openbrain_auth_rollup",
    repair:
      "REVOKE CREATE ON DATABASE openbrain FROM openbrain_auth_rollup CASCADE",
  },
  {
    label: "rollup sequence access",
    introduce:
      "GRANT USAGE ON SEQUENCE public.mcp_auth_events_id_seq TO openbrain_auth_rollup",
    repair:
      "REVOKE ALL ON SEQUENCE public.mcp_auth_events_id_seq FROM openbrain_auth_rollup",
  },
  {
    label: "rollup role membership",
    introduce: "GRANT openbrain_readonly TO openbrain_auth_rollup",
    repair: "REVOKE openbrain_readonly FROM openbrain_auth_rollup",
  },
  {
    label: "rollup sideways relation access",
    introduce: "GRANT SELECT ON public.thoughts TO openbrain_auth_rollup",
    repair: "REVOKE SELECT ON public.thoughts FROM openbrain_auth_rollup",
  },
  {
    label: "rollup privileged-function execution",
    introduce:
      `GRANT EXECUTE ON FUNCTION ${privilegedMutation} TO openbrain_auth_rollup`,
    repair:
      `REVOKE EXECUTE ON FUNCTION ${privilegedMutation} FROM openbrain_auth_rollup`,
  },
];

await cleanDrift();
try {
  await probeDbAtBoot(appPool, target);
  for (const drift of driftCases) {
    await expectBootRefusal(drift);
    console.log(`auth-audit boot grant smoke rejected ${drift.label}`);
  }
} finally {
  await cleanDrift();
  await appPool.end();
  await adminPool.end();
}

console.log(
  "auth-audit boot grant smoke: exact app and standalone rollup boundaries passed",
);
