// On-host CLI. The tools profile supplies only the credential-admin password.
import { Pool } from "postgres";
import {
  allowOAuthSubject,
  importOAuthSubjects,
  listOAuthSubjects,
  parseLegacySubjects,
  revokeOAuthSubject,
} from "./oauth_subjects.ts";
import { parseDbPort } from "./runtime_config.ts";

const USAGE = `Usage:
  subject-admin allow <subject> <user|service> [label] [--json]
  subject-admin list [--json]
  subject-admin revoke <subject> [--json]
  subject-admin import-env [--json]

allow explicitly enrolls or re-enrolls a subject; revoke takes effect on the
next request. import-env reads the legacy OAUTH_ALLOWED_SUBJECTS and
OAUTH_SERVICE_ACCOUNT_SUBJECTS environment variables and seeds only a completely
empty table. It never overwrites existing entries or revocations.`;

export async function runSubjectAdmin(
  args: string[],
  pool: Pool,
  legacy: { allowed: string; services: string } = { allowed: "", services: "" },
): Promise<number> {
  const json = args.at(-1) === "--json";
  const [command, ...values] = json ? args.slice(0, -1) : args;
  let result: unknown;
  if (command === "list" && values.length === 0) {
    result = await listOAuthSubjects(pool);
  } else if (
    command === "allow" && (values.length === 2 || values.length === 3) &&
    (values[1] === "user" || values[1] === "service")
  ) {
    result = await allowOAuthSubject(
      pool,
      values[0],
      values[2] ?? null,
      values[1],
    );
  } else if (command === "revoke" && values.length === 1) {
    result = await revokeOAuthSubject(pool, values[0]);
    if (!result) {
      console.error("No active subject matched.");
      return 1;
    }
  } else if (command === "import-env" && values.length === 0) {
    const added = await importOAuthSubjects(
      pool,
      parseLegacySubjects(legacy.allowed),
      parseLegacySubjects(legacy.services),
    );
    result = { added, skipped: added === 0 };
    if (!json) {
      console.log(
        added > 0
          ? `Imported ${added} subjects. Remove the legacy environment variables.`
          : "Import skipped: table already contains entries (including revoked entries).",
      );
      return 0;
    }
  } else {
    console.error(USAGE);
    return 2;
  }
  console.log(JSON.stringify(result, null, json ? undefined : 2));
  return 0;
}

async function main(): Promise<number> {
  const password = Deno.env.get("DB_PASSWORD");
  if (!password) throw new Error("Missing required env var: DB_PASSWORD");
  const pool = new Pool(
    {
      hostname: Deno.env.get("DB_HOST") || "127.0.0.1",
      port: parseDbPort(Deno.env.get("DB_PORT")),
      database: Deno.env.get("DB_NAME") || "openbrain",
      user: Deno.env.get("DB_USER") || "openbrain_token_admin",
      password,
    },
    1,
    true,
  );
  try {
    return await runSubjectAdmin(Deno.args, pool, {
      allowed: Deno.env.get("OAUTH_ALLOWED_SUBJECTS") ?? "",
      services: Deno.env.get("OAUTH_SERVICE_ACCOUNT_SUBJECTS") ?? "",
    });
  } finally {
    await pool.end().catch(() => {});
  }
}

if (import.meta.main) {
  try {
    Deno.exit(await main());
  } catch {
    // Driver/constraint errors can include SQL parameters, credentials, or
    // complete subject inventories. Keep failures opaque outside --list output.
    console.error(
      "[subject-admin] Failed; check arguments, DB connectivity, credentials, and migration 13.",
    );
    Deno.exit(1);
  }
}
