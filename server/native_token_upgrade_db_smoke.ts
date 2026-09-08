// Called only by the disposable DB-init native-token upgrade rehearsal.
import { assertRejects, assertStringIncludes } from "@std/assert";
import { Pool } from "postgres";
import { probeDbAtBoot } from "./db_boot_probe.ts";
const host = Deno.env.get("DB_SMOKE_HOST") ?? "127.0.0.1";
const port = Number(Deno.env.get("DB_SMOKE_PORT") ?? "55439");
const pool = new Pool({
  hostname: host,
  port,
  database: "openbrain",
  user: "openbrain_app",
  password: Deno.env.get("OPENBRAIN_APP_PASSWORD")!,
}, 1);
try {
  if (Deno.args[0] === "ready") await probeDbAtBoot(pool, "disposable-upgrade");
  else {
    const error = await assertRejects(
      () => probeDbAtBoot(pool, "disposable-upgrade"),
      Error,
    );
    assertStringIncludes(error.message, "db/14-native-token-principals.sql");
    if (Deno.args[0] === "unreadable") {
      assertStringIncludes(error.message, "unreadable");
    }
  }
} finally {
  await pool.end();
}
