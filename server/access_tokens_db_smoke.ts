// Explicit CI smoke for the production native-token boundary.
//
// This is not a *_test.ts file: db-init.yml runs it only against its disposable,
// freshly initialized PostgreSQL container. It proves real deno-postgres BYTEA
// decoding, role grants, hash-only storage, attribution, and immediate revoke.

import { assert, assertEquals, assertMatch, assertRejects } from "@std/assert";
import { Pool } from "postgres";
import {
  authenticateAccessToken,
  createAccessToken,
  hashAccessToken,
  listAccessTokens,
  revokeAccessToken,
} from "./access_tokens.ts";

const host = Deno.env.get("DB_SMOKE_HOST") ?? "127.0.0.1";
const port = Number(Deno.env.get("DB_SMOKE_PORT") ?? "55439");
const postgresPassword = Deno.env.get("POSTGRES_PASSWORD");
const appPassword = Deno.env.get("OPENBRAIN_APP_PASSWORD");
const tokenAdminPassword = Deno.env.get("OPENBRAIN_TOKEN_ADMIN_PASSWORD");

assert(postgresPassword, "POSTGRES_PASSWORD is required");
assert(appPassword, "OPENBRAIN_APP_PASSWORD is required");
assert(tokenAdminPassword, "OPENBRAIN_TOKEN_ADMIN_PASSWORD is required");
assert(Number.isInteger(port) && port > 0, "DB_SMOKE_PORT must be a port");

const common = { hostname: host, port, database: "openbrain" };
const postgresPool = new Pool(
  { ...common, user: "postgres", password: postgresPassword },
  1,
);
const appPool = new Pool(
  { ...common, user: "openbrain_app", password: appPassword },
  1,
);
const tokenAdminPool = new Pool(
  {
    ...common,
    user: "openbrain_token_admin",
    password: tokenAdminPassword,
  },
  1,
);

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

const fixturePrefixes: string[] = [];
try {
  const created = await createAccessToken(
    tokenAdminPool,
    "CI driver smoke",
    "native:driver",
  );
  fixturePrefixes.push(created.prefix);
  assertMatch(created.token, /^ob1_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{43}$/);

  const astralLabel = "😀".repeat(65);
  const astral = await createAccessToken(
    tokenAdminPool,
    astralLabel,
    "native:astral",
  );
  fixturePrefixes.push(astral.prefix);
  assertEquals([...astral.label].length, 65);

  // Exercise SQL directly so a caller bypassing CLI validation cannot mint an
  // unowned token or impersonate an OAuth subject. NULL exists only for legacy
  // rows; invalid non-null values must fail the database shape constraint.
  const administrator = await tokenAdminPool.connect();
  try {
    for (
      const principal of [
        null,
        "",
        "auth0|user",
        "native:",
        "native:-start",
        " native:agent",
        "native:agent\n",
        "native:agent\u0085",
        `native:${"a".repeat(122)}`,
      ]
    ) {
      await assertRejects(
        () =>
          administrator.queryArray(
            "SELECT * FROM native_auth.register_access_token($1,$2,$3,$4)",
            [
              "ob1_BADPRINC",
              new Uint8Array(32),
              "invalid principal",
              principal,
            ],
          ),
        Error,
        principal === null
          ? "requires an explicit principal"
          : "access_token_principal_shape",
      );
    }
  } finally {
    administrator.release();
  }

  const postgres = await postgresPool.connect();
  try {
    const stored = await postgres.queryObject<{
      prefix: string;
      token_hash_hex: string;
      label: string;
      revoked_at: string | null;
    }>(
      `SELECT prefix, encode(token_hash, 'hex') AS token_hash_hex,
              label, revoked_at::text
       FROM native_auth.access_token
       WHERE prefix = $1`,
      [created.prefix],
    );
    assertEquals(stored.rows, [{
      prefix: created.prefix,
      token_hash_hex: toHex(await hashAccessToken(created.token)),
      label: "CI driver smoke",
      revoked_at: null,
    }]);
  } finally {
    postgres.release();
  }

  const inventory = await listAccessTokens(tokenAdminPool);
  assertEquals(inventory.length, 2);
  const standardMetadata = inventory.find((row) =>
    row.prefix === created.prefix
  );
  const astralMetadata = inventory.find((row) => row.prefix === astral.prefix);
  assertEquals(standardMetadata?.label, "CI driver smoke");
  assertEquals(standardMetadata?.principal, "native:driver");
  assertEquals(standardMetadata?.revoked_at, null);
  assertEquals(astralMetadata?.label, astralLabel);
  assertEquals(astralMetadata?.revoked_at, null);
  assertEquals("token" in inventory[0], false);

  assertEquals(await authenticateAccessToken(appPool, created.token), {
    label: "CI driver smoke",
    principal: "native:driver",
  });
  assertEquals(await authenticateAccessToken(appPool, astral.token), {
    label: astralLabel,
    principal: "native:astral",
  });

  const revoked = await revokeAccessToken(tokenAdminPool, created.prefix);
  assert(revoked?.revoked_at, "revoke must return its timestamp");
  assertEquals(revoked.principal, "native:driver");
  assertEquals(await authenticateAccessToken(appPool, created.token), null);
  assertEquals(await revokeAccessToken(tokenAdminPool, created.prefix), null);

  console.log("Deno/Postgres native-token lifecycle passed");
} finally {
  if (fixturePrefixes.length > 0) {
    const postgres = await postgresPool.connect();
    try {
      await postgres.queryArray(
        "DELETE FROM native_auth.access_token WHERE prefix = ANY($1::text[])",
        [fixturePrefixes],
      );
    } finally {
      postgres.release();
    }
  }
  await tokenAdminPool.end();
  await appPool.end();
  await postgresPool.end();
}
