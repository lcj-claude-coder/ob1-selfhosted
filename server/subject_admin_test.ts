import { assertEquals, assertRejects, assertThrows } from "@std/assert";
import { makeFakePool } from "./api_test_support.ts";
import { runSubjectAdmin } from "./subject_admin.ts";
import { lookupOAuthSubject, parseLegacySubjects } from "./oauth_subjects.ts";

Deno.test("legacy lists validate before any import and never widen service-only admission", () => {
  assertEquals(parseLegacySubjects(" a , issuer|b "), ["a", "issuer|b"]);
  assertEquals(parseLegacySubjects(""), []);
  for (
    const raw of [
      "a,a",
      "a,",
      "a\nb",
      "a\u0080b",
      "a\ud800b",
      "x".repeat(1025),
      Array.from({ length: 257 }, (_, i) => `s${i}`).join(","),
    ]
  ) {
    assertThrows(() => parseLegacySubjects(raw));
  }
});

Deno.test("subject-admin binds literal identities and labels; invalid commands never reach DB", async () => {
  const logs: unknown[] = [];
  const oldLog = console.log;
  const oldError = console.error;
  console.log = (...args) => logs.push(args);
  console.error = (...args) => logs.push(args);
  const subject = "issuer|quote'--";
  const label = "Worker ' ; SELECT";
  const record = {
    subject,
    label,
    kind: "service",
    created_at: new Date(0),
    revoked_at: null,
  };
  const { pool, client } = makeFakePool((sql) => {
    if (sql.includes("oauth_auth.allow_subject")) return { rows: [record] };
    if (sql.includes("oauth_auth.revoke_subject")) return { rows: [] };
    if (sql.includes("oauth_auth.import_subjects")) {
      return { rows: [{ added: 1 }] };
    }
    return undefined;
  });
  try {
    for (
      const args of [
        [],
        ["allow", subject],
        ["allow", subject, "admin"],
        ["revoke"],
        ["list", "extra"],
        ["import-env", "extra"],
      ]
    ) {
      assertEquals(await runSubjectAdmin(args, pool), 2);
    }
    assertEquals(client.queryObjectCalls.length, 0);
    for (const invalid of [" padded", "padded ", "a\u0080b", "a\ud800b"]) {
      await assertRejects(
        () => runSubjectAdmin(["allow", invalid, "user"], pool),
        Error,
        "Invalid OAuth subject",
      );
    }
    assertEquals(client.queryObjectCalls.length, 0);
    assertEquals(
      await runSubjectAdmin(
        ["allow", subject, "service", label, "--json"],
        pool,
      ),
      0,
    );
    assertEquals(client.queryObjectCalls[0].params, [
      subject,
      label,
      "service",
    ]);
    assertEquals(client.queryObjectCalls[0].sql.includes(subject), false);
    assertEquals(await runSubjectAdmin(["revoke", subject], pool), 1);
    assertEquals(
      await runSubjectAdmin(["import-env", "--json"], pool, {
        allowed: "worker",
        services: "worker,unadmitted",
      }),
      0,
    );
    assertEquals(client.queryObjectCalls[2].params, [["worker"], [
      "worker",
      "unadmitted",
    ]]);
    for (const allowed of ["", "   "]) {
      assertEquals(
        await runSubjectAdmin(["import-env"], pool, { allowed, services: "" }),
        1,
      );
      assertEquals(logs.at(-1), [
        "No legacy subjects to import: OAUTH_ALLOWED_SUBJECTS is empty. " +
        "If already migrated, use subject-admin list; to enroll a new identity, use subject-admin allow.",
      ]);
    }
    assertEquals(client.queryObjectCalls.length, 3);
    assertEquals(client.releaseCalls, 3);
  } finally {
    console.log = oldLog;
    console.error = oldError;
  }
});

Deno.test("OAuth lookup rejects malformed rows and releases connections on DB errors", async () => {
  for (
    const row of [undefined, { kind: "owner", revoked_at: null }, {
      kind: "user",
      revoked_at: "yesterday",
    }, { kind: "service" }]
  ) {
    const { pool, client } = makeFakePool(() => ({ rows: row ? [row] : [] }));
    assertEquals(await lookupOAuthSubject(pool, "user"), null);
    assertEquals(client.releaseCalls, 1);
  }
  const { pool, client } = makeFakePool(() => {
    throw new Error("storage failed");
  });
  await assertRejects(
    () => lookupOAuthSubject(pool, "user"),
    Error,
    "storage failed",
  );
  assertEquals(client.releaseCalls, 1);
});
