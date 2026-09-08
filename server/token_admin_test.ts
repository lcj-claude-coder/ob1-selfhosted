import { assertEquals } from "@std/assert";
import { parseTokenAdminArgs } from "./token_admin.ts";

Deno.test("token-admin requires an explicit principal for creation", () => {
  assertEquals(
    parseTokenAdminArgs([
      "create",
      "client",
      "--principal",
      "native:agent",
      "--json",
    ]),
    {
      command: "create",
      value: "client",
      principal: "native:agent",
      json: true,
    },
  );
  for (
    const args of [
      ["create", "client"],
      ["create", "client", "--json"],
      ["create", "client", "--principal"],
      ["create", "client", "extra", "native:agent"],
      ["create", "client", "--principal", "native:agent", "extra"],
    ]
  ) assertEquals(parseTokenAdminArgs(args), null);
  assertEquals(
    parseTokenAdminArgs(["create", "--json", "--principal", "native:agent"]),
    {
      command: "create",
      value: "--json",
      principal: "native:agent",
      json: false,
    },
  );
});

Deno.test("token-admin list and revoke retain their trailing JSON flag", () => {
  assertEquals(parseTokenAdminArgs(["list", "--json"]), {
    command: "list",
    value: undefined,
    json: true,
  });
  assertEquals(parseTokenAdminArgs(["revoke", "ob1_AAECAwQF", "--json"]), {
    command: "revoke",
    value: "ob1_AAECAwQF",
    json: true,
  });
  assertEquals(parseTokenAdminArgs(["list", "extra", "extra"]), null);
});
