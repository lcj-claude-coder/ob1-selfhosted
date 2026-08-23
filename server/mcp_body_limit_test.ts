// Regression coverage for the application-side MCP request-body ceiling.
// The test uses the exact middleware mounted by index.ts, while replacing auth
// and the MCP handler with sentinels so no database or transport is required.

import { assert, assertEquals } from "@std/assert";
import { type Context, Hono, type MiddlewareHandler } from "hono";
import {
  MAX_REQUEST_BODY_BYTES,
  mcpRequestBodyLimit,
} from "./request_body_limit.ts";

const MCP_PATHS = ["/mcp", "/"] as const;
const STREAM_CHUNK_BYTES = 64 * 1024;
const STREAM_TOTAL_BYTES = MAX_REQUEST_BODY_BYTES * 4;

function makeCountingBody(totalBytes = STREAM_TOTAL_BYTES) {
  let bytesProduced = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (bytesProduced >= totalBytes) {
        controller.close();
        return;
      }
      const chunkBytes = Math.min(
        STREAM_CHUNK_BYTES,
        totalBytes - bytesProduced,
      );
      bytesProduced += chunkBytes;
      controller.enqueue(new Uint8Array(chunkBytes));
    },
  }, { highWaterMark: 0 });
  return {
    body,
    bytesProduced: () => bytesProduced,
  };
}

function makeApp() {
  const app = new Hono();
  let authCalls = 0;
  let downstreamCalls = 0;

  const authenticate: MiddlewareHandler = async (c, next) => {
    authCalls++;
    if (c.req.header("authorization") !== "Bearer test") {
      return c.text("Unauthorized", 401);
    }
    await next();
  };

  const downstream = async (c: Context) => {
    downstreamCalls++;
    return c.json({ received: await c.req.json() });
  };

  app.all("/mcp", authenticate, mcpRequestBodyLimit, downstream);
  app.all("/", authenticate, mcpRequestBodyLimit, downstream);

  return {
    app,
    authCalls: () => authCalls,
    downstreamCalls: () => downstreamCalls,
  };
}

Deno.test("MCP transport body limit rejects bounded streams on both mounts", async (t) => {
  for (const path of MCP_PATHS) {
    await t.step(path, async () => {
      const fixture = makeApp();
      const source = makeCountingBody();
      const request = new Request(`http://localhost${path}`, {
        method: "POST",
        headers: {
          authorization: "Bearer test",
          "content-type": "application/json",
        },
        body: source.body,
      });
      assertEquals(request.headers.has("content-length"), false);

      const response = await fixture.app.request(request);

      assertEquals(response.status, 413);
      assertEquals(fixture.authCalls(), 1);
      assertEquals(fixture.downstreamCalls(), 0);
      assert(
        source.bytesProduced() > MAX_REQUEST_BODY_BYTES,
        "stream must cross the configured limit before rejection",
      );
      assert(
        source.bytesProduced() <=
          MAX_REQUEST_BODY_BYTES + STREAM_CHUNK_BYTES,
        "bodyLimit must stop after the first limit-crossing chunk",
      );
      assert(
        source.bytesProduced() < STREAM_TOTAL_BYTES,
        "the complete oversized body must not be consumed",
      );
    });
  }
});

Deno.test("MCP transport body limit preserves small bodies on both mounts", async (t) => {
  for (const path of MCP_PATHS) {
    await t.step(path, async () => {
      const fixture = makeApp();
      const payload = { jsonrpc: "2.0", id: 1, method: "ping" };
      const response = await fixture.app.request(path, {
        method: "POST",
        headers: {
          authorization: "Bearer test",
          "content-type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      assertEquals(response.status, 200);
      assertEquals(await response.json(), { received: payload });
      assertEquals(fixture.authCalls(), 1);
      assertEquals(fixture.downstreamCalls(), 1);
    });
  }
});
