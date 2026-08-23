// Shared application-layer request-body ceiling. Caddy independently applies
// an edge cap to public Funnel traffic, but direct tailnet/in-qube/loopback
// callers need the server itself to enforce a bound before JSON parsing.

import { bodyLimit } from "hono/body-limit";

export const MAX_REQUEST_BODY_BYTES = 1024 * 1024;

// Authentication stays outside this middleware in index.ts. That preserves the
// bounded, id-correlating auth-failure reader while ensuring authenticated MCP
// requests cannot reach @hono/mcp's ctx.req.json() without a hard memory bound.
export const mcpRequestBodyLimit = bodyLimit({
  maxSize: MAX_REQUEST_BODY_BYTES,
});
