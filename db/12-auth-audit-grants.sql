-- Tamper-evident application grants for the corpus auth-decision audit.
--
-- Apply after provisioning `openbrain_auth_rollup` and before starting a
-- server version that requires it, then run the stable
-- db/03-grants-assertion.sql source last. Requires the table owner (normally
-- postgres). Idempotent; no rows are rewritten.

BEGIN;

-- The request-path role writes auth decisions but must not be able to rewrite
-- or erase the evidence it generated. Revoke both the historical table-wide
-- privileges and any per-column UPDATE drift before restoring the exact
-- append/read contract.
REVOKE ALL ON public.mcp_auth_events FROM openbrain_app;
REVOKE UPDATE (
  id,
  ts,
  outcome,
  reason,
  middleware,
  door,
  subject,
  token_label,
  client_ip,
  path,
  inserted_at
) ON public.mcp_auth_events FROM openbrain_app;
GRANT SELECT, INSERT ON public.mcp_auth_events TO openbrain_app;

REVOKE ALL ON SEQUENCE public.mcp_auth_events_id_seq FROM openbrain_app;
GRANT USAGE ON SEQUENCE public.mcp_auth_events_id_seq TO openbrain_app;

-- The operational credential gets only what summarize_auth_events.sql uses:
-- SELECT for its report and DELETE for the two bounded retention statements.
-- It cannot insert or update audit rows and has no sequence access.
REVOKE ALL ON public.mcp_auth_events FROM openbrain_auth_rollup;
REVOKE UPDATE (
  id,
  ts,
  outcome,
  reason,
  middleware,
  door,
  subject,
  token_label,
  client_ip,
  path,
  inserted_at
) ON public.mcp_auth_events FROM openbrain_auth_rollup;
GRANT SELECT, DELETE ON public.mcp_auth_events TO openbrain_auth_rollup;
REVOKE ALL ON SEQUENCE public.mcp_auth_events_id_seq
  FROM openbrain_auth_rollup;

COMMIT;
