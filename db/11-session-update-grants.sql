-- Least-privilege UPDATE grants for work sessions.
--
-- Apply after db/10-thought-mutations.sql and before starting a server version
-- that requires it, then run the stable db/03-grants-assertion.sql source last.
-- Requires the table owner (normally postgres). Idempotent; no rows are
-- rewritten.

BEGIN;

-- ---------- Session UPDATE is column-scoped -------------------------------
--
-- RLS confines ordinary server queries to the installed audience, but the
-- application role installs that audience itself. A table-wide UPDATE would
-- therefore let a compromised app credential rewrite workspace_id/project_id/
-- visibility/owner_subject directly. Session recapture is intentionally a
-- content refresh, not an audience-move operation, so keep those columns (and
-- the server-owned id/created_at) outside the app role's UPDATE surface.
--
-- Revoke both the historical table grant and any column-level drift on the
-- protected fields before restoring the exact content-column grant. The
-- explicit protected-column REVOKE is harmless on a clean catalog and makes a
-- re-application converge a manually widened deployment as well.
REVOKE UPDATE ON sessions.session FROM openbrain_app;
REVOKE UPDATE (
  id,
  workspace_id,
  project_id,
  visibility,
  owner_subject,
  created_at
) ON sessions.session FROM openbrain_app;
GRANT UPDATE (
  session_id,
  title,
  session_date,
  goal,
  agent,
  agent_version,
  harness,
  machine,
  working_dir,
  repo_url,
  branch,
  head,
  worktree,
  started_at,
  last_update,
  ended_at,
  status,
  tags,
  linked_issues,
  related_sessions,
  next_actions,
  blockers,
  resume_context,
  summary,
  source,
  source_node,
  raw_toml,
  content_hash,
  embedding,
  updated_at
) ON sessions.session TO openbrain_app;

-- ---------- Artifacts are delete-and-reinsert only -------------------------
--
-- session_capture reconciles artifacts with a qualified DELETE followed by
-- INSERTs; it never UPDATEs a child. In particular, session_pk is the child's
-- audience-bearing parent link, so no direct re-parenting privilege is needed.
REVOKE UPDATE ON sessions.artifact FROM openbrain_app;
REVOKE UPDATE (
  id,
  session_pk,
  position,
  kind,
  title,
  detail
) ON sessions.artifact FROM openbrain_app;

COMMIT;
