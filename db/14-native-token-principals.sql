-- Stable per-token ownership. Apply after 08 and 13, as the database owner,
-- in a transaction with 03-grants-assertion.sql; stop MCP before upgrading.
-- Existing tokens deliberately keep NULL: never copy a shared-key/OAuth
-- principal or infer identity from a label. Rotate them with an explicit
-- principal to enable personal memory; workspace/project access is unchanged.
ALTER TABLE native_auth.access_token
  ADD COLUMN IF NOT EXISTS principal TEXT COLLATE "C";
ALTER TABLE native_auth.access_token
  DROP CONSTRAINT IF EXISTS access_token_principal_shape,
  ADD CONSTRAINT access_token_principal_shape CHECK (
    principal IS NULL OR (
      principal COLLATE "C" ~ '^native:[A-Za-z0-9][A-Za-z0-9._-]{0,120}$'
      AND principal COLLATE "C" !~ '[^A-Za-z0-9:._-]'
    )
  );

-- Retire the principal-less overload, including all its execution grants.
-- No CASCADE: unexpected dependent objects must stop the migration for review.
DROP FUNCTION IF EXISTS native_auth.register_access_token(TEXT, BYTEA, TEXT);
CREATE OR REPLACE FUNCTION native_auth.register_access_token(
  requested_prefix TEXT,
  requested_hash BYTEA,
  requested_label TEXT,
  requested_principal TEXT
)
RETURNS TABLE (id BIGINT, prefix TEXT, label TEXT, principal TEXT, created_at TIMESTAMPTZ)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, native_auth
AS $function$
BEGIN
  IF requested_principal IS NULL THEN
    RAISE EXCEPTION 'native token creation requires an explicit principal';
  END IF;
  RETURN QUERY
    INSERT INTO native_auth.access_token (prefix, token_hash, label, principal)
    VALUES (requested_prefix, requested_hash, requested_label, requested_principal)
    RETURNING access_token.id, access_token.prefix, access_token.label,
              access_token.principal, access_token.created_at;
END;
$function$;

-- Reconcile table AND column grants, including principal mutation on reapply.
REVOKE ALL ON native_auth.access_token
  FROM PUBLIC, openbrain_app, openbrain_token_admin, openbrain_readonly;
REVOKE ALL (id, prefix, token_hash, label, principal, created_at, revoked_at)
  ON native_auth.access_token
  FROM PUBLIC, openbrain_app, openbrain_token_admin, openbrain_readonly;
REVOKE ALL ON FUNCTION native_auth.register_access_token(TEXT, BYTEA, TEXT, TEXT),
  native_auth.revoke_access_token(TEXT)
  FROM PUBLIC, openbrain_app, openbrain_token_admin, openbrain_readonly;

GRANT SELECT (prefix, token_hash, label, principal, revoked_at)
  ON native_auth.access_token TO openbrain_app;
GRANT SELECT (id, prefix, label, principal, created_at, revoked_at)
  ON native_auth.access_token TO openbrain_token_admin;
GRANT EXECUTE ON FUNCTION native_auth.register_access_token(TEXT, BYTEA, TEXT, TEXT),
  native_auth.revoke_access_token(TEXT) TO openbrain_token_admin;
GRANT SELECT ON native_auth.access_token TO openbrain_readonly;
