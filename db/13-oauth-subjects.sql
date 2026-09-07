-- OAuth admission is operator-managed data. Apply as the database owner in a
-- transaction, then run 03-grants-assertion.sql before starting the new server.
-- The existing credential administrator manages both native and OAuth access;
-- neither its credential nor write privileges belong to the MCP runtime.

CREATE SCHEMA IF NOT EXISTS oauth_auth;
REVOKE ALL ON SCHEMA oauth_auth FROM PUBLIC;

CREATE TABLE IF NOT EXISTS oauth_auth.allowed_subject (
  subject TEXT COLLATE "C" PRIMARY KEY,
  label TEXT COLLATE "C",
  kind TEXT COLLATE "C" NOT NULL CHECK (kind IN ('user', 'service')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ,
  CONSTRAINT allowed_subject_shape CHECK (
    char_length(subject) BETWEEN 1 AND 1024
    AND subject = btrim(subject, U&'\0009\000A\000B\000C\000D\0020\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000\FEFF')
    AND subject = translate(
      subject,
      U&'\0001\0002\0003\0004\0005\0006\0007\0008\0009\000A\000B\000C\000D\000E\000F' ||
      U&'\0010\0011\0012\0013\0014\0015\0016\0017\0018\0019\001A\001B\001C\001D\001E\001F' ||
      U&'\007F\0080\0081\0082\0083\0084\0085\0086\0087\0088\0089\008A\008B\008C\008D\008E\008F' ||
      U&'\0090\0091\0092\0093\0094\0095\0096\0097\0098\0099\009A\009B\009C\009D\009E\009F',
      ''
    )
  ),
  CONSTRAINT allowed_subject_label_shape CHECK (
    label IS NULL OR (
      char_length(label) BETWEEN 1 AND 128
      AND label = btrim(label, U&'\0009\000A\000B\000C\000D\0020\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000\FEFF')
      AND label = translate(
        label,
        U&'\0001\0002\0003\0004\0005\0006\0007\0008\0009\000A\000B\000C\000D\000E\000F' ||
        U&'\0010\0011\0012\0013\0014\0015\0016\0017\0018\0019\001A\001B\001C\001D\001E\001F' ||
        U&'\007F\0080\0081\0082\0083\0084\0085\0086\0087\0088\0089\008A\008B\008C\008D\008E\008F' ||
        U&'\0090\0091\0092\0093\0094\0095\0096\0097\0098\0099\009A\009B\009C\009D\009E\009F',
        ''
      )
    )
  ),
  CONSTRAINT allowed_subject_revocation_order CHECK (
    revoked_at IS NULL OR revoked_at >= created_at
  )
);

CREATE OR REPLACE FUNCTION oauth_auth.allow_subject(
  requested_subject TEXT, requested_label TEXT, requested_kind TEXT
)
RETURNS TABLE (subject TEXT, label TEXT, kind TEXT, created_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, oauth_auth
AS $function$
  INSERT INTO oauth_auth.allowed_subject (subject, label, kind)
  VALUES (requested_subject, requested_label, requested_kind)
  ON CONFLICT (subject) DO UPDATE
    SET label = EXCLUDED.label, kind = EXCLUDED.kind, revoked_at = NULL
  RETURNING allowed_subject.subject, allowed_subject.label, allowed_subject.kind,
            allowed_subject.created_at, allowed_subject.revoked_at;
$function$;

CREATE OR REPLACE FUNCTION oauth_auth.revoke_subject(requested_subject TEXT)
RETURNS TABLE (subject TEXT, label TEXT, kind TEXT, created_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, oauth_auth
AS $function$
  UPDATE oauth_auth.allowed_subject
  SET revoked_at = GREATEST(clock_timestamp(), created_at)
  WHERE subject = requested_subject AND revoked_at IS NULL
  RETURNING allowed_subject.subject, allowed_subject.label, allowed_subject.kind,
            allowed_subject.created_at, allowed_subject.revoked_at;
$function$;

-- Transition-release bridge, invoked explicitly by subject-admin import-env
-- BEFORE server startup using the admin credential. Never seed as the runtime
-- role, and never treat "no active rows" as an empty table. Revoked rows prevent
-- re-import. The lock serializes the empty check with all enrollment/revocation
-- writes, including another import; a failed import rolls back as a unit.
CREATE OR REPLACE FUNCTION oauth_auth.import_subjects(
  allowed TEXT[], services TEXT[]
)
RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, oauth_auth
AS $function$
DECLARE added INTEGER;
BEGIN
  IF allowed IS NULL OR cardinality(allowed) NOT BETWEEN 1 AND 256
     OR services IS NULL OR cardinality(services) > 256
     OR array_position(allowed, NULL) IS NOT NULL
     OR array_position(services, NULL) IS NOT NULL THEN
    RAISE EXCEPTION 'invalid legacy subject lists';
  END IF;
  LOCK TABLE oauth_auth.allowed_subject IN SHARE ROW EXCLUSIVE MODE;
  IF EXISTS (SELECT 1 FROM oauth_auth.allowed_subject) THEN
    RETURN 0;
  END IF;
  INSERT INTO oauth_auth.allowed_subject (subject, kind)
  SELECT value, CASE WHEN value COLLATE "C" = ANY(services) THEN 'service' ELSE 'user' END
  FROM unnest(allowed) AS value;
  GET DIAGNOSTICS added = ROW_COUNT;
  RETURN added;
END;
$function$;

REVOKE ALL ON SCHEMA oauth_auth
  FROM openbrain_app, openbrain_token_admin, openbrain_readonly;
REVOKE ALL ON oauth_auth.allowed_subject
  FROM PUBLIC, openbrain_app, openbrain_token_admin, openbrain_readonly;
-- Table-level REVOKE does not clear historical column-level grants.
REVOKE ALL (subject, label, kind, created_at, revoked_at)
  ON oauth_auth.allowed_subject
  FROM PUBLIC, openbrain_app, openbrain_token_admin, openbrain_readonly;
REVOKE ALL ON FUNCTION oauth_auth.allow_subject(TEXT, TEXT, TEXT),
  oauth_auth.revoke_subject(TEXT), oauth_auth.import_subjects(TEXT[], TEXT[])
  FROM PUBLIC, openbrain_app, openbrain_token_admin, openbrain_readonly;

GRANT USAGE ON SCHEMA oauth_auth
  TO openbrain_app, openbrain_token_admin, openbrain_readonly;
GRANT SELECT (subject, label, kind, revoked_at)
  ON oauth_auth.allowed_subject TO openbrain_app;
GRANT SELECT (subject, label, kind, created_at, revoked_at)
  ON oauth_auth.allowed_subject TO openbrain_token_admin;
GRANT EXECUTE ON FUNCTION oauth_auth.allow_subject(TEXT, TEXT, TEXT),
  oauth_auth.revoke_subject(TEXT), oauth_auth.import_subjects(TEXT[], TEXT[])
  TO openbrain_token_admin;
GRANT SELECT ON oauth_auth.allowed_subject TO openbrain_readonly;
