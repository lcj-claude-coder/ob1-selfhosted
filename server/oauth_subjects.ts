// OAuth admission lookups and the operator-only lifecycle. No config.ts import:
// the CLI needs only its dedicated DB credential, never the MCP configuration.
import type { Pool } from "postgres";
import { isNativeTokenLabel, isOAuthSubject } from "./auth_context.ts";
import { getClient } from "./db_pool.ts";

export type OAuthSubjectKind = "user" | "service";
export type OAuthSubjectLookup = (
  subject: string,
) => Promise<OAuthSubjectKind | null>;

export function validateOAuthSubject(subject: string): string {
  if (!isOAuthSubject(subject)) throw new Error("Invalid OAuth subject");
  return subject;
}

export async function lookupOAuthSubject(
  pool: Pool,
  subject: string,
): Promise<OAuthSubjectKind | null> {
  validateOAuthSubject(subject);
  const client = await getClient(pool);
  try {
    const result = await client.queryObject<
      { kind: unknown; revoked_at: unknown }
    >(
      `SELECT kind, revoked_at FROM oauth_auth.allowed_subject WHERE subject = $1`,
      [subject],
    );
    const row = result.rows[0];
    return row?.revoked_at === null &&
        (row.kind === "user" || row.kind === "service")
      ? row.kind
      : null;
  } finally {
    client.release();
  }
}

export async function hasActiveOAuthSubjects(pool: Pool): Promise<boolean> {
  const client = await getClient(pool);
  try {
    const result = await client.queryObject<{ active: boolean }>(
      `SELECT EXISTS (
        SELECT 1 FROM oauth_auth.allowed_subject WHERE revoked_at IS NULL
      ) AS active`,
    );
    return result.rows[0]?.active === true;
  } finally {
    client.release();
  }
}

export type OAuthSubjectMetadata = {
  subject: string;
  label: string | null;
  kind: OAuthSubjectKind;
  created_at: Date;
  revoked_at: Date | null;
};

export async function allowOAuthSubject(
  pool: Pool,
  subject: string,
  label: string | null,
  kind: OAuthSubjectKind,
): Promise<OAuthSubjectMetadata> {
  validateOAuthSubject(subject);
  if (label !== null && !isNativeTokenLabel(label)) {
    throw new Error("Invalid OAuth subject label");
  }
  if (kind !== "user" && kind !== "service") {
    throw new Error("Subject kind must be user or service");
  }
  const client = await getClient(pool);
  try {
    const result = await client.queryObject<OAuthSubjectMetadata>(
      `SELECT subject, label, kind, created_at, revoked_at
       FROM oauth_auth.allow_subject($1, $2, $3)`,
      [subject, label, kind],
    );
    if (!result.rows[0]) throw new Error("Subject enrollment returned no row");
    return result.rows[0];
  } finally {
    client.release();
  }
}

export async function listOAuthSubjects(
  pool: Pool,
): Promise<OAuthSubjectMetadata[]> {
  const client = await getClient(pool);
  try {
    return (await client.queryObject<OAuthSubjectMetadata>(
      `SELECT subject, label, kind, created_at, revoked_at
       FROM oauth_auth.allowed_subject ORDER BY created_at, subject`,
    )).rows;
  } finally {
    client.release();
  }
}

export async function revokeOAuthSubject(
  pool: Pool,
  subject: string,
): Promise<OAuthSubjectMetadata | null> {
  validateOAuthSubject(subject);
  const client = await getClient(pool);
  try {
    return (await client.queryObject<OAuthSubjectMetadata>(
      `SELECT subject, label, kind, created_at, revoked_at
       FROM oauth_auth.revoke_subject($1)`,
      [subject],
    )).rows[0] ?? null;
  } finally {
    client.release();
  }
}

export function parseLegacySubjects(raw: string): string[] {
  if (!raw.trim()) return [];
  const subjects = raw.split(",").map((subject) =>
    validateOAuthSubject(subject.trim())
  );
  if (subjects.length > 256 || new Set(subjects).size !== subjects.length) {
    throw new Error("Legacy list must contain at most 256 unique subjects");
  }
  return subjects;
}

export async function importOAuthSubjects(
  pool: Pool,
  allowed: string[],
  services: string[],
): Promise<number> {
  if (allowed.length === 0) throw new Error("OAUTH_ALLOWED_SUBJECTS is empty");
  const client = await getClient(pool);
  try {
    const result = await client.queryObject<{ added: number }>(
      `SELECT oauth_auth.import_subjects($1, $2) AS added`,
      [allowed, services],
    );
    return result.rows[0].added;
  } finally {
    client.release();
  }
}
