import type { ColPolicy } from "./compiler";
import type { Env, MaskStrategy } from "./types";

// Thin typed helpers over D1. Kept deliberately small — no ORM.

export interface AccountRow {
  id: string;
  owner_email: string;
}
export interface DatabaseRow {
  id: string;
  account_id: string;
  name: string;
  conn_enc: string;
  default_deny: number; // 1 = allowlist (only enabled columns are readable)
}

// A resolved token: scopes/databases JSON-parsed into arrays.
export interface Token {
  id: string;
  account_id: string;
  scopes: string[];
  databases: string[];
}

const nowIso = () => new Date().toISOString();

// Look up a token by hash, parse its scopes/databases, and best-effort update
// last_used_at. Returns null when the hash is unknown.
export async function tokenByHash(
  env: Env,
  hash: string,
): Promise<Token | null> {
  const row = await env.DB.prepare(
    "SELECT id, account_id, scopes, databases FROM tokens WHERE token_hash = ?",
  )
    .bind(hash)
    .first<{
      id: string;
      account_id: string;
      scopes: string;
      databases: string;
    }>();
  if (!row) return null;
  return {
    id: row.id,
    account_id: row.account_id,
    scopes: JSON.parse(row.scopes) as string[],
    databases: JSON.parse(row.databases) as string[],
  };
}

export async function touchToken(env: Env, tokenId: string): Promise<void> {
  await env.DB.prepare("UPDATE tokens SET last_used_at = ? WHERE id = ?")
    .bind(nowIso(), tokenId)
    .run();
}

export async function databaseById(
  env: Env,
  accountId: string,
  dbId: string,
): Promise<DatabaseRow | null> {
  return env.DB.prepare(
    "SELECT id, account_id, name, conn_enc, default_deny FROM databases WHERE id = ? AND account_id = ?",
  )
    .bind(dbId, accountId)
    .first<DatabaseRow>();
}

export interface ResolvedPolicy {
  // Policy for a given (table, column).
  policyFor: (table: string, col: string) => ColPolicy;
  // Tables with >= 1 enabled column (used to hide tables under default-deny).
  enabledTables: Set<string>;
}

// The masking baseline for a database.
// - default-deny (allowlist): a column with no policy row is HIDDEN (enabled:false).
// - default-allow: a column with no policy row is visible + unmasked.
export async function loadPolicy(
  env: Env,
  dbId: string,
  defaultDeny: boolean,
): Promise<ResolvedPolicy> {
  const { results } = await env.DB.prepare(
    "SELECT table_name, column_name, enabled, mask FROM column_policies WHERE database_id = ?",
  )
    .bind(dbId)
    .all<{
      table_name: string;
      column_name: string;
      enabled: number;
      mask: MaskStrategy;
    }>();

  const map = new Map<string, ColPolicy>();
  const enabledTables = new Set<string>();
  for (const r of results) {
    const enabled = r.enabled === 1;
    map.set(`${r.table_name} ${r.column_name}`, { enabled, mask: r.mask });
    if (enabled) enabledTables.add(r.table_name);
  }

  const fallback: ColPolicy = defaultDeny
    ? { enabled: false, mask: "none" }
    : { enabled: true, mask: "none" };

  return {
    policyFor: (table, col) => map.get(`${table} ${col}`) ?? fallback,
    enabledTables,
  };
}

export interface PolicyRow {
  table_name: string;
  column_name: string;
  enabled: number;
  mask: MaskStrategy;
}

// Raw column_policies rows for a database (used by GET policy).
export async function listPolicyRows(
  env: Env,
  dbId: string,
): Promise<PolicyRow[]> {
  const { results } = await env.DB.prepare(
    "SELECT table_name, column_name, enabled, mask FROM column_policies WHERE database_id = ? ORDER BY table_name, column_name",
  )
    .bind(dbId)
    .all<PolicyRow>();
  return results;
}

export async function audit(
  env: Env,
  accountId: string,
  actor: string,
  action: string,
  detail?: unknown,
): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO audit_log (id, account_id, actor, action, detail, created_at) VALUES (?,?,?,?,?,?)",
  )
    .bind(
      crypto.randomUUID(),
      accountId,
      actor,
      action,
      detail ? JSON.stringify(detail) : null,
      nowIso(),
    )
    .run();
}
