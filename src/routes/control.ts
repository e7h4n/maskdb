import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { requireAdmin } from "../auth";
import { decryptSecret, encryptSecret, hashToken, newToken } from "../crypto";
import { connect, describeTable, listTables } from "../pg";
import { audit, databaseById } from "../store";
import {
  AddDatabaseBody,
  type Env,
  MintTokenBody,
  PolicyBody,
  RegisterBody,
  type Vars,
} from "../types";

type Ctx = { Bindings: Env; Variables: Vars };

// Admin-plane routes. requireAdmin is applied per-route (not as blanket
// middleware) so that data-plane requests falling through this sub-app are
// not rejected before reaching their handler. GET /v1/databases is shared
// by both planes and lives in index.ts.
export const control = new Hono<Ctx>();

const nowIso = () => new Date().toISOString();

// POST /v1/databases — register a user Postgres database.
control.post("/databases", requireAdmin, async (c) => {
  const body = AddDatabaseBody.parse(await c.req.json());
  const { accountId } = c.get("principal");

  // Validate the credentials up front so misconfig fails loudly, not later.
  const probe = connect(body.connection_string);
  try {
    await probe`SELECT 1`;
  } catch (e) {
    throw new HTTPException(400, {
      message: `could not connect: ${(e as Error).message}`,
    });
  } finally {
    await probe.end();
  }

  const id = crypto.randomUUID();
  const conn_enc = await encryptSecret(c.env.MASTER_KEY, body.connection_string);
  await c.env.DB.prepare(
    "INSERT INTO databases (id, account_id, name, conn_enc, created_at, default_deny) VALUES (?,?,?,?,?,?)",
  )
    .bind(id, accountId, body.name, conn_enc, nowIso(), body.default_deny ? 1 : 0)
    .run();

  await audit(c.env, accountId, "admin", "db.add", {
    db_id: id,
    name: body.name,
    default_deny: body.default_deny,
  });
  return c.json({ db_id: id, name: body.name, default_deny: body.default_deny }, 201);
});

// DELETE /v1/databases/:db
control.delete("/databases/:db", requireAdmin, async (c) => {
  const { accountId } = c.get("principal");
  const dbId = c.req.param("db");
  const res = await c.env.DB.prepare(
    "DELETE FROM databases WHERE id = ? AND account_id = ?",
  )
    .bind(dbId, accountId)
    .run();
  if (!res.meta.changes) throw new HTTPException(404, { message: "not found" });
  await audit(c.env, accountId, "admin", "db.delete", { db_id: dbId });
  return c.json({ ok: true });
});

// GET /v1/databases/:db/schema — RAW, unmasked schema to configure masking.
control.get("/databases/:db/schema", requireAdmin, async (c) => {
  const { accountId } = c.get("principal");
  const db = await databaseById(c.env, accountId, c.req.param("db"));
  if (!db) throw new HTTPException(404, { message: "not found" });

  const sql = connect(await decryptSecret(c.env.MASTER_KEY, db.conn_enc));
  try {
    const tables = await listTables(sql);
    const out = [];
    for (const table of tables) {
      out.push({ table, columns: await describeTable(sql, table) });
    }
    return c.json({ tables: out });
  } finally {
    await sql.end();
  }
});

// PUT /v1/databases/:db/policy — replace the masking baseline.
control.put("/databases/:db/policy", requireAdmin, async (c) => {
  const { accountId } = c.get("principal");
  const dbId = c.req.param("db");
  const db = await databaseById(c.env, accountId, dbId);
  if (!db) throw new HTTPException(404, { message: "not found" });

  const body = PolicyBody.parse(await c.req.json());
  const stmts = [
    c.env.DB.prepare("DELETE FROM column_policies WHERE database_id = ?").bind(
      dbId,
    ),
  ];
  let count = 0;
  for (const t of body.tables) {
    for (const col of t.columns) {
      count++;
      stmts.push(
        c.env.DB.prepare(
          "INSERT INTO column_policies (database_id, table_name, column_name, enabled, mask) VALUES (?,?,?,?,?)",
        ).bind(dbId, t.table, col.name, col.enabled ? 1 : 0, col.mask),
      );
    }
  }
  await c.env.DB.batch(stmts);
  await audit(c.env, accountId, "admin", "db.policy", { db_id: dbId, columns: count });
  return c.json({ ok: true, columns: count });
});

// POST /v1/agent-tokens — mint a read-only token scoped to a set of DBs.
control.post("/agent-tokens", requireAdmin, async (c) => {
  const { accountId } = c.get("principal");
  const body = MintTokenBody.parse(await c.req.json());

  // Every db_id must belong to this account.
  for (const dbId of body.db_ids) {
    if (!(await databaseById(c.env, accountId, dbId))) {
      throw new HTTPException(400, { message: `unknown db_id: ${dbId}` });
    }
  }

  const id = crypto.randomUUID();
  const token = newToken("mk_agent");
  await c.env.DB.prepare(
    "INSERT INTO agent_tokens (id, account_id, name, token_hash, db_ids, created_at) VALUES (?,?,?,?,?,?)",
  )
    .bind(
      id,
      accountId,
      body.name,
      await hashToken(token),
      JSON.stringify(body.db_ids),
      nowIso(),
    )
    .run();

  await audit(c.env, accountId, "admin", "token.mint", { token_id: id, name: body.name });
  // The secret is shown exactly once.
  return c.json({ token_id: id, agent_token: token, name: body.name, db_ids: body.db_ids }, 201);
});

// GET /v1/agent-tokens — list (never the secret).
control.get("/agent-tokens", requireAdmin, async (c) => {
  const { accountId } = c.get("principal");
  const { results } = await c.env.DB.prepare(
    "SELECT id, name, db_ids, created_at, last_used_at FROM agent_tokens WHERE account_id = ? ORDER BY created_at",
  )
    .bind(accountId)
    .all<{ id: string; name: string; db_ids: string; created_at: string; last_used_at: string | null }>();
  return c.json({
    tokens: results.map((t) => ({ ...t, db_ids: JSON.parse(t.db_ids) })),
  });
});

// DELETE /v1/agent-tokens/:id — revoke.
control.delete("/agent-tokens/:id", requireAdmin, async (c) => {
  const { accountId } = c.get("principal");
  const id = c.req.param("id");
  const res = await c.env.DB.prepare(
    "DELETE FROM agent_tokens WHERE id = ? AND account_id = ?",
  )
    .bind(id, accountId)
    .run();
  if (!res.meta.changes) throw new HTTPException(404, { message: "not found" });
  await audit(c.env, accountId, "admin", "token.revoke", { token_id: id });
  return c.json({ ok: true });
});
