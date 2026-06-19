import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { assertDb, requireScope } from "../auth";
import { decryptSecret, encryptSecret } from "../crypto";
import { connect, describeTable, listTables } from "../pg";
import { audit, databaseById, listPolicyRows } from "../store";
import {
  AddDatabaseBody,
  type Env,
  PolicyBody,
  type Vars,
} from "../types";

type Ctx = { Bindings: Env; Variables: Vars };

// Control-plane routes (databases + policies). Scopes are enforced per-route
// via requireScope; resource (database) checks via assertDb in the handler.
export const control = new Hono<Ctx>();

const nowIso = () => new Date().toISOString();

// POST /v1/databases — register a user Postgres database.
// db:manage AND the caller must be account-level (databases == ["*"]).
control.post("/databases", requireScope("db:manage"), async (c) => {
  const principal = c.get("principal");
  const { accountId } = principal;

  // Adding a DB is an account-level operation: only ["*"] tokens may do it.
  if (!(principal.databases.length === 1 && principal.databases[0] === "*")) {
    throw new HTTPException(403, {
      message: "token not scoped to this database",
    });
  }

  const body = AddDatabaseBody.parse(await c.req.json());

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

  await audit(c.env, accountId, principal.tokenId, "db.add", {
    db_id: id,
    name: body.name,
    default_deny: body.default_deny,
  });
  return c.json({ db_id: id, name: body.name, default_deny: body.default_deny }, 201);
});

// DELETE /v1/databases/:db — db:manage + hasDatabase(db).
control.delete("/databases/:db", requireScope("db:manage"), async (c) => {
  const principal = c.get("principal");
  const { accountId } = principal;
  const dbId = c.req.param("db");
  assertDb(principal, dbId);
  const res = await c.env.DB.prepare(
    "DELETE FROM databases WHERE id = ? AND account_id = ?",
  )
    .bind(dbId, accountId)
    .run();
  if (!res.meta.changes) throw new HTTPException(404, { message: "not found" });
  await audit(c.env, accountId, principal.tokenId, "db.delete", { db_id: dbId });
  return c.json({ ok: true });
});

// GET /v1/databases/:db/schema — RAW, unmasked schema. db:manage + hasDatabase.
control.get("/databases/:db/schema", requireScope("db:manage"), async (c) => {
  const principal = c.get("principal");
  const { accountId } = principal;
  const dbId = c.req.param("db");
  assertDb(principal, dbId);
  const db = await databaseById(c.env, accountId, dbId);
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
// policy:write + hasDatabase(db).
control.put("/databases/:db/policy", requireScope("policy:write"), async (c) => {
  const principal = c.get("principal");
  const { accountId } = principal;
  const dbId = c.req.param("db");
  assertDb(principal, dbId);
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
  await audit(c.env, accountId, principal.tokenId, "db.policy", {
    db_id: dbId,
    columns: count,
  });
  return c.json({ ok: true, columns: count });
});

// GET /v1/databases/:db/policy — read the masking baseline rows.
// policy:read + hasDatabase(db).
control.get("/databases/:db/policy", requireScope("policy:read"), async (c) => {
  const principal = c.get("principal");
  const { accountId } = principal;
  const dbId = c.req.param("db");
  assertDb(principal, dbId);
  const db = await databaseById(c.env, accountId, dbId);
  if (!db) throw new HTTPException(404, { message: "not found" });

  const rows = await listPolicyRows(c.env, dbId);
  return c.json({
    db_id: dbId,
    default_deny: db.default_deny === 1,
    columns: rows.map((r) => ({
      table: r.table_name,
      name: r.column_name,
      enabled: r.enabled === 1,
      mask: r.mask,
    })),
  });
});
