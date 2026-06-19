import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import type { Context } from "hono";
import { assertDb, requireScope } from "../auth";
import { compileQuery } from "../compiler";
import { decryptSecret } from "../crypto";
import { applyMask } from "../mask";
import { connect, describeTable, listIndexes, listTables } from "../pg";
import { audit, databaseById, loadPolicy } from "../store";
import { type Env, QueryBody, type Vars } from "../types";

type Ctx = { Bindings: Env; Variables: Vars };

export const data = new Hono<Ctx>();

// Resolve a database the current token is allowed to reach, or throw.
async function resolveDb(c: Context<Ctx>, dbId: string) {
  const p = c.get("principal");
  assertDb(p, dbId);
  const db = await databaseById(c.env, p.accountId, dbId);
  if (!db) throw new HTTPException(404, { message: "database not found" });
  return db;
}

// GET /v1/databases/:db/tables — db:metadata + hasDatabase.
data.get("/databases/:db/tables", requireScope("db:metadata"), async (c) => {
  const db = await resolveDb(c, c.req.param("db"));
  const sql = connect(await decryptSecret(c.env.MASTER_KEY, db.conn_enc));
  try {
    const all = await listTables(sql);
    // Allowlist: only surface tables that have at least one enabled column.
    const { enabledTables } = await loadPolicy(c.env, db.id);
    return c.json({ tables: all.filter((t) => enabledTables.has(t)) });
  } finally {
    await sql.end();
  }
});

// GET /v1/databases/:db/tables/:t/schema — enabled + masked projection.
data.get("/databases/:db/tables/:t/schema", requireScope("db:metadata"), async (c) => {
  const db = await resolveDb(c, c.req.param("db"));
  const table = c.req.param("t");
  const { policyFor, enabledTables } = await loadPolicy(c.env, db.id);
  // Allowlist: a table with no enabled column is not exposed at all.
  if (!enabledTables.has(table)) {
    throw new HTTPException(404, { message: "table not found" });
  }
  const sql = connect(await decryptSecret(c.env.MASTER_KEY, db.conn_enc));
  try {
    const cols = await describeTable(sql, table);
    if (cols.length === 0) {
      throw new HTTPException(404, { message: "table not found" });
    }
    const projected = cols
      .map((col) => ({ col, p: policyFor(table, col.name) }))
      .filter(({ p }) => p.enabled)
      .map(({ col, p }) => ({
        name: col.name,
        type: col.type,
        nullable: col.nullable,
        masked: p.mask !== "none",
        filterable: p.mask === "none",
      }));
    return c.json({ table, columns: projected });
  } finally {
    await sql.end();
  }
});

// GET /v1/databases/:db/tables/:t/indexes — db:metadata + hasDatabase.
data.get("/databases/:db/tables/:t/indexes", requireScope("db:metadata"), async (c) => {
  const db = await resolveDb(c, c.req.param("db"));
  const table = c.req.param("t");
  const sql = connect(await decryptSecret(c.env.MASTER_KEY, db.conn_enc));
  try {
    const idx = await listIndexes(sql, table);
    return c.json({
      indexes: idx.map((i) => ({
        name: i.name,
        unique: /\bUNIQUE\b/i.test(i.definition),
        definition: i.definition,
      })),
    });
  } finally {
    await sql.end();
  }
});

// POST /v1/databases/:db/query — the structured read. db:query + hasDatabase.
data.post("/databases/:db/query", requireScope("db:query"), async (c) => {
  const db = await resolveDb(c, c.req.param("db"));
  const body = QueryBody.parse(await c.req.json());
  const { policyFor, enabledTables } = await loadPolicy(c.env, db.id);
  // Allowlist gate (same set as /tables): a non-allowlisted table is "not
  // found" — no schema enumeration oracle, checked before we touch the DB.
  if (!enabledTables.has(body.table)) {
    throw new HTTPException(404, { message: "table not found" });
  }
  const maxLimit = parseInt(c.env.MAX_LIMIT || "1000", 10);

  const sql = connect(await decryptSecret(c.env.MASTER_KEY, db.conn_enc));
  try {
    const cols = await describeTable(sql, body.table);
    if (cols.length === 0) {
      throw new HTTPException(404, { message: "table not found" });
    }
    const validColumns = new Set(cols.map((c) => c.name));

    const compiled = compileQuery(
      body,
      body.table,
      validColumns,
      (col) => policyFor(body.table, col),
      maxLimit,
    );

    // Run inside a READ ONLY transaction: even if the compiler ever emitted a
    // write, Postgres rejects it. Defense-in-depth beyond the SELECT-only DSL.
    // params are pre-validated and bound positionally ($1..$n); the cast is
    // only to satisfy postgres.js's parameter type at the call boundary.
    const rows = (await sql.begin("read only", (tx) =>
      tx.unsafe(
        compiled.text,
        compiled.params as (string | number | boolean | null)[],
      ),
    )) as Record<string, unknown>[];

    // Mask after fetching — raw values never leave this function.
    for (const row of rows) {
      for (const { column, mask } of compiled.maskPlan) {
        row[column] = await applyMask(mask, row[column]);
      }
    }

    const p = c.get("principal");
    await audit(c.env, p.accountId, p.tokenId, "query", {
      db_id: db.id,
      table: body.table,
      columns: body.select.length,
      returned: rows.length,
    });

    return c.json({
      rows,
      masked: compiled.maskPlan.map((m) => m.column),
      page: {
        limit: Math.min(body.limit ?? maxLimit, maxLimit),
        offset: body.offset,
        returned: rows.length,
      },
    });
  } finally {
    await sql.end();
  }
});
