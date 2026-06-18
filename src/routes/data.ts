import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import type { Context } from "hono";
import { requireAgent } from "../auth";
import { compileQuery } from "../compiler";
import { decryptSecret } from "../crypto";
import { applyMask } from "../mask";
import { connect, describeTable, listIndexes, listTables } from "../pg";
import { audit, databaseById, loadPolicy } from "../store";
import { type Env, QueryBody, type Vars } from "../types";

type Ctx = { Bindings: Env; Variables: Vars };

export const data = new Hono<Ctx>();

// Resolve a database the current agent token is allowed to reach, or throw.
async function resolveDb(c: Context<Ctx>, dbId: string) {
  const p = c.get("principal");
  if (p.kind === "agent" && !p.dbIds.includes(dbId)) {
    throw new HTTPException(403, { message: "token not scoped to this database" });
  }
  const db = await databaseById(c.env, p.accountId, dbId);
  if (!db) throw new HTTPException(404, { message: "database not found" });
  return db;
}

// GET /v1/databases/:db/tables
data.get("/databases/:db/tables", requireAgent, async (c) => {
  const db = await resolveDb(c, c.req.param("db"));
  const sql = connect(await decryptSecret(c.env.MASTER_KEY, db.conn_enc));
  try {
    return c.json({ tables: await listTables(sql) });
  } finally {
    await sql.end();
  }
});

// GET /v1/databases/:db/tables/:t/schema — enabled + masked projection.
data.get("/databases/:db/tables/:t/schema", requireAgent, async (c) => {
  const db = await resolveDb(c, c.req.param("db"));
  const table = c.req.param("t");
  const policyFor = await loadPolicy(c.env, db.id);
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

// GET /v1/databases/:db/tables/:t/indexes
data.get("/databases/:db/tables/:t/indexes", requireAgent, async (c) => {
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

// POST /v1/databases/:db/query — the structured read.
data.post("/databases/:db/query", requireAgent, async (c) => {
  const db = await resolveDb(c, c.req.param("db"));
  const body = QueryBody.parse(await c.req.json());
  const policyFor = await loadPolicy(c.env, db.id);
  const maxLimit = parseInt(c.env.MAX_LIMIT || "1000", 10);

  const sql = connect(await decryptSecret(c.env.MASTER_KEY, db.conn_enc));
  try {
    const cols = await describeTable(sql, body.table);
    if (cols.length === 0) {
      throw new HTTPException(400, { message: `unknown table: ${body.table}` });
    }
    const validColumns = new Set(cols.map((c) => c.name));

    const compiled = compileQuery(
      body,
      body.table,
      validColumns,
      (col) => policyFor(body.table, col),
      maxLimit,
    );

    // params are pre-validated and bound positionally ($1..$n); the cast is
    // only to satisfy postgres.js's parameter type at the call boundary.
    const rows = (await sql.unsafe(
      compiled.text,
      compiled.params as (string | number | boolean | null)[],
    )) as Record<string, unknown>[];

    // Mask after fetching — raw values never leave this function.
    for (const row of rows) {
      for (const { column, mask } of compiled.maskPlan) {
        row[column] = await applyMask(mask, row[column]);
      }
    }

    const p = c.get("principal");
    await audit(c.env, p.accountId, p.kind === "agent" ? p.tokenId : "admin", "query", {
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
