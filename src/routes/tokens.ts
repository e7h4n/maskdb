import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { requireScope } from "../auth";
import { hashToken, newToken } from "../crypto";
import { databasesSubset, scopesSubset } from "../scopes";
import { audit, databaseById } from "../store";
import { type Env, MintTokenBody, type Vars } from "../types";

type Ctx = { Bindings: Env; Variables: Vars };

// Token-management routes. A token may only mint children whose scopes and
// databases are a subset of its own (containment).
export const tokens = new Hono<Ctx>();

const nowIso = () => new Date().toISOString();

// POST /v1/tokens — mint a child token. token:mint + containment(new ⊆ caller).
tokens.post("/tokens", requireScope("token:mint"), async (c) => {
  const caller = c.get("principal");
  const body = MintTokenBody.parse(await c.req.json());

  // Containment: the new token's scopes/databases must be a subset of the
  // caller's. Reject with 400 otherwise.
  if (!scopesSubset(body.scopes, caller.scopes)) {
    throw new HTTPException(400, {
      message: "scopes not a subset of caller",
    });
  }
  if (!databasesSubset(body.databases, caller.databases)) {
    throw new HTTPException(400, {
      message: "databases not a subset of caller",
    });
  }

  // Every concrete database id in the new token must belong to the account.
  for (const dbId of body.databases) {
    if (dbId === "*") continue;
    if (!(await databaseById(c.env, caller.accountId, dbId))) {
      throw new HTTPException(400, { message: `unknown database: ${dbId}` });
    }
  }

  const id = crypto.randomUUID();
  const token = newToken();
  await c.env.DB.prepare(
    "INSERT INTO tokens (id, account_id, name, token_hash, scopes, databases, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
  )
    .bind(
      id,
      caller.accountId,
      body.name,
      await hashToken(token),
      JSON.stringify(body.scopes),
      JSON.stringify(body.databases),
      caller.tokenId,
      nowIso(),
    )
    .run();

  await audit(c.env, caller.accountId, caller.tokenId, "token.mint", {
    token_id: id,
    name: body.name,
    scopes: body.scopes,
    databases: body.databases,
  });

  // The secret is shown exactly once.
  return c.json(
    {
      token_id: id,
      token,
      name: body.name,
      scopes: body.scopes,
      databases: body.databases,
    },
    201,
  );
});

// GET /v1/tokens — list (never the secret). token:read.
tokens.get("/tokens", requireScope("token:read"), async (c) => {
  const { accountId } = c.get("principal");
  const { results } = await c.env.DB.prepare(
    "SELECT id, name, scopes, databases, created_at, last_used_at FROM tokens WHERE account_id = ? ORDER BY created_at",
  )
    .bind(accountId)
    .all<{
      id: string;
      name: string;
      scopes: string;
      databases: string;
      created_at: string;
      last_used_at: string | null;
    }>();
  return c.json({
    tokens: results.map((t) => ({
      id: t.id,
      name: t.name,
      scopes: JSON.parse(t.scopes) as string[],
      databases: JSON.parse(t.databases) as string[],
      created_at: t.created_at,
      last_used_at: t.last_used_at,
    })),
  });
});

// DELETE /v1/tokens/:id — revoke (scoped to the caller's account). token:revoke.
tokens.delete("/tokens/:id", requireScope("token:revoke"), async (c) => {
  const caller = c.get("principal");
  const id = c.req.param("id");
  const res = await c.env.DB.prepare(
    "DELETE FROM tokens WHERE id = ? AND account_id = ?",
  )
    .bind(id, caller.accountId)
    .run();
  if (!res.meta.changes) throw new HTTPException(404, { message: "not found" });
  await audit(c.env, caller.accountId, caller.tokenId, "token.revoke", {
    token_id: id,
  });
  return c.json({ ok: true });
});
