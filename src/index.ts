import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { ZodError } from "zod";
import { authenticate } from "./auth";
import { CompileError } from "./compiler";
import { hashToken, newToken } from "./crypto";
import { control } from "./routes/control";
import { data } from "./routes/data";
import { tokens } from "./routes/tokens";
import { hasScope } from "./scopes";
import { audit } from "./store";
import { type Env, RegisterBody, type Vars } from "./types";

type Ctx = { Bindings: Env; Variables: Vars };

const app = new Hono<Ctx>();

app.get("/", (c) =>
  c.json({
    name: "maskdb",
    description:
      "A safe, read-only REST gateway to Postgres for AI agents. Credentials hidden, sensitive columns masked.",
    docs: "https://github.com/e7h4n/maskdb",
  }),
);

// --- public: self-registration -------------------------------------------
// Instant, no human gate (abuse-controlled at the edge). Creates the account
// and a root token (scopes ["*"], databases ["*"]). Returns it exactly once.
app.post("/v1/accounts", async (c) => {
  const body = RegisterBody.parse(await c.req.json());
  const accountId = crypto.randomUUID();
  const tokenId = crypto.randomUUID();
  const token = newToken();
  const now = new Date().toISOString();
  const scopes = ["*"];
  const databases = ["*"];

  await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT INTO accounts (id, owner_email, created_at) VALUES (?,?,?)",
    ).bind(accountId, body.owner_email, now),
    c.env.DB.prepare(
      "INSERT INTO tokens (id, account_id, name, token_hash, scopes, databases, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)",
    ).bind(
      tokenId,
      accountId,
      "root",
      await hashToken(token),
      JSON.stringify(scopes),
      JSON.stringify(databases),
      null,
      now,
    ),
  ]);

  await audit(c.env, accountId, tokenId, "account.create", {
    owner_email: body.owner_email,
  });
  return c.json({ account_id: accountId, token, scopes, databases }, 201);
});

// --- everything below requires a token ------------------------------------
app.use("/v1/*", authenticate);

// GET /v1/databases — list databases the token can reach. Requires any db
// scope (db:query / db:metadata / db:manage). databases ["*"] → all account
// DBs; otherwise only the ids the token is scoped to.
app.get("/v1/databases", async (c) => {
  const p = c.get("principal");
  const anyDbScope =
    hasScope(p.scopes, "db:query") ||
    hasScope(p.scopes, "db:metadata") ||
    hasScope(p.scopes, "db:manage");
  if (!anyDbScope) {
    return c.json({ error: "missing scope: db:*" }, 403);
  }

  if (p.databases.includes("*")) {
    const { results } = await c.env.DB.prepare(
      "SELECT id, name, created_at FROM databases WHERE account_id = ? ORDER BY created_at",
    )
      .bind(p.accountId)
      .all();
    return c.json({ databases: results });
  }
  if (p.databases.length === 0) return c.json({ databases: [] });
  const placeholders = p.databases.map(() => "?").join(",");
  const { results } = await c.env.DB.prepare(
    `SELECT id, name, created_at FROM databases WHERE account_id = ? AND id IN (${placeholders}) ORDER BY name`,
  )
    .bind(p.accountId, ...p.databases)
    .all();
  return c.json({ databases: results });
});

app.route("/v1", control);
app.route("/v1", tokens);
app.route("/v1", data);

// --- uniform error handling -----------------------------------------------
app.onError((err, c) => {
  if (err instanceof HTTPException) {
    return c.json({ error: err.message }, err.status);
  }
  if (err instanceof ZodError) {
    return c.json({ error: "invalid request", issues: err.issues }, 400);
  }
  if (err instanceof CompileError) {
    return c.json({ error: err.message }, 400);
  }
  // Anything else (including upstream Postgres errors) is reported but not leaked verbatim.
  console.error(err);
  return c.json({ error: "internal error" }, 500);
});

export default app;
