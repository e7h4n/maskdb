import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { ZodError } from "zod";
import { authenticate } from "./auth";
import { CompileError } from "./compiler";
import { hashToken, newToken } from "./crypto";
import { control } from "./routes/control";
import { data } from "./routes/data";
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
// Instant, no human gate (abuse-controlled at the edge). Returns the admin
// token exactly once.
app.post("/v1/accounts", async (c) => {
  const body = RegisterBody.parse(await c.req.json());
  const id = crypto.randomUUID();
  const token = newToken("mk_admin");
  await c.env.DB.prepare(
    "INSERT INTO accounts (id, owner_email, admin_token_hash, created_at) VALUES (?,?,?,?)",
  )
    .bind(id, body.owner_email, await hashToken(token), new Date().toISOString())
    .run();
  await audit(c.env, id, "admin", "account.create", { owner_email: body.owner_email });
  return c.json({ account_id: id, admin_token: token, owner_email: body.owner_email }, 201);
});

// --- everything below requires a token ------------------------------------
app.use("/v1/*", authenticate);

// Shared by both planes: admin sees all account DBs, agent sees scoped DBs.
app.get("/v1/databases", async (c) => {
  const p = c.get("principal");
  if (p.kind === "admin") {
    const { results } = await c.env.DB.prepare(
      "SELECT id, name, created_at FROM databases WHERE account_id = ? ORDER BY created_at",
    )
      .bind(p.accountId)
      .all();
    return c.json({ databases: results });
  }
  // agent: only the databases this token is scoped to
  if (p.dbIds.length === 0) return c.json({ databases: [] });
  const placeholders = p.dbIds.map(() => "?").join(",");
  const { results } = await c.env.DB.prepare(
    `SELECT id, name FROM databases WHERE account_id = ? AND id IN (${placeholders}) ORDER BY name`,
  )
    .bind(p.accountId, ...p.dbIds)
    .all();
  return c.json({ databases: results });
});

app.route("/v1", control);
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
