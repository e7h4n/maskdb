import type { MiddlewareHandler } from "hono";
import { hashToken } from "./crypto";
import { accountByAdminHash, agentByTokenHash } from "./store";
import type { Env, Principal, Vars } from "./types";

type Ctx = { Bindings: Env; Variables: Vars };

function bearer(header: string | undefined): string | null {
  if (!header) return null;
  const m = /^Bearer\s+(.+)$/i.exec(header.trim());
  return m && m[1] ? m[1] : null;
}

// Resolves the principal from the bearer token and stores it on the context.
// `mk_admin_*` -> admin plane, `mk_agent_*` -> data plane.
export const authenticate: MiddlewareHandler<Ctx> = async (c, next) => {
  const token = bearer(c.req.header("authorization"));
  if (!token) return c.json({ error: "missing bearer token" }, 401);
  const hash = await hashToken(token);

  let principal: Principal | null = null;
  if (token.startsWith("mk_admin_")) {
    const acct = await accountByAdminHash(c.env, hash);
    if (acct) principal = { kind: "admin", accountId: acct.id };
  } else if (token.startsWith("mk_agent_")) {
    const tok = await agentByTokenHash(c.env, hash);
    if (tok) {
      principal = {
        kind: "agent",
        accountId: tok.account_id,
        tokenId: tok.id,
        dbIds: JSON.parse(tok.db_ids) as string[],
      };
      // Best-effort last-used tracking; never block the request on it.
      c.executionCtx.waitUntil(
        c.env.DB.prepare(
          "UPDATE agent_tokens SET last_used_at = ? WHERE id = ?",
        )
          .bind(new Date().toISOString(), tok.id)
          .run(),
      );
    }
  }

  if (!principal) return c.json({ error: "invalid token" }, 401);
  c.set("principal", principal);
  await next();
};

export const requireAdmin: MiddlewareHandler<Ctx> = async (c, next) => {
  if (c.get("principal").kind !== "admin") {
    return c.json({ error: "admin token required" }, 403);
  }
  await next();
};

export const requireAgent: MiddlewareHandler<Ctx> = async (c, next) => {
  if (c.get("principal").kind !== "agent") {
    return c.json({ error: "agent token required" }, 403);
  }
  await next();
};
