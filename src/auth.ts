import type { MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import { hashToken } from "./crypto";
import { hasDatabase, hasScope } from "./scopes";
import { tokenByHash, touchToken } from "./store";
import type { Env, Principal, Vars } from "./types";

type Ctx = { Bindings: Env; Variables: Vars };

function bearer(header: string | undefined): string | null {
  if (!header) return null;
  const m = /^Bearer\s+(.+)$/i.exec(header.trim());
  return m && m[1] ? m[1] : null;
}

// Resolves the principal from the bearer token and stores it on the context.
// One token class (mk_): look up by hash, load scopes/databases.
export const authenticate: MiddlewareHandler<Ctx> = async (c, next) => {
  const token = bearer(c.req.header("authorization"));
  if (!token) return c.json({ error: "missing bearer token" }, 401);
  const hash = await hashToken(token);

  const tok = await tokenByHash(c.env, hash);
  if (!tok) return c.json({ error: "invalid token" }, 401);

  const principal: Principal = {
    accountId: tok.account_id,
    tokenId: tok.id,
    scopes: tok.scopes,
    databases: tok.databases,
  };
  c.set("principal", principal);

  // Best-effort last-used tracking; never block the request on it.
  c.executionCtx.waitUntil(touchToken(c.env, tok.id));

  await next();
};

// requireScope: 403 unless the principal's scopes satisfy `scope`.
export function requireScope(scope: string): MiddlewareHandler<Ctx> {
  return async (c, next) => {
    if (!hasScope(c.get("principal").scopes, scope)) {
      return c.json({ error: `missing scope: ${scope}` }, 403);
    }
    await next();
  };
}

// assertDb: throw 403 unless the principal's databases reach `dbId`.
export function assertDb(principal: Principal, dbId: string): void {
  if (!hasDatabase(principal.databases, dbId)) {
    throw new HTTPException(403, {
      message: "token not scoped to this database",
    });
  }
}
