import { describe, expect, it, vi } from "vitest";
import app from "../index";
import { hashToken } from "../crypto";
import type { Env } from "../types";

interface TokenRow {
  id: string;
  account_id: string;
  name: string;
  token_hash: string;
  scopes: string;
  databases: string;
}

async function fixture(callerScopes = ["*"], callerDatabases = ["*"]) {
  const callerSecret = "mk_manager";
  const targetSecret = "mk_readonly";
  const tokens: TokenRow[] = [
    {
      id: "manager",
      account_id: "account",
      name: "manager",
      token_hash: await hashToken(callerSecret),
      scopes: JSON.stringify(callerScopes),
      databases: JSON.stringify(callerDatabases),
    },
    {
      id: "readonly",
      account_id: "account",
      name: "agents-readonly",
      token_hash: await hashToken(targetSecret),
      scopes: JSON.stringify(["db:query", "db:metadata"]),
      databases: JSON.stringify(["old-db"]),
    },
  ];
  const databases = [
    { id: "old-db", account_id: "account", name: "existing" },
    { id: "new-db", account_id: "account", name: "marketing" },
    { id: "foreign-db", account_id: "other", name: "foreign" },
  ];
  const audits: { action: string; detail: string }[] = [];
  let beforeUpdate: (() => void) | undefined;
  const env = {
    DB: {
      prepare(query: string) {
        return {
          bind(...args: unknown[]) {
            return {
              async first() {
                if (
                  query ===
                  "SELECT id, account_id, scopes, databases FROM tokens WHERE token_hash = ?"
                ) {
                  return (
                    tokens.find((token) => token.token_hash === args[0]) ?? null
                  );
                }
                if (
                  query ===
                  "SELECT name, scopes, databases FROM tokens WHERE id = ? AND account_id = ?"
                ) {
                  const token = tokens.find(
                    (token) =>
                      token.id === args[0] && token.account_id === args[1],
                  );
                  return token ? { ...token } : null;
                }
                if (
                  query ===
                  "SELECT id, account_id, name, conn_enc FROM databases WHERE id = ? AND account_id = ?"
                ) {
                  return (
                    databases.find(
                      (db) => db.id === args[0] && db.account_id === args[1],
                    ) ?? null
                  );
                }
                throw new Error(`unexpected first query: ${query}`);
              },
              async run() {
                if (query === "UPDATE tokens SET last_used_at = ? WHERE id = ?")
                  return { meta: { changes: 1 } };
                if (
                  query ===
                  "UPDATE tokens SET databases = ? WHERE id = ? AND account_id = ? AND scopes = ? AND databases = ?"
                ) {
                  beforeUpdate?.();
                  const token = tokens.find(
                    (token) =>
                      token.id === args[1] &&
                      token.account_id === args[2] &&
                      token.scopes === args[3] &&
                      token.databases === args[4],
                  );
                  if (token) token.databases = String(args[0]);
                  return { meta: { changes: token ? 1 : 0 } };
                }
                if (
                  query ===
                  "INSERT INTO audit_log (id, account_id, actor, action, detail, created_at) VALUES (?,?,?,?,?,?)"
                ) {
                  audits.push({
                    action: String(args[3]),
                    detail: String(args[4]),
                  });
                  return { meta: { changes: 1 } };
                }
                throw new Error(`unexpected run query: ${query}`);
              },
              async all() {
                if (
                  query.startsWith(
                    "SELECT id, name, created_at FROM databases WHERE account_id = ?",
                  )
                ) {
                  return {
                    results: databases.filter(
                      (db) =>
                        db.account_id === args[0] &&
                        (args.length === 1 || args.slice(1).includes(db.id)),
                    ),
                  };
                }
                throw new Error(`unexpected all query: ${query}`);
              },
            };
          },
        };
      },
    } as unknown as D1Database,
    MASTER_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    MAX_LIMIT: "100",
    REGISTER_RL: {
      async limit() {
        return { success: true };
      },
    },
  } satisfies Env;
  const ctx = {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;
  return {
    tokens,
    audits,
    targetSecret,
    beforeUpdate(fn: () => void) {
      beforeUpdate = fn;
    },
    patch(body: unknown, id = "readonly", secret = callerSecret) {
      return app.request(
        `/v1/tokens/${id}`,
        {
          method: "PATCH",
          headers: {
            authorization: `Bearer ${secret}`,
            "content-type": "application/json",
          },
          body: JSON.stringify(body),
        },
        env,
        ctx,
      );
    },
    list(secret = targetSecret) {
      return app.request(
        "/v1/databases",
        { headers: { authorization: `Bearer ${secret}` } },
        env,
        ctx,
      );
    },
  };
}

async function databaseIds(response: Response): Promise<string[]> {
  const body = (await response.json()) as { databases: { id: string }[] };
  return body.databases.map((db) => db.id);
}

describe("PATCH /v1/tokens/:id", () => {
  it("adds database reach without rotating the secret or changing scopes", async () => {
    const f = await fixture();
    const before = { ...f.tokens[1]! };
    expect(await databaseIds(await f.list())).toEqual(["old-db"]);
    const response = await f.patch({ databases: ["old-db", "new-db"] });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      token_id: "readonly",
      name: "agents-readonly",
      scopes: ["db:query", "db:metadata"],
      databases: ["old-db", "new-db"],
    });
    expect(f.tokens[1]).toEqual({
      ...before,
      databases: JSON.stringify(["old-db", "new-db"]),
    });
    expect(await databaseIds(await f.list())).toEqual(["old-db", "new-db"]);
    expect(f.audits).toEqual([
      {
        action: "token.update",
        detail: JSON.stringify({
          token_id: "readonly",
          previous_databases: ["old-db"],
          databases: ["old-db", "new-db"],
        }),
      },
    ]);
  });

  it("replaces rather than appends the allowlist", async () => {
    const f = await fixture();
    expect((await f.patch({ databases: ["new-db"] })).status).toBe(200);
    expect(await databaseIds(await f.list())).toEqual(["new-db"]);
  });

  it.each(["token:update", "token:*"])(
    "accepts %s with contained capabilities",
    async (scope) => {
      const f = await fixture(
        [scope, "db:query", "db:metadata"],
        ["old-db", "new-db"],
      );
      expect((await f.patch({ databases: ["old-db", "new-db"] })).status).toBe(
        200,
      );
    },
  );

  it("requires token:update", async () => {
    const f = await fixture([
      "token:mint",
      "token:read",
      "db:query",
      "db:metadata",
    ]);
    const response = await f.patch({ databases: ["new-db"] });
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      error: "missing scope: token:update",
    });
    expect(f.audits).toEqual([]);
  });

  it.each(["missing", "foreign-token"])(
    "hides inaccessible target %s",
    async (id) => {
      const f = await fixture();
      f.tokens.push({
        ...f.tokens[1]!,
        id: "foreign-token",
        account_id: "other",
      });
      expect((await f.patch({ databases: ["new-db"] }, id)).status).toBe(404);
      expect(f.audits).toEqual([]);
    },
  );

  it.each(["missing-db", "foreign-db"])(
    "rejects inaccessible database %s",
    async (id) => {
      const f = await fixture();
      expect((await f.patch({ databases: [id] })).status).toBe(400);
      expect(f.tokens[1]!.databases).toBe(JSON.stringify(["old-db"]));
      expect(f.audits).toEqual([]);
    },
  );

  it.each([{ databases: ["new-db"] }, { databases: ["*"] }])(
    "rejects databases outside caller reach: %j",
    async ({ databases }) => {
      const f = await fixture(
        ["token:update", "db:query", "db:metadata"],
        ["old-db"],
      );
      expect((await f.patch({ databases })).status).toBe(400);
      expect(f.audits).toEqual([]);
    },
  );

  it("rejects managing a target whose existing reach exceeds the caller", async () => {
    const f = await fixture(
      ["token:update", "db:query", "db:metadata"],
      ["new-db"],
    );
    expect((await f.patch({ databases: ["new-db"] })).status).toBe(400);
    expect(f.audits).toEqual([]);
  });

  it("rejects granting databases to a target with stronger capabilities", async () => {
    const f = await fixture(["token:update", "db:query", "db:metadata"]);
    f.tokens[1]!.scopes = JSON.stringify(["*"]);
    expect((await f.patch({ databases: ["new-db"] })).status).toBe(400);
    expect(f.audits).toEqual([]);
  });

  it("allows wildcard reach only for a wildcard caller", async () => {
    const f = await fixture();
    expect((await f.patch({ databases: ["*"] })).status).toBe(200);
  });

  it.each([
    {},
    { databases: [] },
    { databases: [""] },
    { databases: "new-db" },
    { databases: ["new-db"], scopes: ["*"] },
    { databases: ["new-db"], name: "renamed" },
  ])("rejects invalid or unsupported fields: %j", async (body) => {
    const f = await fixture();
    expect((await f.patch(body)).status).toBe(400);
    expect(f.audits).toEqual([]);
  });

  it.each(["changed", "revoked"])(
    "does not overwrite a concurrently %s target",
    async (change) => {
      const f = await fixture();
      f.beforeUpdate(() => {
        if (change === "changed")
          f.tokens[1]!.databases = JSON.stringify(["*"]);
        else f.tokens.splice(1, 1);
      });
      expect((await f.patch({ databases: ["new-db"] })).status).toBe(409);
      expect(f.audits).toEqual([]);
    },
  );
});
