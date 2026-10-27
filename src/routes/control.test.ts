import { beforeEach, describe, expect, it, vi } from "vitest";
import app from "../index";
import { decryptSecret, encryptSecret, hashToken } from "../crypto";
import { connect, describeTable } from "../pg";
import type { PolicyRow } from "../store";
import type { Env } from "../types";

vi.mock("../pg", () => {
  return {
    connect: vi.fn(),
    describeTable: vi.fn(),
    listIndexes: vi.fn(),
    listTables: vi.fn(),
  };
});

const MASTER_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const TOKEN = "mk_test_token";

type SqlProbe = ((strings: TemplateStringsArray) => Promise<unknown>) & {
  end: () => Promise<void>;
};

interface TokenRow {
  id: string;
  account_id: string;
  token_hash: string;
  scopes: string;
  databases: string;
  last_used_at?: string;
}

interface DatabaseRow {
  id: string;
  account_id: string;
  name: string;
  conn_enc: string;
}

interface AuditRow {
  action: string;
  detail: string | null;
}

interface TestState {
  tokens: TokenRow[];
  databases: DatabaseRow[];
  audits: AuditRow[];
  policies: PolicyRow[];
}

const connectMock = vi.mocked(connect);

function okProbe(): SqlProbe {
  const probe = vi.fn(async () => {
    return [{ ok: 1 }];
  }) as unknown as SqlProbe;
  probe.end = vi.fn(async () => {});
  return probe;
}

function failingProbe(): SqlProbe {
  const probe = vi.fn(async () => {
    throw new Error("bad upstream credentials");
  }) as unknown as SqlProbe;
  probe.end = vi.fn(async () => {});
  return probe;
}

async function seedState(scopes: readonly string[]): Promise<TestState> {
  return {
    tokens: [
      {
        id: "token_1",
        account_id: "acct_1",
        token_hash: await hashToken(TOKEN),
        scopes: JSON.stringify(scopes),
        databases: JSON.stringify(["db_1"]),
      },
    ],
    databases: [
      {
        id: "db_1",
        account_id: "acct_1",
        name: "prod",
        conn_enc: await encryptSecret(MASTER_KEY, "postgres://old"),
      },
    ],
    audits: [],
    policies: [],
  };
}

function createEnv(state: TestState): Env {
  return {
    DB: {
      prepare(query: string) {
        return {
          bind(...args: unknown[]) {
            return {
              query,
              args,
              async first<T>() {
                if (
                  query ===
                  "SELECT id, account_id, scopes, databases FROM tokens WHERE token_hash = ?"
                ) {
                  return (
                    state.tokens.find((token) => {
                      return token.token_hash === args[0];
                    }) ?? null
                  ) as T | null;
                }
                if (
                  query ===
                  "SELECT id, account_id, name, conn_enc FROM databases WHERE id = ? AND account_id = ?"
                ) {
                  return (
                    state.databases.find((database) => {
                      return (
                        database.id === args[0] && database.account_id === args[1]
                      );
                    }) ?? null
                  ) as T | null;
                }
                throw new Error(`unexpected first query: ${query}`);
              },
              async run() {
                if (query === "UPDATE tokens SET last_used_at = ? WHERE id = ?") {
                  const token = state.tokens.find((candidate) => {
                    return candidate.id === args[1];
                  });
                  if (token) {
                    token.last_used_at = String(args[0]);
                  }
                  return { meta: { changes: token ? 1 : 0 } };
                }
                if (
                  query ===
                  "UPDATE databases SET conn_enc = ? WHERE id = ? AND account_id = ?"
                ) {
                  const database = state.databases.find((candidate) => {
                    return candidate.id === args[1] && candidate.account_id === args[2];
                  });
                  if (database) {
                    database.conn_enc = String(args[0]);
                  }
                  return { meta: { changes: database ? 1 : 0 } };
                }
                if (
                  query ===
                  "INSERT INTO audit_log (id, account_id, actor, action, detail, created_at) VALUES (?,?,?,?,?,?)"
                ) {
                  state.audits.push({
                    action: String(args[3]),
                    detail: args[4] === null ? null : String(args[4]),
                  });
                  return { meta: { changes: 1 } };
                }
                throw new Error(`unexpected run query: ${query}`);
              },
              async all<T>() {
                if (query.includes("FROM column_policies")) {
                  return { results: state.policies as T[] };
                }
                return { results: [] as T[] };
              },
            };
          },
        };
      },
      async batch(statements: { query: string; args: unknown[] }[]) {
        for (const statement of statements) {
          if (statement.query.startsWith("DELETE FROM column_policies")) {
            state.policies = [];
          } else if (statement.query.startsWith("INSERT INTO column_policies")) {
            const [, table, name, enabled, mask, fields] = statement.args;
            state.policies.push({
              table_name: String(table),
              column_name: String(name),
              enabled: Number(enabled),
              mask: mask as PolicyRow["mask"],
              json_fields: fields === null ? null : String(fields),
            });
          } else {
            throw new Error(`unexpected batch query: ${statement.query}`);
          }
        }
        return [];
      },
    } as unknown as D1Database,
    MASTER_KEY,
    MAX_LIMIT: "100",
    REGISTER_RL: {
      async limit() {
        return { success: true };
      },
    },
  };
}

describe("JSON policy round-trip and query response", () => {
  it("persists an allowlist and exposes only metadata through the data route", async () => {
    const state = await seedState([
      "policy:write",
      "policy:read",
      "db:query",
      "db:metadata",
    ]);
    const env = createEnv(state);
    const context = executionContext();
    const headers = {
      authorization: `Bearer ${TOKEN}`,
      "content-type": "application/json",
    };
    const jsonFields = ["id", "status", "updatedAt"];
    const policy = await app.request(
      "/v1/databases/db_1/policy",
      {
        method: "PUT",
        headers,
        body: JSON.stringify({
          tables: [
            {
              table: "suggestions",
              columns: [
                { name: "entries", mask: "json", json_fields: jsonFields },
              ],
            },
          ],
        }),
      },
      env,
      context,
    );
    expect(policy.status).toBe(200);
    expect(state.policies[0]?.json_fields).toBe(JSON.stringify(jsonFields));
    const readBack = await app.request(
      "/v1/databases/db_1/policy",
      { headers },
      env,
      context,
    );
    expect(await readBack.json()).toStrictEqual({
      db_id: "db_1",
      columns: [
        {
          table: "suggestions",
          name: "entries",
          enabled: true,
          mask: "json",
          json_fields: jsonFields,
        },
      ],
    });

    vi.mocked(describeTable).mockResolvedValue([
      { name: "entries", type: "jsonb", nullable: false },
    ]);
    const raw = [
      {
        entries: [
          {
            id: "s1",
            status: "active",
            updatedAt: "2026-10-27T10:00:00Z",
            title: "private",
            draft: { text: "secret" },
            unapproved: "secret",
          },
        ],
      },
    ];
    const upstream = {
      begin: vi.fn(async () => structuredClone(raw)),
      end: vi.fn(async () => {}),
    };
    connectMock.mockReturnValue(
      upstream as unknown as ReturnType<typeof connect>,
    );
    const schema = await app.request(
      "/v1/databases/db_1/tables/suggestions/schema",
      { headers },
      env,
      context,
    );
    expect(await schema.json()).toStrictEqual({
      table: "suggestions",
      columns: [
        {
          name: "entries",
          type: "jsonb",
          nullable: false,
          masked: true,
          filterable: false,
          json_fields: jsonFields,
        },
      ],
    });
    const response = await app.request(
      "/v1/databases/db_1/query",
      {
        method: "POST",
        headers,
        body: JSON.stringify({ table: "suggestions", select: ["entries"] }),
      },
      env,
      context,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toStrictEqual({
      rows: [
        {
          entries: [
            { id: "s1", status: "active", updatedAt: "2026-10-27T10:00:00Z" },
          ],
        },
      ],
      masked: ["entries"],
      page: { limit: 100, offset: 0, returned: 1 },
    });
  });

  it("rejects a JSON policy without fields before changing the existing baseline", async () => {
    const state = await seedState(["policy:write"]);
    state.policies = [{
      table_name: "users", column_name: "email", enabled: 1,
      mask: "email", json_fields: null,
    }];
    const baseline = structuredClone(state.policies);
    const env = createEnv(state);
    const response = await app.request(
      "/v1/databases/db_1/policy",
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${TOKEN}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          tables: [
            {
              table: "suggestions",
              columns: [{ name: "entries", mask: "json" }],
            },
          ],
        }),
      },
      env,
      executionContext(),
    );
    expect(response.status).toBe(400);
    expect(state.policies).toStrictEqual(baseline);
  });
});

function executionContext(): ExecutionContext {
  return {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;
}

async function replaceConnection(
  env: Env,
  connectionString: string,
): Promise<Response> {
  return app.request(
    "/v1/databases/db_1/connection",
    {
      method: "PUT",
      headers: {
        authorization: `Bearer ${TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ connection_string: connectionString }),
    },
    env,
    executionContext(),
  );
}

describe("PUT /v1/databases/:db/connection", () => {
  beforeEach(() => {
    connectMock.mockReset();
    connectMock.mockReturnValue(okProbe() as ReturnType<typeof connect>);
  });

  it("validates and replaces the encrypted connection string", async () => {
    const state = await seedState(["db:manage"]);
    const env = createEnv(state);
    const nextConnection = "postgres://readonly:new-password@example.com/prod";

    const response = await replaceConnection(env, nextConnection);
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body).toStrictEqual({ ok: true, db_id: "db_1", name: "prod" });
    expect(connectMock).toHaveBeenCalledWith(nextConnection);
    expect(
      await decryptSecret(MASTER_KEY, state.databases[0]?.conn_enc ?? ""),
    ).toBe(nextConnection);
    expect(state.audits).toHaveLength(1);
    expect(state.audits[0]?.action).toBe("db.connection.replace");
    expect(state.audits[0]?.detail).toBe(
      JSON.stringify({ db_id: "db_1", name: "prod" }),
    );
  });

  it("keeps the old connection string when validation fails", async () => {
    const state = await seedState(["db:manage"]);
    const env = createEnv(state);
    const oldConnection = await decryptSecret(
      MASTER_KEY,
      state.databases[0]?.conn_enc ?? "",
    );
    connectMock.mockReturnValueOnce(failingProbe() as ReturnType<typeof connect>);

    const response = await replaceConnection(env, "postgres://bad");
    const body = await response.json();

    expect(response.status).toBe(400);
    expect(body).toStrictEqual({ error: "could not connect" });
    expect(
      await decryptSecret(MASTER_KEY, state.databases[0]?.conn_enc ?? ""),
    ).toBe(oldConnection);
    expect(state.audits).toHaveLength(0);
  });

  it("requires db:manage", async () => {
    const state = await seedState(["db:query"]);
    const env = createEnv(state);

    const response = await replaceConnection(env, "postgres://new");
    const body = await response.json();

    expect(response.status).toBe(403);
    expect(body).toStrictEqual({ error: "missing scope: db:manage" });
    expect(connectMock).not.toHaveBeenCalled();
  });
});
