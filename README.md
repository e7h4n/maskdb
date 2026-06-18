# maskdb

**Turn any PostgreSQL database into a safe, read-only REST API for AI agents.**

Give an AI agent access to your production database without giving it your data.
The agent connects with a dedicated token instead of the real password, you
control exactly which columns it can read, and sensitive columns are masked
before a single byte leaves the proxy. Every query is audited.

maskdb runs on Cloudflare Workers and **installs nothing on your database** —
you point it at an existing read-only connection string. No extensions, no
views, no schema changes.

---

## Why

Handing an agent a database is risky two ways:

- **Credentials leak.** A raw connection string exposes the host, user, and
  password. Once it lands in a prompt or a log line, the keys to the whole DB
  are out.
- **Sensitive data leaks.** One `SELECT *` pulls emails, tokens, and PII into
  the model's context, where it gets summarized, cached, and memorized.

maskdb closes both by construction:

1. The real password never leaves the proxy — agents hold disposable,
   revocable, read-only tokens.
2. Sensitive columns are masked at the source — raw values never reach the
   agent, and **masked columns can never be used in a filter or sort**, so they
   can't be reconstructed through a boolean oracle.

## Two planes, two tokens

```
   CONTROL PLANE (mk_admin_…)                 DATA PLANE (mk_agent_…)
   self-register → admin token                read-only, scoped to a set of DBs
   add DB (name, conn str)          ──mint──▶ GET  /v1/databases
   set masking baseline per column            GET  /v1/databases/{db}/tables
   mint / revoke agent tokens                 GET  …/tables/{t}/schema
                                              GET  …/tables/{t}/indexes
                                              POST …/query   (structured, no raw SQL)
```

No raw SQL is ever accepted. The data plane exposes a small structured query
language; queries are compiled to parameterized SQL with every identifier
checked against the live, allowlisted schema.

## The query DSL

```jsonc
POST /v1/databases/{db}/query
Authorization: Bearer mk_agent_…
{
  "table": "users",
  "select": ["id", "name", "email", "plan"],
  "where": {
    "and": [
      { "col": "status", "op": "eq", "value": "active" },
      { "or": [
        { "col": "plan",    "op": "eq",  "value": "pro" },
        { "col": "credits", "op": "gte", "value": 100 }
      ]}
    ]
  },
  "order_by": [{ "col": "id", "dir": "asc" }],
  "limit": 100,
  "offset": 0
}
```

`where` is a recursive boolean tree: a leaf `{col, op, value}` or a group
`{and:[…]}` / `{or:[…]}` / `{not:{…}}`, nestable to any depth.

Operators: `eq` `neq` `gt` `gte` `lt` `lte` `contains` `in` `is_null`.

## Masking strategies

Set once per column on the database (`PUT /v1/databases/{db}/policy`), inherited
by every agent token:

| strategy | result                          |
| -------- | ------------------------------- |
| `none`   | value as-is                     |
| `redact` | `••••••••`                      |
| `email`  | `e***@example.com`              |
| `hash`   | irreversible SHA-256 (joinable) |
| `null`   | `null`                          |

A column with no policy row defaults to `enabled: true, mask: "none"`.

## Stack

- **Cloudflare Workers** + **Hono** (router) + **Zod** (validation)
- **Cloudflare D1** for the service's own metadata (accounts, tokens,
  databases, policies, audit log) — raw SQL, no ORM
- **postgres.js** over Cloudflare TCP sockets to reach user databases
- Connection strings encrypted at rest with **AES-GCM** (Web Crypto); tokens
  stored only as SHA-256 hashes

## Run it

```sh
npm install

# 1. create the metadata DB and paste the id into wrangler.toml
npx wrangler d1 create maskdb

# 2. apply migrations (local for dev, remote for prod)
npm run db:migrate:local

# 3. set the master encryption key (32 bytes, base64)
openssl rand -base64 32 | npx wrangler secret put MASTER_KEY

# 4. run / deploy
npm run dev
npm run deploy
```

Bind your domain to the Worker in the Cloudflare dashboard
(Workers → Custom Domains), e.g. `api.maskdb.ai`.

## Quick walkthrough

```sh
# self-register → admin token (shown once)
curl -sX POST $API/v1/accounts -d '{"owner_email":"you@example.com"}'

# add a database (connection string is validated, then encrypted)
curl -sX POST $API/v1/databases -H "authorization: Bearer $ADMIN" \
  -d '{"name":"prod","connection_string":"postgres://readonly:…@host/db"}'

# inspect the raw schema, then set a masking baseline
curl -sX PUT $API/v1/databases/$DB/policy -H "authorization: Bearer $ADMIN" \
  -d '{"tables":[{"table":"users","columns":[
        {"name":"email","mask":"email"},
        {"name":"api_key","mask":"hash"}]}]}'

# mint a read-only agent token scoped to that DB
curl -sX POST $API/v1/agent-tokens -H "authorization: Bearer $ADMIN" \
  -d '{"name":"support-bot","db_ids":["'$DB'"]}'

# the agent queries — masked, parameterized, read-only
curl -sX POST $API/v1/databases/$DB/query -H "authorization: Bearer $AGENT" \
  -d '{"table":"users","select":["id","email"],"limit":10}'
```

## Status & known limits

v1 is intentionally small. Out of scope for now: joins, aggregates / `GROUP BY`
(can leak masked distributions), raw SQL (never), and writes of any kind.

Operational caveats on Cloudflare Workers:

- **Egress IP** — Workers have no stable egress IP, so a user DB behind an IP
  allowlist or in a private VPC may be unreachable. "Any connection string"
  means any *publicly reachable* one.
- **Connection latency** — v1 opens a short-lived connection per request.
  Pooling via Durable Objects is a planned optimization.

## License

[Apache-2.0](./LICENSE)
