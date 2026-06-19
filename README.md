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

## One token class, granular scopes

There is a single token class (prefix `mk_`). Self-registration mints a **root
token** — `scopes: ["*"]`, `databases: ["*"]` — which can do everything. From it
you mint **narrower child tokens**: each carries an explicit set of capability
*scopes* and a set of *databases* it may reach. A child can never out-scope its
parent (see [Containment](#containment)).

```
   self-register ──▶ root token   scopes:["*"]  databases:["*"]
                          │
                          ├─ mint ▶ admin-ish   scopes:["db:*","policy:*","token:*"]  databases:["*"]
                          └─ mint ▶ support-bot scopes:["db:query","db:metadata"]     databases:["<db_id>"]
```

### Scopes

| scope            | grants                                                  |
| ---------------- | ------------------------------------------------------ |
| `db:query`       | `POST /v1/databases/{db}/query`                        |
| `db:metadata`    | list tables, table schema, indexes                     |
| `db:manage`      | add DB, delete DB, read the **raw** (unmasked) schema  |
| `policy:read`    | `GET  /v1/databases/{db}/policy`                       |
| `policy:write`   | `PUT  /v1/databases/{db}/policy`                       |
| `token:mint`     | `POST /v1/tokens`                                       |
| `token:read`     | `GET  /v1/tokens`                                       |
| `token:revoke`   | `DELETE /v1/tokens/{id}`                                |
| `account:admin`  | reserved for account-level operations                  |

Wildcards: `*` (everything), and category wildcards `db:*`, `policy:*`,
`token:*`. A required scope is satisfied if the token holds it exactly, holds
its category wildcard, or holds `*`.

### Databases resource

Every token also carries a `databases` array: either `["*"]` (every database in
the account) or a list of specific database ids. Endpoints scoped to a single
`{db}` additionally require that `{db}` be reachable by the token. Registering a
new database (`POST /v1/databases`) is an account-level operation and requires
`databases: ["*"]`.

### Containment

When minting a child token, both its `scopes` and `databases` must be a
**subset** of the caller's:

- A child scope is allowed only if the caller holds it, holds its category
  wildcard, or holds `*`. A child may include `*` only if the caller has `*`.
- If the caller's `databases` is `["*"]`, any child database set is allowed.
  Otherwise the child may not use `["*"]`, and every id it lists must be one the
  caller already holds.

Minting that would broaden scope is rejected with `400`.

### The /v1/tokens API

```jsonc
POST /v1/tokens
Authorization: Bearer mk_…
{ "name": "support-bot",
  "scopes": ["db:query", "db:metadata"],
  "databases": ["<db_id>"] }
→ 201 { "token_id": "…", "token": "mk_…", "name": "support-bot",
        "scopes": […], "databases": […] }   // secret shown once

GET    /v1/tokens          → [{ id, name, scopes, databases, created_at, last_used_at }]
DELETE /v1/tokens/{id}     → revoke (never returns the secret)
```

A failed scope check returns `403 {"error":"missing scope: <scope>"}`; a token
reaching a database it isn't scoped to returns
`403 {"error":"token not scoped to this database"}`; a bad or absent token
returns `401`.

> **Security note:** `policy:write` is effectively the ability to **unmask** —
> a token that can rewrite a database's column policy can disable masking on any
> column. Grant it as narrowly as you grant raw `db:manage`.

No raw SQL is ever accepted. The query endpoint exposes a small structured query
language; queries are compiled to parameterized SQL with every identifier
checked against the live, allowlisted schema.

## The query DSL

```jsonc
POST /v1/databases/{db}/query
Authorization: Bearer mk_…
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

Set once per column on the database (`PUT /v1/databases/{db}/policy`, requires
`policy:write`), inherited by every token that can reach the database:

| strategy | result                          |
| -------- | ------------------------------- |
| `none`   | value as-is                     |
| `redact` | `••••••••`                      |
| `email`  | `e***@example.com`              |
| `phone`  | last 4 digits kept: `+X (XXX) XXX-1848` |
| `hash`   | irreversible SHA-256 (joinable) |
| `null`   | `null`                          |

## Allowlist vs allow-by-default

Each database has a `default_deny` flag (set when you register it, **default
`true`**):

- **`default_deny: true` (allowlist)** — only columns explicitly enabled in the
  policy are readable; every other column and table is hidden from introspection
  and rejected if queried. Forgetting to mask a column fails *closed*. Use this
  for any real/production database.
- **`default_deny: false`** — a column with no policy row is visible and
  unmasked. Only safe for an already-masked source (e.g. a static-masked
  replica) where masking is defence-in-depth.

Every query also runs inside a Postgres `READ ONLY` transaction, so a write can
never reach the database even if the query compiler had a bug — on top of using
a read-only DB role.

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
# self-register → root token (scopes ["*"], databases ["*"]); shown once
curl -sX POST $API/v1/accounts -d '{"owner_email":"you@example.com"}'

# add a database (connection string is validated, then encrypted)
# requires db:manage and an account-level (databases ["*"]) token
curl -sX POST $API/v1/databases -H "authorization: Bearer $ROOT" \
  -d '{"name":"prod","connection_string":"postgres://readonly:…@host/db"}'

# inspect the raw schema, then set a masking baseline
curl -sX PUT $API/v1/databases/$DB/policy -H "authorization: Bearer $ROOT" \
  -d '{"tables":[{"table":"users","columns":[
        {"name":"email","mask":"email"},
        {"name":"api_key","mask":"hash"}]}]}'

# mint a read-only token scoped to that DB and to query+metadata only
curl -sX POST $API/v1/tokens -H "authorization: Bearer $ROOT" \
  -d '{"name":"support-bot","scopes":["db:query","db:metadata"],
       "databases":["'$DB'"]}'

# the agent queries — masked, parameterized, read-only
curl -sX POST $API/v1/databases/$DB/query -H "authorization: Bearer $AGENT" \
  -d '{"table":"users","select":["id","email"],"limit":10}'
```

## Deploy (CI/CD)

Pushing to `main` triggers `.github/workflows/deploy.yml`, which deploys both
the API worker (`api.maskdb.ai`) and the marketing site (`www.maskdb.ai`) to
Cloudflare. Configure two repository secrets:

- `CLOUDFLARE_API_TOKEN` — a scoped token with **Workers Scripts:Edit**,
  **D1:Edit**, **Workers Routes:Edit**, and **Account Settings:Read**
- `CLOUDFLARE_ACCOUNT_ID`

The `MASTER_KEY` secret is set once with `wrangler secret put MASTER_KEY` and is
preserved across deploys. The marketing site lives in [`site/`](./site) and is
served as a static-assets Worker (`wrangler.site.toml`).

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
