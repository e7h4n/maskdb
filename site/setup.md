# Set up maskdb

Give your AI agents safe, read-only, **masked** access to a Postgres database.
This guide is written so an AI assistant can run it for you — or you can run the
six calls yourself with any HTTP client.

- **API base:** `https://api.maskdb.ai`
- **Auth:** every request sends `Authorization: Bearer <token>`
- Show each token to the user **once** and tell them to store it in a secret
  manager. Never log full tokens.

---

## 1. Register → admin token

```sh
curl -sX POST https://api.maskdb.ai/v1/accounts \
  -H "content-type: application/json" \
  -d '{"owner_email":"<MY_EMAIL>"}'
```

Returns a token with `scopes: ["*"]` — the **root credential**. It can't be
recovered, so save it somewhere safe. Use it only to manage maskdb.

## 2. Connect your database

Use a **read-only** connection string — ideally a role with only `SELECT`, not
an owner. If the string has `channel_binding=require`, drop it and keep
`sslmode=require`.

```sh
curl -sX POST https://api.maskdb.ai/v1/databases \
  -H "authorization: Bearer <ADMIN_TOKEN>" -H "content-type: application/json" \
  -d '{"name":"prod","connection_string":"postgres://readonly:…@host/db?sslmode=require"}'
```

Save the returned `db_id`. The database defaults to **allowlist mode**
(`default_deny`): nothing is readable until you explicitly enable it.

## 3. Read the schema, propose a masking policy

```sh
curl -s https://api.maskdb.ai/v1/databases/<DB_ID>/schema \
  -H "authorization: Bearer <ADMIN_TOKEN>"
```

For every column decide `enabled` + `mask`:

| column kind | mask |
| --- | --- |
| ids, foreign keys, timestamps, enums, numbers | `none` (enable, useful & low-risk) |
| email addresses | `email` |
| phone numbers | `phone` |
| secrets, tokens, api keys, `encrypted_*` | `redact` |
| free-text user content (prompts, messages, bodies, notes) | `null` |
| unsure whether it's sensitive | mask it, or leave it disabled |

Because allowlist mode is on, **only the columns you enable are readable** —
everything else (and any column you forget) stays hidden. Present the proposed
policy to the user and let them adjust before applying.

## 4. Apply the policy

```sh
curl -sX PUT https://api.maskdb.ai/v1/databases/<DB_ID>/policy \
  -H "authorization: Bearer <ADMIN_TOKEN>" -H "content-type: application/json" \
  -d '{"tables":[{"table":"users","columns":[
        {"name":"id","enabled":true,"mask":"none"},
        {"name":"email","enabled":true,"mask":"email"},
        {"name":"api_key","enabled":true,"mask":"redact"}]}]}'
```

## 5. Mint the read-only agent token

This is the token you hand to your agents.

```sh
curl -sX POST https://api.maskdb.ai/v1/tokens \
  -H "authorization: Bearer <ADMIN_TOKEN>" -H "content-type: application/json" \
  -d '{"name":"my-agent","scopes":["db:query","db:metadata"],"databases":["<DB_ID>"]}'
```

It can only **read** (`db:query` + `db:metadata`) and only **this** database.

## 6. Verify

```sh
curl -sX POST https://api.maskdb.ai/v1/databases/<DB_ID>/query \
  -H "authorization: Bearer <AGENT_TOKEN>" -H "content-type: application/json" \
  -d '{"table":"users","select":["id","email"],"limit":3}'
```

Confirm sensitive columns come back masked. The agent token can **not** change
the policy or reach another database.

---

## Safety notes

- Never give an agent token `policy:write` — it could rewrite the policy to
  unmask a column.
- Keep the admin token offline; mint a fresh scoped token per agent and revoke
  any token anytime (`DELETE /v1/tokens/{id}`).
- Every query is audited.

Full reference: <https://github.com/e7h4n/maskdb>
