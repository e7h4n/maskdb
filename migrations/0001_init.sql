-- maskdb control-plane metadata. Stored in Cloudflare D1 (SQLite).
-- The service's OWN database. User Postgres databases are never touched.

-- An account is a tenant, created by self-registration.
CREATE TABLE accounts (
  id               TEXT PRIMARY KEY,
  owner_email      TEXT NOT NULL,
  admin_token_hash TEXT NOT NULL UNIQUE,   -- SHA-256 of the admin token; raw token never stored
  created_at       TEXT NOT NULL
);

-- A registered user Postgres database. The connection string is encrypted
-- at rest (AES-GCM) and write-only over the API: set/rotate, never read back.
CREATE TABLE databases (
  id          TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  conn_enc    TEXT NOT NULL,               -- "<iv_b64>:<ciphertext_b64>"
  created_at  TEXT NOT NULL
);
CREATE INDEX idx_databases_account ON databases(account_id);

-- The masking baseline for a database: one row per (table, column).
-- A column with no row defaults to enabled + no mask.
CREATE TABLE column_policies (
  database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
  table_name  TEXT NOT NULL,
  column_name TEXT NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 1,  -- 0/1: may the agent see this column at all
  mask        TEXT NOT NULL DEFAULT 'none',-- none | hash | redact | email | null
  PRIMARY KEY (database_id, table_name, column_name)
);

-- A read-only data-plane credential, scoped to a set of databases.
-- It inherits each database's masking baseline; there is no per-token policy.
CREATE TABLE agent_tokens (
  id           TEXT PRIMARY KEY,
  account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,        -- SHA-256 of the agent token
  db_ids       TEXT NOT NULL,               -- JSON array of database ids
  created_at   TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX idx_agent_tokens_account ON agent_tokens(account_id);

-- Append-only audit trail spanning both planes.
CREATE TABLE audit_log (
  id         TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  actor      TEXT NOT NULL,                 -- 'admin' or an agent token id
  action     TEXT NOT NULL,                 -- e.g. 'account.create', 'db.add', 'query'
  detail     TEXT,                          -- JSON blob, never contains raw row data
  created_at TEXT NOT NULL
);
CREATE INDEX idx_audit_account_time ON audit_log(account_id, created_at);
