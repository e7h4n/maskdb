-- Unified single-class token model. One token class (prefix mk_) carries
-- scopes (JSON array of capability strings) and databases (JSON array:
-- ["*"] or specific db ids). The registration root token is just a token
-- with scopes:["*"], databases:["*"]. Clean slate: old data is discarded.

DROP TABLE IF EXISTS agent_tokens;
DROP TABLE IF EXISTS column_policies;
DROP TABLE IF EXISTS databases;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS accounts;

CREATE TABLE accounts (
  id TEXT PRIMARY KEY,
  owner_email TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE databases (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  conn_enc TEXT NOT NULL,
  created_at TEXT NOT NULL,
  default_deny INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_databases_account ON databases(account_id);
CREATE TABLE column_policies (
  database_id TEXT NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
  table_name TEXT NOT NULL,
  column_name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  mask TEXT NOT NULL DEFAULT 'none',
  PRIMARY KEY (database_id, table_name, column_name)
);
CREATE TABLE tokens (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  scopes TEXT NOT NULL,
  databases TEXT NOT NULL,
  created_by TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX idx_tokens_account ON tokens(account_id);
CREATE TABLE audit_log (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_audit_account_time ON audit_log(account_id, created_at);
