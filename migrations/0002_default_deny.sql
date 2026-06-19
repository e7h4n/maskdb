-- Allowlist (default-deny) support. When default_deny = 1, a column with no
-- column_policies row is hidden from the agent: not listed in schema, and
-- rejected if queried. "Forgot to mask it" fails closed instead of leaking.
-- Defaults to 1 (deny) so registering a raw production DB is safe by default.
ALTER TABLE databases ADD COLUMN default_deny INTEGER NOT NULL DEFAULT 1;
