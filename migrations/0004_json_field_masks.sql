-- Opt-in JSON field projection. Existing column policies keep their masks.
ALTER TABLE column_policies ADD COLUMN json_fields TEXT;
