import postgres from "postgres";

// A connection to a user's Postgres database. postgres.js uses the Cloudflare
// TCP socket API under the hood when running on Workers (nodejs_compat).
//
// We open a short-lived connection per request (max: 1) and close it in a
// finally block. Pooling via Durable Objects is a later optimization.
export function connect(connectionString: string) {
  return postgres(connectionString, {
    max: 1,
    idle_timeout: 5,
    connect_timeout: 10,
    ssl: "require",
    // We never need prepared-statement caching across requests.
    prepare: false,
  });
}

export interface ColumnInfo {
  name: string;
  type: string;
  nullable: boolean;
}

export interface IndexInfo {
  name: string;
  definition: string;
}

// Only the public schema is exposed in v1.
export async function listTables(
  sql: postgres.Sql,
): Promise<string[]> {
  const rows = await sql<{ table_name: string }[]>`
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
    ORDER BY table_name`;
  return rows.map((r) => r.table_name);
}

export async function describeTable(
  sql: postgres.Sql,
  table: string,
): Promise<ColumnInfo[]> {
  const rows = await sql<
    { column_name: string; data_type: string; is_nullable: string }[]
  >`
    SELECT column_name, data_type, is_nullable
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = ${table}
    ORDER BY ordinal_position`;
  return rows.map((r) => ({
    name: r.column_name,
    type: r.data_type,
    nullable: r.is_nullable === "YES",
  }));
}

export async function listIndexes(
  sql: postgres.Sql,
  table: string,
): Promise<IndexInfo[]> {
  const rows = await sql<{ indexname: string; indexdef: string }[]>`
    SELECT indexname, indexdef
    FROM pg_indexes
    WHERE schemaname = 'public' AND tablename = ${table}
    ORDER BY indexname`;
  return rows.map((r) => ({ name: r.indexname, definition: r.indexdef }));
}
