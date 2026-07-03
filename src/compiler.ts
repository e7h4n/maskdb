import type {
  AggregateBody,
  MaskStrategy,
  Op,
  QueryBody,
  WhereNode,
} from "./types";

export class CompileError extends Error {}

export interface ColPolicy {
  enabled: boolean;
  mask: MaskStrategy;
}

export interface Compiled {
  text: string;
  params: unknown[];
  // Columns selected that must be masked post-fetch, in result order.
  maskPlan: { column: string; mask: MaskStrategy }[];
}

export interface AggregateCompiled {
  text: string;
  params: unknown[];
}

const OP_SQL: Record<Exclude<Op, "contains" | "in" | "is_null">, string> = {
  eq: "=",
  neq: "<>",
  gt: ">",
  gte: ">=",
  lt: "<",
  lte: "<=",
};

// Double-quote an identifier that has already been allowlisted against the
// live schema. The quote-doubling is defense-in-depth, not the primary guard.
function ident(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}

// Resolve a column for use in SELECT (masked allowed) or in a
// filter/sort position (masked rejected — that would be an oracle).
function resolve(
  col: string,
  validColumns: Set<string>,
  policyFor: (c: string) => ColPolicy,
  position: "select" | "filter",
): ColPolicy {
  if (!validColumns.has(col)) {
    throw new CompileError(`unknown column: ${col}`);
  }
  const p = policyFor(col);
  if (!p.enabled) {
    throw new CompileError(`column not available: ${col}`);
  }
  if (position === "filter" && p.mask !== "none") {
    throw new CompileError(
      `masked column cannot be used in a filter or sort: ${col}`,
    );
  }
  return p;
}

type Bind = (v: unknown) => string;

function compileWhere(
  node: WhereNode,
  validColumns: Set<string>,
  policyFor: (c: string) => ColPolicy,
  bind: Bind,
): string {
  if ("and" in node) {
    return `(${node.and
      .map((child) => compileWhere(child, validColumns, policyFor, bind))
      .join(" AND ")})`;
  }
  if ("or" in node) {
    return `(${node.or
      .map((child) => compileWhere(child, validColumns, policyFor, bind))
      .join(" OR ")})`;
  }
  if ("not" in node) {
    return `(NOT ${compileWhere(node.not, validColumns, policyFor, bind)})`;
  }
  // leaf condition
  resolve(node.col, validColumns, policyFor, "filter");
  const c = ident(node.col);
  switch (node.op) {
    case "is_null":
      return `${c} IS NULL`;
    case "contains": {
      if (typeof node.value !== "string") {
        throw new CompileError(`'contains' requires a string value`);
      }
      const escaped = node.value.replace(/([\\%_])/g, "\\$1");
      return `${c} ILIKE ${bind(`%${escaped}%`)} ESCAPE '\\'`;
    }
    case "in": {
      if (!Array.isArray(node.value)) {
        throw new CompileError(`'in' requires an array value`);
      }
      return `${c} = ANY(${bind(node.value)})`;
    }
    default:
      if (node.value === undefined) {
        throw new CompileError(`'${node.op}' requires a value`);
      }
      return `${c} ${OP_SQL[node.op]} ${bind(node.value)}`;
  }
}

export function compileQuery(
  body: QueryBody,
  table: string,
  validColumns: Set<string>,
  policyFor: (c: string) => ColPolicy,
  maxLimit: number,
): Compiled {
  const params: unknown[] = [];
  const bind = (v: unknown): string => {
    params.push(v);
    return `$${params.length}`;
  };

  // --- SELECT (masked columns are fetched raw, masked after the query) ----
  const maskPlan: { column: string; mask: MaskStrategy }[] = [];
  const selectSql = body.select.map((col) => {
    const p = resolve(col, validColumns, policyFor, "select");
    if (p.mask !== "none") maskPlan.push({ column: col, mask: p.mask });
    return ident(col);
  });

  let text = `SELECT ${selectSql.join(", ")} FROM ${ident(table)}`;
  if (body.where) {
    text += ` WHERE ${compileWhere(body.where, validColumns, policyFor, bind)}`;
  }

  // --- ORDER BY -----------------------------------------------------------
  if (body.order_by && body.order_by.length > 0) {
    const parts = body.order_by.map((o) => {
      resolve(o.col, validColumns, policyFor, "filter");
      return `${ident(o.col)} ${o.dir === "desc" ? "DESC" : "ASC"}`;
    });
    text += ` ORDER BY ${parts.join(", ")}`;
  }

  // --- LIMIT / OFFSET (hard ceiling) --------------------------------------
  const limit = Math.min(body.limit ?? maxLimit, maxLimit);
  text += ` LIMIT ${bind(limit)} OFFSET ${bind(body.offset)}`;

  return { text, params, maskPlan };
}

function isNumericType(type: string | undefined): boolean {
  if (!type) return false;
  return new Set([
    "smallint",
    "integer",
    "bigint",
    "decimal",
    "numeric",
    "real",
    "double precision",
  ]).has(type.toLowerCase());
}

const OUTPUT_ALIAS = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;

function metricAlias(metric: AggregateBody["metrics"][number]): string {
  if (metric.as) return metric.as;
  const alias = metric.col ? `${metric.op}_${metric.col}` : metric.op;
  if (!OUTPUT_ALIAS.test(alias)) {
    throw new CompileError(`aggregate alias required for column: ${metric.col}`);
  }
  return alias;
}

export function compileAggregateQuery(
  body: AggregateBody,
  table: string,
  validColumns: Set<string>,
  columnTypes: Map<string, string>,
  policyFor: (c: string) => ColPolicy,
  maxLimit: number,
): AggregateCompiled {
  const params: unknown[] = [];
  const bind = (v: unknown): string => {
    params.push(v);
    return `$${params.length}`;
  };

  const selectSql: string[] = [];
  const groupSql: string[] = [];
  const outputColumns = new Set<string>();

  for (const col of body.group_by) {
    if (outputColumns.has(col)) {
      throw new CompileError(`duplicate output column: ${col}`);
    }
    resolve(col, validColumns, policyFor, "filter");
    const quoted = ident(col);
    selectSql.push(quoted);
    groupSql.push(quoted);
    outputColumns.add(col);
  }

  for (const metric of body.metrics) {
    const alias = metricAlias(metric);
    if (outputColumns.has(alias)) {
      throw new CompileError(`duplicate output column: ${alias}`);
    }

    if (metric.op === "count") {
      if (metric.col) {
        resolve(metric.col, validColumns, policyFor, "filter");
        selectSql.push(`COUNT(${ident(metric.col)}) AS ${ident(alias)}`);
      } else {
        selectSql.push(`COUNT(*) AS ${ident(alias)}`);
      }
    } else {
      if (!metric.col) {
        throw new CompileError(`'sum' requires a column`);
      }
      resolve(metric.col, validColumns, policyFor, "filter");
      if (!isNumericType(columnTypes.get(metric.col))) {
        throw new CompileError(`sum requires a numeric column: ${metric.col}`);
      }
      selectSql.push(`SUM(${ident(metric.col)}) AS ${ident(alias)}`);
    }

    outputColumns.add(alias);
  }

  let text = `SELECT ${selectSql.join(", ")} FROM ${ident(table)}`;
  if (body.where) {
    text += ` WHERE ${compileWhere(body.where, validColumns, policyFor, bind)}`;
  }
  if (groupSql.length > 0) {
    text += ` GROUP BY ${groupSql.join(", ")}`;
  }

  if (body.order_by && body.order_by.length > 0) {
    const parts = body.order_by.map((o) => {
      if (!outputColumns.has(o.col)) {
        throw new CompileError(`unknown aggregate output column: ${o.col}`);
      }
      return `${ident(o.col)} ${o.dir === "desc" ? "DESC" : "ASC"}`;
    });
    text += ` ORDER BY ${parts.join(", ")}`;
  }

  const limit = Math.min(body.limit ?? maxLimit, maxLimit);
  text += ` LIMIT ${bind(limit)} OFFSET ${bind(body.offset)}`;

  return { text, params };
}
