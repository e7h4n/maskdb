import type { MaskStrategy, Op, QueryBody, WhereNode } from "./types";

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

  // --- WHERE --------------------------------------------------------------
  const compileNode = (node: WhereNode): string => {
    if ("and" in node) {
      return `(${node.and.map(compileNode).join(" AND ")})`;
    }
    if ("or" in node) {
      return `(${node.or.map(compileNode).join(" OR ")})`;
    }
    if ("not" in node) {
      return `(NOT ${compileNode(node.not)})`;
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
  };

  let text = `SELECT ${selectSql.join(", ")} FROM ${ident(table)}`;
  if (body.where) text += ` WHERE ${compileNode(body.where)}`;

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
