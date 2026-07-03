import { describe, expect, it } from "vitest";
import {
  CompileError,
  compileAggregateQuery,
  compileQuery,
  type ColPolicy,
} from "./compiler";
import { AggregateBody, QueryBody } from "./types";

const validColumns = new Set(["id", "status", "amount", "email", "notes"]);
const columnTypes = new Map([
  ["id", "integer"],
  ["status", "text"],
  ["amount", "numeric"],
  ["email", "text"],
  ["notes", "text"],
]);

function policyFor(col: string): ColPolicy {
  if (col === "email") return { enabled: true, mask: "email" };
  if (col === "notes") return { enabled: false, mask: "none" };
  return { enabled: true, mask: "none" };
}

describe("compileQuery", () => {
  it("allows selecting masked columns but rejects filtering on them", () => {
    const selected = compileQuery(
      QueryBody.parse({
        table: "orders",
        select: ["id", "email"],
      }),
      "orders",
      validColumns,
      policyFor,
      1000,
    );

    expect(selected.text).toBe(
      'SELECT "id", "email" FROM "orders" LIMIT $1 OFFSET $2',
    );
    expect(selected.maskPlan).toEqual([{ column: "email", mask: "email" }]);

    expect(() =>
      compileQuery(
        QueryBody.parse({
          table: "orders",
          select: ["id"],
          where: { col: "email", op: "eq", value: "a@example.com" },
        }),
        "orders",
        validColumns,
        policyFor,
        1000,
      ),
    ).toThrow(CompileError);
  });
});

describe("compileAggregateQuery", () => {
  it("compiles grouped count and sum over unmasked columns", () => {
    const compiled = compileAggregateQuery(
      AggregateBody.parse({
        table: "orders",
        group_by: ["status"],
        metrics: [
          { op: "count", as: "orders" },
          { op: "sum", col: "amount", as: "revenue" },
        ],
        order_by: [{ col: "revenue", dir: "desc" }],
        limit: 25,
      }),
      "orders",
      validColumns,
      columnTypes,
      policyFor,
      1000,
    );

    expect(compiled.text).toBe(
      'SELECT "status", COUNT(*) AS "orders", SUM("amount") AS "revenue" FROM "orders" GROUP BY "status" ORDER BY "revenue" DESC LIMIT $1 OFFSET $2',
    );
    expect(compiled.params).toEqual([25, 0]);
  });

  it("rejects masked group and metric columns", () => {
    expect(() =>
      compileAggregateQuery(
        AggregateBody.parse({
          table: "orders",
          group_by: ["email"],
          metrics: [{ op: "count" }],
        }),
        "orders",
        validColumns,
        columnTypes,
        policyFor,
        1000,
      ),
    ).toThrow(CompileError);

    expect(() =>
      compileAggregateQuery(
        AggregateBody.parse({
          table: "orders",
          metrics: [{ op: "count", col: "email" }],
        }),
        "orders",
        validColumns,
        columnTypes,
        policyFor,
        1000,
      ),
    ).toThrow(CompileError);
  });

  it("rejects disabled and non-numeric sum columns", () => {
    expect(() =>
      compileAggregateQuery(
        AggregateBody.parse({
          table: "orders",
          metrics: [{ op: "count", col: "notes" }],
        }),
        "orders",
        validColumns,
        columnTypes,
        policyFor,
        1000,
      ),
    ).toThrow(CompileError);

    expect(() =>
      compileAggregateQuery(
        AggregateBody.parse({
          table: "orders",
          metrics: [{ op: "sum", col: "status" }],
        }),
        "orders",
        validColumns,
        columnTypes,
        policyFor,
        1000,
      ),
    ).toThrow(CompileError);
  });

  it("rejects ordering by fields that are not aggregate outputs", () => {
    expect(() =>
      compileAggregateQuery(
        AggregateBody.parse({
          table: "orders",
          metrics: [{ op: "count" }],
          order_by: [{ col: "status" }],
        }),
        "orders",
        validColumns,
        columnTypes,
        policyFor,
        1000,
      ),
    ).toThrow(CompileError);
  });
});
