import { z } from "zod";

export interface Env {
  DB: D1Database;
  MASTER_KEY: string; // base64 32-byte AES-GCM key (wrangler secret)
  MAX_LIMIT: string;
}

// The authenticated principal, resolved by the auth middleware.
export type Principal =
  | { kind: "admin"; accountId: string }
  | { kind: "agent"; accountId: string; tokenId: string; dbIds: string[] };

// Hono context variables.
export type Vars = { principal: Principal };

// ---- mask strategies ------------------------------------------------------
export const MaskStrategy = z.enum([
  "none",
  "hash",
  "redact",
  "email",
  "phone",
  "null",
]);
export type MaskStrategy = z.infer<typeof MaskStrategy>;

// ---- control plane request bodies -----------------------------------------
export const RegisterBody = z.object({
  owner_email: z.string().email(),
});

export const AddDatabaseBody = z.object({
  name: z.string().min(1).max(100),
  connection_string: z.string().min(1),
  // Allowlist mode: only columns explicitly enabled in the policy are readable.
  // Defaults to true so a raw production DB is safe to register.
  default_deny: z.boolean().default(true),
});

export const PolicyBody = z.object({
  tables: z.array(
    z.object({
      table: z.string().min(1),
      columns: z.array(
        z.object({
          name: z.string().min(1),
          enabled: z.boolean().default(true),
          mask: MaskStrategy.default("none"),
        }),
      ),
    }),
  ),
});

export const MintTokenBody = z.object({
  name: z.string().min(1).max(100),
  db_ids: z.array(z.string().min(1)).min(1),
});

// ---- data plane query DSL -------------------------------------------------
export const OP = z.enum([
  "eq",
  "neq",
  "gt",
  "gte",
  "lt",
  "lte",
  "contains",
  "in",
  "is_null",
]);
export type Op = z.infer<typeof OP>;

// A scalar value usable in a filter.
const Scalar = z.union([z.string(), z.number(), z.boolean(), z.null()]);

// A where node is recursive: a leaf condition or a boolean group.
export type WhereNode =
  | { col: string; op: Op; value?: unknown }
  | { and: WhereNode[] }
  | { or: WhereNode[] }
  | { not: WhereNode };

export const WhereNode: z.ZodType<WhereNode> = z.lazy(() =>
  z.union([
    z.object({
      col: z.string().min(1),
      op: OP,
      value: z.union([Scalar, z.array(Scalar)]).optional(),
    }),
    z.object({ and: z.array(WhereNode).min(1) }),
    z.object({ or: z.array(WhereNode).min(1) }),
    z.object({ not: WhereNode }),
  ]),
);

export const QueryBody = z.object({
  table: z.string().min(1),
  select: z.array(z.string().min(1)).min(1),
  where: WhereNode.optional(),
  order_by: z
    .array(
      z.object({
        col: z.string().min(1),
        dir: z.enum(["asc", "desc"]).default("asc"),
      }),
    )
    .optional(),
  limit: z.number().int().positive().optional(),
  offset: z.number().int().nonnegative().default(0),
});
export type QueryBody = z.infer<typeof QueryBody>;
