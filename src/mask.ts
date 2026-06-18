import type { MaskStrategy } from "./types";
import { sha256Hex } from "./crypto";

// Masks are applied inside the proxy, after fetching from Postgres and before
// the response is serialized to the agent. Raw values never reach the caller.
//
// Because masked columns are never allowed in WHERE / ORDER BY (enforced by the
// compiler), there is no boolean-oracle channel to reconstruct them.
export async function applyMask(
  strategy: MaskStrategy,
  value: unknown,
): Promise<unknown> {
  if (strategy === "none") return value;
  if (value === null || value === undefined) return value;

  const s = String(value);
  switch (strategy) {
    case "null":
      return null;
    case "redact":
      return "••••••••";
    case "hash":
      // Irreversible but deterministic: equal inputs hash equal, so values
      // stay joinable across rows without exposing the original.
      return await sha256Hex(s);
    case "email": {
      const at = s.indexOf("@");
      if (at <= 0) return "••••••••";
      const first = s[0];
      const domain = s.slice(at);
      return `${first}***${domain}`;
    }
    default:
      return "••••••••";
  }
}
