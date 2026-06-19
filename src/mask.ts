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

  // Partial-reveal masks assume a plain string. For JSON/array columns (parsed
  // into objects by postgres.js), stringifying could echo structure/content —
  // so fall closed to full redaction instead.
  if ((strategy === "email" || strategy === "phone") && typeof value !== "string") {
    return "••••••••";
  }

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
    case "phone": {
      // Keep the last 4 digits, mask all earlier digits with X, and preserve
      // separators like "+", "-", "(", ")", and spaces for readability.
      const digitCount = (s.match(/\d/g) || []).length;
      if (digitCount <= 4) return s.replace(/\d/g, "X");
      const toMask = digitCount - 4;
      let masked = 0;
      let out = "";
      for (const ch of s) {
        if (ch >= "0" && ch <= "9" && masked < toMask) {
          out += "X";
          masked++;
        } else {
          out += ch;
        }
      }
      return out;
    }
    default:
      return "••••••••";
  }
}
