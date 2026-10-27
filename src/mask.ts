import { JsonFields, type MaskStrategy } from "./types";
import { sha256Hex } from "./crypto";

function projectJsonObject(value: unknown, fields: readonly string[]): unknown {
  if (value === null) return null;
  if (typeof value !== "object" || Array.isArray(value)) return "••••••••";
  const object = value as Record<string, unknown>;
  return Object.fromEntries(
    fields
      .filter((field) => Object.prototype.hasOwnProperty.call(object, field))
      .map((field) => {
        const item = object[field];
        const scalar = item === null || typeof item === "string" ||
          typeof item === "boolean" ||
          (typeof item === "number" && Number.isFinite(item));
        return [field, scalar ? item : "••••••••"];
      }),
  );
}

// Masks are applied inside the proxy, after fetching from Postgres and before
// the response is serialized to the agent. Raw values never reach the caller.
//
// Because masked columns are never allowed in WHERE / ORDER BY (enforced by the
// compiler), there is no boolean-oracle channel to reconstruct them.
export async function applyMask(
  strategy: MaskStrategy,
  value: unknown,
  jsonFields?: readonly string[],
): Promise<unknown> {
  if (strategy === "none") return value;
  if (value === null || value === undefined) return value;

  if (strategy === "json") {
    const fields = JsonFields.safeParse(jsonFields);
    if (!fields.success) return "••••••••";
    return Array.isArray(value)
      ? value.map((item) => projectJsonObject(item, fields.data))
      : projectJsonObject(value, fields.data);
  }

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
