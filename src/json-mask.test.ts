import { describe, expect, it } from "vitest";
import { applyMask } from "./mask";
import { parseJsonFields } from "./store";
import { PolicyBody } from "./types";

const fields = ["id", "status", "createdAt", "updatedAt", "expiresAt"];
const metadata = {
  id: "entry_1",
  status: "active",
  createdAt: "2026-10-27T10:00:00Z",
  updatedAt: "2026-10-27T10:01:00Z",
  expiresAt: "2026-10-28T10:01:00Z",
};

describe("JSON field mask", () => {
  it("returns only approved scalar metadata from objects and arrays", async () => {
    const entry = {
      ...metadata,
      title: "private title",
      draft: { text: "private draft" },
      futureField: "private",
    };
    expect(await applyMask("json", entry, fields)).toStrictEqual(metadata);
    expect(await applyMask("json", [entry], fields)).toStrictEqual([metadata]);
    expect(entry.draft.text).toBe("private draft");
  });

  it("preserves empty arrays and null without returning content", async () => {
    expect(await applyMask("json", [], fields)).toStrictEqual([]);
    expect(await applyMask("json", null, fields)).toBeNull();
    expect(await applyMask("json", {}, fields)).toStrictEqual({});
  });

  it("redacts unexpected values, including nested values at approved keys", async () => {
    expect(
      await applyMask(
        "json",
        { status: { secret: "nested" }, id: ["private"] },
        fields,
      ),
    ).toStrictEqual({ status: "••••••••", id: "••••••••" });
    expect(
      await applyMask("json", ["secret", 42, [metadata], null], fields),
    ).toStrictEqual(["••••••••", "••••••••", "••••••••", null]);
    expect(await applyMask("json", "private JSON text", fields)).toBe(
      "••••••••",
    );
    expect(
      await applyMask(
        "json",
        { status: false, id: 1, expiresAt: null },
        fields,
      ),
    ).toStrictEqual({ status: false, id: 1, expiresAt: null });
  });

  it.each([undefined, [], ["status", "status"], ["__proto__"], ["draft.text"]])(
    "fails closed with missing or invalid JSON fields: %j",
    async (invalid) => {
      expect(await applyMask("json", metadata, invalid)).toBe("••••••••");
    },
  );

  it("does not return inherited properties", async () => {
    const entry = Object.create({ status: "private inherited value" });
    entry.id = "entry_1";
    expect(await applyMask("json", entry, fields)).toStrictEqual({
      id: "entry_1",
    });
  });

  it("keeps existing whole-column redaction", async () => {
    expect(await applyMask("redact", metadata)).toBe("••••••••");
    expect(await applyMask("email", metadata)).toBe("••••••••");
    expect(await applyMask("phone", metadata)).toBe("••••••••");
  });
});

describe("JSON policy validation", () => {
  const body = (column: Record<string, unknown>) => ({
    tables: [
      { table: "suggestions", columns: [{ name: "entries", ...column }] },
    ],
  });

  it("requires an explicit allowlist for JSON masks", () => {
    expect(
      PolicyBody.safeParse(body({ mask: "json", json_fields: fields })).success,
    ).toBe(true);
    expect(PolicyBody.safeParse(body({ mask: "json" })).success).toBe(false);
    expect(
      PolicyBody.safeParse(body({ mask: "json", json_fields: [] })).success,
    ).toBe(false);
    expect(
      PolicyBody.safeParse(body({ mask: "none", json_fields: fields })).success,
    ).toBe(false);
  });

  it.each([
    null,
    "invalid JSON",
    "{}",
    "[]",
    '["constructor"]',
    '["status","status"]',
  ])("does not load malformed stored configuration: %j", (value) => {
    expect(parseJsonFields(value)).toBeUndefined();
  });

  it("loads a persisted JSON allowlist", () => {
    expect(parseJsonFields(JSON.stringify(fields))).toStrictEqual(fields);
  });
});
