// Token generation/hashing and AES-GCM encryption of connection strings.
// All primitives come from the Web Crypto API available in Workers.

const enc = new TextEncoder();
const dec = new TextDecoder();

function toB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromB64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// A url-safe random secret, e.g. "mk_admin_<43 base64url chars>".
export function newToken(prefix: "mk_admin" | "mk_agent"): string {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const b64url = toB64(raw)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${prefix}_${b64url}`;
}

// We only ever store the hash of a token, never the token itself.
export async function hashToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(token));
  return toB64(new Uint8Array(digest));
}

async function importKey(masterKeyB64: string): Promise<CryptoKey> {
  const keyBytes = fromB64(masterKeyB64);
  if (keyBytes.length !== 32) {
    throw new Error("MASTER_KEY must be a base64-encoded 32-byte key");
  }
  return crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

// "<iv_b64>:<ciphertext_b64>"
export async function encryptSecret(
  masterKeyB64: string,
  plaintext: string,
): Promise<string> {
  const key = await importKey(masterKeyB64);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plaintext),
  );
  return `${toB64(iv)}:${toB64(new Uint8Array(ct))}`;
}

export async function decryptSecret(
  masterKeyB64: string,
  stored: string,
): Promise<string> {
  const [ivB64, ctB64] = stored.split(":");
  if (!ivB64 || !ctB64) throw new Error("malformed ciphertext");
  const key = await importKey(masterKeyB64);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(ivB64) },
    key,
    fromB64(ctB64),
  );
  return dec.decode(pt);
}

// Deterministic, irreversible mask for the "hash" strategy.
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(input));
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
