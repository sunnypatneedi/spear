/**
 * Cross-runtime primitives (Node, browsers, Cloudflare Workers, Deno).
 *
 * Avoids Node-only APIs (`Buffer`, `fs`) so gates can run at the edge.
 */

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Decode a base64 string to UTF-8 text without `Buffer`.
 *
 * @param input Base64 (standard or URL-safe)
 * @returns Decoded string, or null if the input is not valid base64
 */
export function base64Decode(input: string): string | null {
  if (!input) return null;
  try {
    const normalized = input.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
    if (typeof atob === 'function') {
      return atob(normalized);
    }
    return decodeBase64Manual(normalized);
  } catch {
    return null;
  }
}

function decodeBase64Manual(input: string): string | null {
  let str = input;
  while (str.length % 4 !== 0) str += '=';
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of str) {
    if (ch === '=') break;
    const idx = B64.indexOf(ch);
    if (idx < 0) return null;
    value = (value << 6) | idx;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 0xff);
    }
  }
  return String.fromCharCode(...bytes);
}

/**
 * Fill a Uint8Array with cryptographically strong random values when available.
 *
 * @param length Number of bytes
 */
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(out);
    return out;
  }
  for (let i = 0; i < length; i++) {
    out[i] = Math.floor(Math.random() * 256);
  }
  return out;
}

/**
 * SHA-256 hex digest. Uses Web Crypto when available; falls back to a
 * non-cryptographic FNV-1a hex for extremely constrained runtimes so
 * the registry client can still produce a stable identifier.
 *
 * @param text UTF-8 text to hash
 */
export async function sha256Hex(text: string): Promise<string> {
  const encoded = new TextEncoder().encode(text);
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const digest = await crypto.subtle.digest('SHA-256', encoded);
    return Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
  let hash = 2166136261;
  for (const byte of encoded) {
    hash ^= byte;
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}
