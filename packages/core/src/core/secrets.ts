/**
 * Lightweight secret detection for agent boundaries.
 *
 * This is intentionally a conservative, dependency-free detector. It is not
 * a replacement for a secrets manager or a vendor-specific scanner; its job is
 * to stop the most damaging accidental disclosure paths before an agent sends
 * data to another service.
 */

/** Known secret classes detected by SPEAR. */
export type SecretType =
  | 'private_key'
  | 'aws_access_key'
  | 'github_token'
  | 'huggingface_token'
  | 'openai_key'
  | 'jwt'
  | 'generic_secret';

/** A secret match. The raw value is never included in this result. */
export interface SecretMatch {
  type: SecretType;
  start: number;
  end: number;
  redacted: string;
}

/** Result of scanning a value for credentials or secret material. */
export interface SecretScanResult {
  detected: boolean;
  matches: SecretMatch[];
}

interface SecretPattern {
  type: SecretType;
  pattern: RegExp;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    type: 'private_key',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g
  },
  { type: 'aws_access_key', pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { type: 'github_token', pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g },
  { type: 'huggingface_token', pattern: /\bhf_[A-Za-z0-9]{20,}\b/g },
  { type: 'openai_key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  {
    type: 'jwt',
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g
  },
  {
    type: 'generic_secret',
    pattern: /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|private[_-]?key|secret)\b["']?\s*[:=]\s*["']?[A-Za-z0-9_./+=:-]{12,}["']?/gi
  },
  {
    type: 'generic_secret',
    pattern: /\b(?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_TOKEN|HF_TOKEN|OPENAI_API_KEY|DATABASE_URL|GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET)\b["']?\s*[:=]\s*["']?[A-Za-z0-9_./+=:@?&-]{12,}["']?/gi
  },
  {
    type: 'generic_secret',
    pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b/gi
  }
];

/** Serialize a value for inspection; reject oversized or unserializable values. */
export function stringifyForInspection(value: unknown, maxLength = 100_000): string {
  let text: string;

  if (typeof value === 'string') {
    text = value;
  } else {
    try {
      text = JSON.stringify(value) ?? String(value);
    } catch {
      throw new Error('Value cannot be serialized for security inspection');
    }
  }

  if (text.length > maxLength) throw new Error('Value exceeds security inspection limit');
  return text;
}

/** Scan text or a JSON-like value for common credential formats. */
export function scanSecrets(value: unknown): SecretScanResult {
  const text = stringifyForInspection(value);
  if (!text) return { detected: false, matches: [] };

  const matches: SecretMatch[] = [];

  for (const { type, pattern } of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      if (match.index === undefined) continue;
      matches.push({
        type,
        start: match.index,
        end: match.index + match[0].length,
        redacted: redactMatch(match[0])
      });
    }
  }

  matches.sort((a, b) => a.start - b.start || b.end - a.end);
  return { detected: matches.length > 0, matches };
}

/** Return true when a value contains a recognized secret format. */
export function containsSecrets(value: unknown): boolean {
  return scanSecrets(value).detected;
}

/** Replace recognized secret material while preserving a small fingerprint. */
export function redactSecrets(value: unknown): string {
  const text = stringifyForInspection(value);
  const matches = scanSecrets(text).matches;
  if (matches.length === 0) return text;

  const ranges: Array<{ start: number; end: number }> = [];
  for (const match of matches) {
    const last = ranges[ranges.length - 1];
    if (last && match.start <= last.end) last.end = Math.max(last.end, match.end);
    else ranges.push({ start: match.start, end: match.end });
  }
  let result = text;
  for (const match of ranges.reverse()) {
    result = `${result.slice(0, match.start)}[REDACTED]${result.slice(match.end)}`;
  }
  return result;
}

function redactMatch(value: string): string {
  if (value.length <= 8) return '[REDACTED]';
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}
