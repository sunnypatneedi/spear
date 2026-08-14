/**
 * Attack-pattern community registry client (local half of the data flywheel).
 *
 * Contributes SHA-256 hashes of normalized, truncated attack text — never raw
 * content. Fetches promoted patterns and merges them into `regex_block`.
 */

import { sha256Hex } from '../core/platform.js';
import type { Policy } from '../core/policy.js';

/**
 * Normalize an attack snippet before hashing: NFKC, lowercase, truncate to 64 chars.
 *
 * @param text Raw matched input
 */
export function normalizeForRegistry(text: string): string {
  return text.normalize('NFKC').toLowerCase().slice(0, 64);
}

/**
 * Client-side hash of an attack snippet.
 *
 * @param text Raw matched input
 */
export async function hashAttackPattern(text: string): Promise<string> {
  return sha256Hex(normalizeForRegistry(text));
}

export interface RegistryConfig {
  enabled: boolean;
  contribute: boolean;
  url?: string;
}

export interface RegistryFetchResult {
  patterns: string[];
  contributed: boolean;
}

/**
 * Fetch promoted patterns from a registry URL and optionally contribute a hash.
 *
 * Failures are swallowed (registry is best-effort, never on the request path).
 *
 * @param policy Active policy (reads `registry` section)
 * @param attackText Optional blocked input to contribute as a hash
 */
export async function syncPatternRegistry(
  policy: Policy,
  attackText?: string
): Promise<RegistryFetchResult> {
  const cfg = policy.registry;
  if (!cfg?.enabled) {
    return { patterns: [], contributed: false };
  }

  const url = cfg.url;
  if (!url) {
    return { patterns: [], contributed: false };
  }

  let patterns: string[] = [];
  try {
    const res = await fetch(`${url.replace(/\/$/, '')}/v1/patterns`);
    if (res.ok) {
      const body = await res.json() as { patterns?: string[] };
      patterns = Array.isArray(body.patterns) ? body.patterns.filter(p => typeof p === 'string') : [];
    }
  } catch {
    patterns = [];
  }

  let contributed = false;
  if (cfg.contribute && attackText) {
    try {
      const hash = await hashAttackPattern(attackText);
      const res = await fetch(`${url.replace(/\/$/, '')}/v1/patterns/contribute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash }),
      });
      contributed = res.ok;
    } catch {
      contributed = false;
    }
  }

  return { patterns, contributed };
}

/**
 * Merge fetched regex patterns into a policy copy (deduped).
 *
 * @param policy Base policy
 * @param patterns New regex strings
 */
export function mergeRegistryPatterns(policy: Policy, patterns: string[]): Policy {
  const existing = new Set(policy.input_rules.regex_block);
  const added = patterns.filter(p => p.length > 0 && !existing.has(p));
  if (added.length === 0) return policy;
  return {
    ...policy,
    input_rules: {
      ...policy.input_rules,
      regex_block: [...policy.input_rules.regex_block, ...added],
    },
  };
}
