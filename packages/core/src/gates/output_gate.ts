/**
 * OutputGate: Last line of defense before returning LLM output
 * 
 * Validates output doesn't contain:
 * 1. Canary tokens (proof of prompt exfiltration)
 * 2. Deny-listed n-grams (e.g., "system prompt")
 * 3. PII that should be masked
 * 4. Cross-lingual similarity to system prompt (optional sidecar)
 */

import { containsCanary, containsAnyCanary } from '../core/canary.js';
import { containsPII, maskPII, type PIIConfig } from '../core/pii.js';
import type { Policy } from '../core/policy.js';

/**
 * Output gate input
 */
export interface OutputGateInput {
  output: string;
  canaries?: string[];
  systemPrompt?: string;
}

/**
 * Output gate result
 */
export interface OutputGateResult {
  allowed: boolean;
  reason?: string;
  output: string;  // Potentially masked/sanitized output
  score: number;   // Risk score 0-1
}

/**
 * Sidecar similarity check options
 */
export interface SidecarOptions {
  url?: string;
  budgetMs?: number;
  enabled?: boolean;
}

/**
 * Check if output contains any deny-listed n-grams
 */
function containsDenyNgrams(output: string, ngrams: string[]): { matched: boolean; ngram?: string } {
  const lowerOutput = output.toLowerCase();

  for (const ngram of ngrams) {
    if (lowerOutput.includes(ngram.toLowerCase())) {
      return { matched: true, ngram };
    }
  }

  return { matched: false };
}

/**
 * Safe base64 decode with error handling
 */
function safeBase64Decode(str: string): string | null {
  try {
    // Node.js Buffer-based decoding
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(str, 'base64').toString('utf-8');
    }
    // Browser/Deno atob fallback
    return atob(str);
  } catch {
    return null;
  }
}

/**
 * Safe hex decode with error handling
 */
function safeHexDecode(str: string): string | null {
  try {
    if (str.length % 2 !== 0) return null;
    let result = '';
    for (let i = 0; i < str.length; i += 2) {
      const byte = parseInt(str.substring(i, i + 2), 16);
      if (isNaN(byte)) return null;
      result += String.fromCharCode(byte);
    }
    return result;
  } catch {
    return null;
  }
}

/**
 * Detect encoded/hashed leaks in output (side-channel prevention)
 *
 * Attackers may try to exfiltrate system prompts via:
 * - Base64 encoding
 * - Hex encoding
 * - Other obfuscation techniques
 *
 * This function decodes suspicious patterns and checks for leaks.
 */
function detectEncodedLeak(
  output: string,
  canaries: string[],
  denyNgrams: string[]
): { detected: boolean; encoding?: string; reason?: string } {
  // 1. Detect base64-looking strings (20+ chars of base64 alphabet)
  const base64Regex = /[A-Za-z0-9+/]{20,}={0,2}/g;
  const base64Matches = output.match(base64Regex) || [];

  for (const match of base64Matches) {
    const decoded = safeBase64Decode(match);
    if (!decoded) continue;

    // Check if decoded contains canary tokens
    for (const canary of canaries) {
      if (decoded.toLowerCase().includes(canary.toLowerCase())) {
        return {
          detected: true,
          encoding: 'base64',
          reason: `Canary token detected in base64-encoded content`
        };
      }
    }

    // Check if decoded contains deny-listed n-grams
    for (const ngram of denyNgrams) {
      if (decoded.toLowerCase().includes(ngram.toLowerCase())) {
        return {
          detected: true,
          encoding: 'base64',
          reason: `Deny-listed phrase "${ngram}" detected in base64-encoded content`
        };
      }
    }

    // Check for system prompt fragments in decoded content
    const suspiciousPatterns = [
      /you are an? (ai|assistant|helpful)/i,
      /your (role|purpose|task) is/i,
      /instructions:/i,
      /do not reveal/i,
      /keep (this|these) (secret|private|confidential)/i
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(decoded)) {
        return {
          detected: true,
          encoding: 'base64',
          reason: `Suspicious system prompt fragment in base64-encoded content`
        };
      }
    }
  }

  // 2. Detect hex-encoded strings (40+ hex chars, likely SHA-256 or encoded text)
  const hexRegex = /\b[0-9a-fA-F]{40,}\b/g;
  const hexMatches = output.match(hexRegex) || [];

  for (const match of hexMatches) {
    // Skip if it looks like a hash (exactly 64 chars = SHA-256)
    if (match.length === 64) {
      // Could be legitimate hash, but flag if suspicious context
      const contextBefore = output.substring(
        Math.max(0, output.indexOf(match) - 50),
        output.indexOf(match)
      ).toLowerCase();

      if (contextBefore.includes('system') ||
          contextBefore.includes('prompt') ||
          contextBefore.includes('instruction')) {
        return {
          detected: true,
          encoding: 'sha256',
          reason: `SHA-256 hash appears to be of system prompt content`
        };
      }
      continue;
    }

    // Try to decode as hex
    const decoded = safeHexDecode(match);
    if (!decoded) continue;

    // Check for canaries in hex-decoded content
    for (const canary of canaries) {
      if (decoded.toLowerCase().includes(canary.toLowerCase())) {
        return {
          detected: true,
          encoding: 'hex',
          reason: `Canary token detected in hex-encoded content`
        };
      }
    }
  }

  // 3. Detect ROT13 encoded content (common obfuscation)
  const rot13Decode = (str: string): string => {
    return str.replace(/[a-zA-Z]/g, (char) => {
      const base = char <= 'Z' ? 65 : 97;
      return String.fromCharCode(((char.charCodeAt(0) - base + 13) % 26) + base);
    });
  };

  // Look for text that when ROT13'd contains suspicious content
  // Only check longer strings that could be encoded prompts
  const words = output.split(/\s+/).filter(w => w.length > 10);
  for (const word of words.slice(0, 20)) { // Limit to first 20 long words
    const rotDecoded = rot13Decode(word);
    for (const ngram of denyNgrams) {
      if (rotDecoded.toLowerCase().includes(ngram.toLowerCase())) {
        return {
          detected: true,
          encoding: 'rot13',
          reason: `Deny-listed phrase detected in ROT13-encoded content`
        };
      }
    }
  }

  return { detected: false };
}

/**
 * Call sidecar similarity service with timeout
 */
async function checkSidecarSimilarity(
  output: string,
  systemPrompt: string,
  options: SidecarOptions
): Promise<{ score: number; error?: string }> {
  if (!options.url || !options.enabled) {
    return { score: 0 };
  }
  
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.budgetMs || 30);
  
  try {
    const response = await fetch(`${options.url}/v1/similarity`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: output,
        reference: systemPrompt
      }),
      signal: controller.signal
    });
    
    if (!response.ok) {
      return { score: 0, error: `Sidecar returned ${response.status}` };
    }
    
    const data = await response.json() as Record<string, unknown>;
    return { score: (data.score as number) || 0 };
  } catch (error) {
    // Timeout or network error - degrade gracefully
    if (error instanceof Error) {
      return { score: 0, error: error.message };
    }
    return { score: 0, error: 'Unknown error' };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Calculate output risk score
 */
function calculateOutputRisk(
  canaryDetected: boolean,
  ngramDetected: boolean,
  piiDetected: boolean,
  similarityScore: number,
  encodedLeakDetected: boolean = false
): number {
  let score = 0;

  // Canary is strongest signal (definitive leak)
  if (canaryDetected) {
    score = 1.0;
  }
  // Encoded leak is also very strong signal
  else if (encodedLeakDetected) {
    score = Math.max(score, 0.95);
  }
  // N-gram match is strong signal
  else if (ngramDetected) {
    score = Math.max(score, 0.8);
  }
  // Similarity score from sidecar
  else if (similarityScore > 0) {
    score = Math.max(score, similarityScore);
  }

  // PII adds to score
  if (piiDetected) {
    score = Math.min(score + 0.1, 1.0);
  }

  return score;
}

/**
 * Output gate: Validate and sanitize LLM output
 * 
 * @param input Output to validate
 * @param policy SPEAR policy configuration
 * @param sidecarOptions Optional sidecar configuration
 * @returns Gate result with sanitized output
 * 
 * @example
 * ```typescript
 * const result = await outputGate(
 *   { output: 'Here is the answer...', canaries: ['abc123'] },
 *   policy
 * );
 * // result.allowed === true (no issues)
 * ```
 */
export async function outputGate(
  input: OutputGateInput,
  policy: Policy,
  sidecarOptions: SidecarOptions = {}
): Promise<OutputGateResult> {
  const { output, canaries = [], systemPrompt } = input;
  
  if (!output) {
    return {
      allowed: true,
      output: '',
      score: 0
    };
  }
  
  // Step 1: Canary detection (instant block if found)
  const canaryDetected = canaries.length > 0 && containsAnyCanary(output, canaries);
  
  if (canaryDetected) {
    return {
      allowed: false,
      reason: 'Canary token detected in output (proof of prompt leak)',
      output: policy.refusal_phrases[0] || 'Request blocked by security policy.',
      score: 1.0
    };
  }
  
  // Step 2: N-gram denylist check
  const ngramResult = containsDenyNgrams(output, policy.output_rules.deny_ngrams);

  if (ngramResult.matched) {
    if (policy.mode === 'enforce') {
      return {
        allowed: false,
        reason: `Output contains deny-listed phrase: ${ngramResult.ngram}`,
        output: policy.refusal_phrases[0] || 'Request blocked by security policy.',
        score: 0.8
      };
    }
    // Shadow mode: allow but flag
  }

  // Step 3: Encoded leak detection (base64, hex, rot13 obfuscation)
  const encodedLeakResult = detectEncodedLeak(
    output,
    canaries,
    policy.output_rules.deny_ngrams
  );

  if (encodedLeakResult.detected) {
    if (policy.mode === 'enforce') {
      return {
        allowed: false,
        reason: encodedLeakResult.reason || 'Encoded content leak detected',
        output: policy.refusal_phrases[0] || 'Request blocked by security policy.',
        score: 0.95
      };
    }
    // Shadow mode: allow but flag
  }

  // Step 4: PII detection and masking
  const piiConfig: PIIConfig = policy.output_rules.pii;
  const piiDetected = containsPII(output, piiConfig);
  
  let sanitizedOutput = output;
  if (piiDetected && (piiConfig.email || piiConfig.phone || piiConfig.credit_card)) {
    sanitizedOutput = maskPII(output, piiConfig);
  }
  
  // Step 4: Optional sidecar similarity check
  let similarityScore = 0;
  if (policy.similarity.enabled && systemPrompt && sidecarOptions.url) {
    const similarityResult = await checkSidecarSimilarity(
      output,
      systemPrompt,
      {
        ...sidecarOptions,
        enabled: true,
        budgetMs: sidecarOptions.budgetMs || policy.sidecar_budget_ms
      }
    );
    
    similarityScore = similarityResult.score;
    
    // If similarity exceeds threshold, block or flag
    if (similarityScore >= policy.similarity.threshold) {
      if (policy.mode === 'enforce') {
        return {
          allowed: false,
          reason: `Output too similar to system prompt (score: ${similarityScore.toFixed(2)})`,
          output: policy.refusal_phrases[0] || 'Request blocked by security policy.',
          score: similarityScore
        };
      }
      // Shadow mode: allow but flag
    }
  }
  
  // Calculate final risk score
  const riskScore = calculateOutputRisk(
    canaryDetected,
    ngramResult.matched,
    piiDetected,
    similarityScore,
    encodedLeakResult.detected
  );
  
  // In enforce mode with high risk, block
  if (policy.mode === 'enforce' && riskScore > 0.7) {
    return {
      allowed: false,
      reason: `Output risk score too high (${riskScore.toFixed(2)})`,
      output: policy.refusal_phrases[0] || 'Request blocked by security policy.',
      score: riskScore
    };
  }
  
  // Return sanitized output
  return {
    allowed: true,
    output: sanitizedOutput,
    score: riskScore
  };
}

/**
 * Quick check if output would be blocked (without sanitization)
 */
export async function checkOutput(
  output: string,
  policy: Policy,
  canaries: string[] = []
): Promise<boolean> {
  const result = await outputGate({ output, canaries }, policy);
  return result.allowed;
}

/**
 * Batch process multiple outputs
 */
export async function outputGateBatch(
  inputs: OutputGateInput[],
  policy: Policy,
  sidecarOptions: SidecarOptions = {}
): Promise<OutputGateResult[]> {
  return Promise.all(
    inputs.map(input => outputGate(input, policy, sidecarOptions))
  );
}

/**
 * Sanitize output without full gate logic (PII masking only)
 */
export function sanitizeOutput(output: string, policy: Policy): string {
  return maskPII(output, policy.output_rules.pii);
}

