/**
 * Canary token system for provable leak detection
 * 
 * Embeds unique tokens in system prompts that should never appear in outputs.
 * If a canary is detected, it's proof of prompt exfiltration.
 */

/**
 * Generate a random canary token
 * 
 * Creates a unique, non-guessable token that can be embedded in system prompts.
 * Uses cryptographically random characters to prevent prediction.
 * 
 * @param length Length of the token (default: 16)
 * @returns Random canary token
 * 
 * @example
 * ```typescript
 * const token = generateCanary(16);
 * // Returns something like: "a3f9c2e8b1d4f7a2"
 * ```
 */
export function generateCanary(length: number = 16): string {
  const chars = 'abcdef0123456789';
  let result = '';
  
  // Use crypto.randomBytes if available (Node.js), otherwise Math.random
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    
    for (let i = 0; i < length; i++) {
      result += chars[array[i] % chars.length];
    }
  } else {
    // Fallback for environments without crypto
    for (let i = 0; i < length; i++) {
      result += chars[Math.floor(Math.random() * chars.length)];
    }
  }
  
  return result;
}

/**
 * Check if text contains a canary token
 * 
 * Performs case-insensitive substring matching to detect canary presence.
 * 
 * @param text Text to check
 * @param canary Canary token to search for
 * @returns True if canary is found
 * 
 * @example
 * ```typescript
 * const canary = "a3f9c2e8";
 * const output = "The system uses token a3f9c2e8 for...";
 * containsCanary(output, canary); // true
 * ```
 */
export function containsCanary(text: string, canary: string): boolean {
  if (!text || !canary) return false;
  
  // Case-insensitive search
  return text.toLowerCase().includes(canary.toLowerCase());
}

/**
 * Check if text contains any canary from a list
 * 
 * @param text Text to check
 * @param canaries Array of canary tokens
 * @returns True if any canary is found
 */
export function containsAnyCanary(text: string, canaries: string[]): boolean {
  if (!text || !canaries || canaries.length === 0) return false;
  
  return canaries.some(canary => containsCanary(text, canary));
}

/**
 * Embed canary token in system prompt
 * 
 * Adds a canary token to the system prompt in a way that makes it part of
 * the instructions without being obvious.
 * 
 * @param systemPrompt Original system prompt
 * @param canary Canary token to embed
 * @returns Modified system prompt with embedded canary
 * 
 * @example
 * ```typescript
 * const prompt = "You are a helpful assistant.";
 * const canary = "a3f9c2e8";
 * const modified = embedCanary(prompt, canary);
 * // "You are a helpful assistant. [Reference: a3f9c2e8]"
 * ```
 */
export function embedCanary(systemPrompt: string, canary: string): string {
  if (!systemPrompt || !canary) return systemPrompt;
  
  // Embed canary as a reference code at the end
  return `${systemPrompt}\n\n[Internal Reference: ${canary}]`;
}

/**
 * Extract canaries from system prompts
 * 
 * Finds all embedded canary tokens in a system prompt.
 * 
 * @param systemPrompt System prompt to search
 * @returns Array of found canary tokens
 */
export function extractCanaries(systemPrompt: string): string[] {
  if (!systemPrompt) return [];
  
  const pattern = /\[Internal Reference: ([a-f0-9]+)\]/gi;
  const matches = systemPrompt.matchAll(pattern);
  const canaries: string[] = [];
  
  for (const match of matches) {
    if (match[1]) {
      canaries.push(match[1]);
    }
  }
  
  return canaries;
}

/**
 * Canary token manager for session-based tracking
 *
 * Entries expire after `ttlMs` (default 30 minutes) and the map is capped
 * at `maxEntries` to prevent unbounded growth in long-running servers.
 */
export class CanaryManager {
  private canaries: Map<string, { token: string; createdAt: number }> = new Map();
  private readonly tokenLength: number;
  private readonly ttlMs: number;
  private readonly maxEntries: number;

  /**
   * @param tokenLength Canary token length
   * @param options.ttlMs Time-to-live for session canaries (default 30 minutes)
   * @param options.maxEntries Hard cap on stored sessions (default 10_000)
   */
  constructor(
    tokenLength: number = 16,
    options: { ttlMs?: number; maxEntries?: number } = {}
  ) {
    this.tokenLength = tokenLength;
    this.ttlMs = options.ttlMs ?? 30 * 60 * 1000;
    this.maxEntries = options.maxEntries ?? 10_000;
  }

  /**
   * Generate and store a canary for a session
   *
   * @param sessionId Unique session identifier
   * @returns Generated canary token
   */
  generateForSession(sessionId: string): string {
    this.evictExpired();
    const existing = this.canaries.get(sessionId);
    if (existing && Date.now() - existing.createdAt <= this.ttlMs) {
      return existing.token;
    }
    const token = generateCanary(this.tokenLength);
    this.canaries.set(sessionId, { token, createdAt: Date.now() });
    this.evictOverflow();
    return token;
  }

  /**
   * Get canary for a session
   *
   * @param sessionId Session identifier
   * @returns Canary token or undefined if not found or expired
   */
  getCanary(sessionId: string): string | undefined {
    this.evictExpired();
    return this.canaries.get(sessionId)?.token;
  }

  /**
   * Check if text contains the session's canary
   *
   * @param sessionId Session identifier
   * @param text Text to check
   * @returns True if session canary is found in text
   */
  checkSession(sessionId: string, text: string): boolean {
    const canary = this.getCanary(sessionId);
    if (!canary) return false;

    return containsCanary(text, canary);
  }

  /**
   * Remove canary for a session (cleanup)
   *
   * @param sessionId Session identifier
   */
  removeSession(sessionId: string): void {
    this.canaries.delete(sessionId);
  }

  /**
   * Get all active canaries
   *
   * @returns Array of all canary tokens
   */
  getAllCanaries(): string[] {
    this.evictExpired();
    return Array.from(this.canaries.values()).map(e => e.token);
  }

  /**
   * Number of currently stored (non-evicted) session canaries
   */
  get size(): number {
    this.evictExpired();
    return this.canaries.size;
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [id, entry] of this.canaries) {
      if (now - entry.createdAt > this.ttlMs) {
        this.canaries.delete(id);
      }
    }
  }

  private evictOverflow(): void {
    if (this.canaries.size <= this.maxEntries) return;
    const overflow = this.canaries.size - this.maxEntries;
    const oldest = [...this.canaries.entries()]
      .sort((a, b) => a[1].createdAt - b[1].createdAt)
      .slice(0, overflow);
    for (const [id] of oldest) {
      this.canaries.delete(id);
    }
  }
}

