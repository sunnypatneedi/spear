/**
 * In-memory sliding-window rate limiter and token-budget tracker.
 *
 * Used at the top of `SpearRuntime.pre()` to stop budget-exhaustion /
 * noisy-neighbor abuse. Maps are pruned so they cannot grow without bound.
 */

export interface RateLimitConfig {
  enabled: boolean;
  requests_per_window: number;
  window_seconds: number;
  token_budget: number;
  per_user: {
    requests_per_window: number;
    window_seconds: number;
  };
}

export interface RateLimitDecision {
  allowed: boolean;
  reason?: string;
  retryAfterMs?: number;
}

interface WindowState {
  timestamps: number[];
  tokens: number;
}

/**
 * Sliding-window counter keyed by session and user.
 */
export class RateLimiter {
  private sessions = new Map<string, WindowState>();
  private users = new Map<string, WindowState>();
  private checks = 0;

  /**
   * @param config Rate-limit policy section
   */
  constructor(private readonly config: RateLimitConfig) {}

  /**
   * Record a request and decide whether it is within budget.
   *
   * @param key Session id (fallback 'anon')
   * @param userId Optional user id for the per-user window
   * @param estimatedTokens Rough token count (chars/4)
   */
  check(key: string, userId: string | undefined, estimatedTokens: number): RateLimitDecision {
    if (!this.config.enabled) {
      return { allowed: true };
    }

    this.checks++;
    if (this.checks % 32 === 0) this.prune();

    const now = Date.now();
    const sessionWindow = this.config.window_seconds * 1000;
    const session = this.touch(this.sessions, key, now, sessionWindow);

    if (session.timestamps.length > this.config.requests_per_window) {
      const retryAfterMs = Math.max(0, session.timestamps[0] + sessionWindow - now);
      return { allowed: false, reason: 'rate_limit', retryAfterMs };
    }

    if (session.tokens > this.config.token_budget) {
      const retryAfterMs = Math.max(0, session.timestamps[0] + sessionWindow - now);
      return { allowed: false, reason: 'token_budget', retryAfterMs };
    }

    if (userId) {
      const userWindow = this.config.per_user.window_seconds * 1000;
      const user = this.touch(this.users, userId, now, userWindow);
      if (user.timestamps.length > this.config.per_user.requests_per_window) {
        const retryAfterMs = Math.max(0, user.timestamps[0] + userWindow - now);
        return { allowed: false, reason: 'rate_limit', retryAfterMs };
      }
    }

    session.tokens += estimatedTokens;
    return { allowed: true };
  }

  /** Drop empty windows to bound memory. */
  prune(): void {
    const now = Date.now();
    const sessionWindow = this.config.window_seconds * 1000;
    const userWindow = this.config.per_user.window_seconds * 1000;
    for (const [k, state] of this.sessions) {
      state.timestamps = state.timestamps.filter(t => now - t <= sessionWindow);
      if (state.timestamps.length === 0) this.sessions.delete(k);
    }
    for (const [k, state] of this.users) {
      state.timestamps = state.timestamps.filter(t => now - t <= userWindow);
      if (state.timestamps.length === 0) this.users.delete(k);
    }
  }

  private touch(
    map: Map<string, WindowState>,
    key: string,
    now: number,
    windowMs: number
  ): WindowState {
    let state = map.get(key);
    if (!state) {
      state = { timestamps: [], tokens: 0 };
      map.set(key, state);
    }
    state.timestamps = state.timestamps.filter(t => now - t <= windowMs);
    if (state.timestamps.length === 0) state.tokens = 0;
    state.timestamps.push(now);
    return state;
  }
}

/**
 * Estimate tokens from character count (chars/4).
 *
 * @param text Input text
 */
export function estimateTokens(text: string): number {
  if (!text) return 0;
  return Math.ceil(text.length / 4);
}
