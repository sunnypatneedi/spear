import { quick, type SpearRuntime, type SpearSession } from '@spear-secure/core';

let runtime: SpearRuntime | null = null;

export function getRuntime(): SpearRuntime {
  if (!runtime) {
    const policyName = process.env.SPEAR_POLICY || 'balanced';
    const mode = (process.env.SPEAR_MODE as 'shadow' | 'enforce') || 'shadow';
    const sidecarUrl = process.env.SPEAR_SIDECAR_URL || null;
    runtime = quick(policyName, { mode, sidecarUrl });
  }
  return runtime;
}

const sessions = new Map<string, SpearSession>();

export function getSession(sessionId: string): SpearSession | undefined {
  return sessions.get(sessionId);
}

export function createSession(sessionId: string, userId?: string): SpearSession {
  const session = getRuntime().session({ sessionId, userId });
  sessions.set(sessionId, session);
  return session;
}

export function removeSession(sessionId: string): boolean {
  return sessions.delete(sessionId);
}

export function getSessionCount(): number {
  return sessions.size;
}
