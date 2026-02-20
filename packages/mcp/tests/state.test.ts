import { describe, it, expect, beforeEach } from 'vitest';

// Reset module state between tests by dynamically importing
let getRuntime: typeof import('../src/state.js').getRuntime;
let createSession: typeof import('../src/state.js').createSession;
let getSession: typeof import('../src/state.js').getSession;
let removeSession: typeof import('../src/state.js').removeSession;
let getSessionCount: typeof import('../src/state.js').getSessionCount;

beforeEach(async () => {
  // Re-import to get fresh module (vitest doesn't auto-reset module state)
  const mod = await import('../src/state.js');
  getRuntime = mod.getRuntime;
  createSession = mod.createSession;
  getSession = mod.getSession;
  removeSession = mod.removeSession;
  getSessionCount = mod.getSessionCount;
});

describe('state', () => {
  describe('getRuntime', () => {
    it('returns a SpearRuntime instance', () => {
      const runtime = getRuntime();
      expect(runtime).toBeDefined();
      expect(typeof runtime.pre).toBe('function');
      expect(typeof runtime.post).toBe('function');
      expect(typeof runtime.mediateToolCall).toBe('function');
    });

    it('returns the same singleton on subsequent calls', () => {
      const a = getRuntime();
      const b = getRuntime();
      expect(a).toBe(b);
    });
  });

  describe('sessions', () => {
    it('createSession returns a SpearSession', () => {
      const session = createSession('test-1');
      expect(session).toBeDefined();
      expect(session.id).toBe('test-1');
    });

    it('getSession retrieves an existing session', () => {
      createSession('test-2');
      const session = getSession('test-2');
      expect(session).toBeDefined();
      expect(session!.id).toBe('test-2');
    });

    it('getSession returns undefined for non-existent session', () => {
      expect(getSession('nonexistent')).toBeUndefined();
    });

    it('removeSession deletes a session', () => {
      createSession('test-3');
      expect(removeSession('test-3')).toBe(true);
      expect(getSession('test-3')).toBeUndefined();
    });

    it('removeSession returns false for non-existent session', () => {
      expect(removeSession('nonexistent')).toBe(false);
    });

    it('getSessionCount tracks active sessions', () => {
      const initial = getSessionCount();
      createSession('count-1');
      createSession('count-2');
      expect(getSessionCount()).toBe(initial + 2);
      removeSession('count-1');
      expect(getSessionCount()).toBe(initial + 1);
    });
  });
});
