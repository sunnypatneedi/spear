/**
 * Fail-closed enforce mode (#18). Isolated so the inputGate mock cannot
 * leak into other test files.
 */

import { describe, it, expect, vi } from 'vitest';

vi.mock('../src/gates/input_gate.js', async () => {
  const actual = await vi.importActual<typeof import('../src/gates/input_gate.js')>(
    '../src/gates/input_gate.js'
  );
  return {
    ...actual,
    inputGate: vi.fn().mockRejectedValue(new Error('simulated gate crash')),
  };
});

import { createRuntime } from '../src/core/runtime.js';
import { getDefaultPolicy } from '../src/core/policy.js';

describe('#18 fail-closed on internal error', () => {
  it('blocks in enforce mode when a gate throws', async () => {
    const policy = getDefaultPolicy();
    const spear = createRuntime({ policy, mode: 'enforce', enableLogging: true });
    const result = await spear.pre([{ role: 'user', content: 'hi' }]);
    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/internal error/i);
    expect(spear.getTelemetry().some(e => e.type === 'block')).toBe(true);
  });

  it('allows in shadow mode when a gate throws', async () => {
    const policy = getDefaultPolicy();
    const spear = createRuntime({ policy, mode: 'shadow', enableLogging: true });
    const result = await spear.pre([{ role: 'user', content: 'hi' }]);
    expect(result.allowed).toBe(true);
    expect(spear.getTelemetry().some(e => e.type === 'block')).toBe(true);
  });
});
