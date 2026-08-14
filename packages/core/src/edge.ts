/**
 * Edge / browser entry — no `fs`, no `path`, no Python sidecar.
 *
 * ```ts
 * import { quick } from '@spear-secure/core/edge';
 * const spear = quick('balanced', { mode: 'shadow', policy: loadPolicyFromString(yaml) });
 * ```
 *
 * Named profiles like `balanced.yaml` are not read from disk here. Pass
 * `policy: loadPolicyFromString(...)` or rely on `getDefaultPolicy()`.
 */

import { createRuntime, type SpearRuntime, type RuntimeOptions } from './core/runtime.js';
import { getDefaultPolicy, type Policy } from './core/policy.js';

export { createRuntime, SpearRuntime } from './core/runtime.js';
export type {
  RuntimeOptions,
  PreContext,
  PreResult,
  PostInput,
  PostResult,
  TelemetryEvent,
  TelemetryExporter,
} from './core/runtime.js';

export { SpearSession } from './core/session.js';
export type {
  SessionOptions,
  StepResult,
  ToolBatchResult,
  SessionCompletionResult,
} from './core/session.js';

export {
  loadPolicyFromString,
  validatePolicy,
  getDefaultPolicy,
  mergePolicy,
  policySchema,
} from './core/policy.js';
export type { Policy } from './core/policy.js';

export { PolicyRegistry } from './core/policy-registry.js';
export { localSimilarity } from './core/similarity.js';
export { sanitize, decodeHtmlEntities } from './core/unicode.js';
export { generateCanary, containsCanary, CanaryManager } from './core/canary.js';
export { detectPII, maskPII, tokenizePII, detokenizePII } from './core/pii.js';
export { inputGate } from './gates/input_gate.js';
export { instructionShield } from './gates/instruction_shield.js';
export { outputGate } from './gates/output_gate.js';
export { toolMediator } from './gates/tool_mediator.js';

export const VERSION = '0.1.1';

/**
 * Create a runtime without touching the filesystem.
 *
 * @param _policyName Ignored on edge (no YAML files). Prefer `options.policy`.
 * @param options Runtime options
 */
export function quick(
  _policyName = 'balanced',
  options: Partial<{
    mode: 'shadow' | 'enforce';
    sidecarUrl: string | null;
    budgetMs: number;
    enableLogging: boolean;
    policy: Policy;
  }> = {}
): SpearRuntime {
  const policy = options.policy || getDefaultPolicy();
  return createRuntime({ ...options, policy } as RuntimeOptions);
}
