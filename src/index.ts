/**
 * SAPPS (Secure AI Prompt Protection System)
 *
 * Defense-in-depth security middleware for LLM I/O pipelines.
 *
 * Enhanced with CaMeL-inspired security features:
 * - Data provenance tracking (trusted vs untrusted sources)
 * - Capability-based security for tool mediation
 * - Control flow integrity for tool selection
 *
 * @see https://arxiv.org/abs/2503.18813 (CaMeL paper)
 * @packageDocumentation
 */

// Import for internal use (quick function)
import { createRuntime as createRuntimeImpl, type SpearRuntime } from './core/runtime.js';
import { loadPolicy as loadPolicyImpl, type Policy } from './core/policy.js';
import type { RuntimeOptions } from './core/runtime.js';

// Core runtime
export { createRuntime, SpearRuntime } from './core/runtime.js';
export type {
  RuntimeOptions,
  PreContext,
  PreResult,
  PostInput,
  PostResult,
  TelemetryEvent
} from './core/runtime.js';

// Session API — stateful context for multi-step agent loops
export { SpearSession } from './core/session.js';
export type {
  SessionOptions,
  StepResult,
  ToolBatchResult,
  SessionCompletionResult
} from './core/session.js';

// Policy management
export {
  loadPolicy,
  loadPolicyFromString,
  validatePolicy,
  getDefaultPolicy,
  mergePolicy,
  policySchema
} from './core/policy.js';
export type { Policy } from './core/policy.js';

// Canary system
export {
  generateCanary,
  containsCanary,
  containsAnyCanary,
  embedCanary,
  extractCanaries,
  CanaryManager
} from './core/canary.js';

// CaMeL-inspired Data Provenance & Capabilities
export {
  // Provenance creation
  createProvenance,
  generateProvenanceId,
  tagValue,
  tag,

  // Provenance operations
  getTrustScore,
  compareProvenance,
  minProvenance,
  deriveProvenance,
  serializeProvenance,

  // Capability checking
  hasCapability,
  valueHasCapability,
  getCapabilities,
  meetsMinimumLevel,
  canSelectTool,
  canUseAsToolArg,
  checkCapabilities,

  // Capability matrix
  buildCapabilityMatrix,
  DEFAULT_CAPABILITY_MATRIX,
  PROVENANCE_TRUST_SCORES,

  // Convenience factories
  ProvenanceSource,

  // Zod schemas for policy
  provenanceLevelSchema,
  capabilitySchema,
  toolCapabilityRequirementSchema,
  provenancePolicySchema
} from './core/provenance.js';
export type {
  ProvenanceLevel,
  Provenance,
  TaggedValue,
  Capability,
  ToolCapabilityRequirement,
  ProvenancePolicy,
  CapabilityCheckResult
} from './core/provenance.js';

// Unicode sanitization
export {
  normalize,
  stripBidi,
  stripZeroWidth,
  sanitize,
  hasSuspiciousUnicode
} from './core/unicode.js';

// PII detection and tokenization
export {
  detectPII,
  containsPII,
  maskValue,
  maskPII,
  redactPII,
  getPIIStats,
  // Tokenization for AI context (privacy-preserving)
  tokenizePII,
  detokenizePII,
  zipToRegion,
  serializeTokens,
  deserializeTokens
} from './core/pii.js';
export type {
  PIIType,
  PIIMatch,
  PIIConfig,
  // Tokenization types
  TokenType,
  KnownEntities,
  TokenizationResult
} from './core/pii.js';

// Gates (can be used standalone)
export { inputGate, inputGateBatch, checkUserMessage } from './gates/input_gate.js';
export type { Message, InputGateResult } from './gates/input_gate.js';

export { instructionShield, canAppendMessage, getEffectivePrivilege } from './gates/instruction_shield.js';
export type { ShieldResult } from './gates/instruction_shield.js';

export {
  toolMediator,
  toolMediatorBatch,
  createMediationContext,
  incrementDepth,
  decrementDepth,
  resetForNewTurn,
  setProvenancePolicy,
  recordToolOutput,
  ToolSchemaRegistry,
  globalSchemaRegistry
} from './gates/tool_mediator.js';
export type {
  ToolCall,
  MediationContext,
  ToolMediatorResult,
  TaggedArgument,
  CapabilityViolation
} from './gates/tool_mediator.js';

export {
  outputGate,
  outputGateBatch,
  checkOutput,
  sanitizeOutput
} from './gates/output_gate.js';
export type { OutputGateInput, OutputGateResult, SidecarOptions } from './gates/output_gate.js';

/**
 * Package version
 */
export const VERSION = '0.1.0';

/**
 * Quick start helper: Create runtime from policy name
 *
 * @param policyName Policy file name (balanced, safe, permissive)
 * @param options Optional runtime options
 * @returns SAPPS runtime instance
 *
 * @example
 * ```typescript
 * import { quick } from '@sunnypatneedi/spear';
 *
 * const runtime = quick('balanced', {
 *   mode: 'shadow',
 *   sidecarUrl: process.env.SPEAR_SIDECAR_URL
 * });
 * ```
 */
export function quick(
  policyName = 'balanced',
  options: Partial<{
    mode: 'shadow' | 'enforce';
    sidecarUrl: string | null;
    budgetMs: number;
    enableLogging: boolean;
    policy: Policy;
  }> = {}
): SpearRuntime {
  const policy = options.policy || loadPolicyImpl(`${policyName}.yaml`);
  return createRuntimeImpl({ ...options, policy } as RuntimeOptions);
}
