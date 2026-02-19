/**
 * SPEAR (Secure Prompt Enforcement At Runtime)
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
import { createRuntime as createRuntimeImpl, type SPEARRuntime } from './core/runtime';
import { loadPolicy as loadPolicyImpl, type Policy } from './core/policy';
import type { RuntimeOptions } from './core/runtime';

// Core runtime
export { createRuntime, SPEARRuntime } from './core/runtime';
export type {
  RuntimeOptions,
  PreContext,
  PreResult,
  PostInput,
  PostResult,
  TelemetryEvent
} from './core/runtime';

// Policy management
export {
  loadPolicy,
  loadPolicyFromString,
  validatePolicy,
  getDefaultPolicy,
  mergePolicy,
  policySchema
} from './core/policy';
export type { Policy } from './core/policy';

// Canary system
export {
  generateCanary,
  containsCanary,
  containsAnyCanary,
  embedCanary,
  extractCanaries,
  CanaryManager
} from './core/canary';

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
} from './core/provenance';
export type {
  ProvenanceLevel,
  Provenance,
  TaggedValue,
  Capability,
  ToolCapabilityRequirement,
  ProvenancePolicy,
  CapabilityCheckResult
} from './core/provenance';

// Unicode sanitization
export {
  normalize,
  stripBidi,
  stripZeroWidth,
  sanitize,
  hasSuspiciousUnicode
} from './core/unicode';

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
} from './core/pii';
export type {
  PIIType,
  PIIMatch,
  PIIConfig,
  // Tokenization types
  TokenType,
  KnownEntities,
  TokenizationResult
} from './core/pii';

// Gates (can be used standalone)
export { inputGate, inputGateBatch, checkUserMessage } from './gates/input_gate';
export type { Message, InputGateResult } from './gates/input_gate';

export { instructionShield, canAppendMessage, getEffectivePrivilege } from './gates/instruction_shield';
export type { ShieldResult } from './gates/instruction_shield';

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
} from './gates/tool_mediator';
export type {
  ToolCall,
  MediationContext,
  ToolMediatorResult,
  TaggedArgument,
  CapabilityViolation
} from './gates/tool_mediator';

export {
  outputGate,
  outputGateBatch,
  checkOutput,
  sanitizeOutput
} from './gates/output_gate';
export type { OutputGateInput, OutputGateResult, SidecarOptions } from './gates/output_gate';

/**
 * Package version
 */
export const VERSION = '0.1.0';

/**
 * Quick start helper: Create runtime from policy name
 * 
 * @param policyName Policy file name (balanced, safe, permissive)
 * @param options Optional runtime options
 * @returns SPEAR runtime instance
 * 
 * @example
 * ```typescript
 * import { quick } from '@spear/core';
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
): SPEARRuntime {
  const policy = options.policy || loadPolicyImpl(`${policyName}.yaml`);
  return createRuntimeImpl({ ...options, policy } as RuntimeOptions);
}

