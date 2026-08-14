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
import { createRuntime as createRuntimeImpl, type SpearRuntime } from './core/runtime.js';
import { loadPolicy as loadPolicyImpl } from './core/policy-load.js';
import type { RuntimeOptions } from './core/runtime.js';

// Core runtime
export { createRuntime, SpearRuntime } from './core/runtime.js';
export type {
  RuntimeOptions,
  PreContext,
  PreResult,
  PostInput,
  PostResult,
  TelemetryEvent,
  TelemetryExporter
} from './core/runtime.js';

// Session API — stateful context for multi-step agent loops
export { SpearSession } from './core/session.js';
export type {
  SessionOptions,
  StepResult,
  ToolBatchResult,
  SessionCompletionResult
} from './core/session.js';

// Emergent agent defense — session-level composition checks
export {
  EmergentTracker,
  createEmergentTracker,
  classifyToolRole,
  normalizeToolName,
  toolNameMatches,
  sourceToProvenanceLevel,
  containsSensitiveContent,
  containsGoalHijack,
  DEFAULT_DANGEROUS_SEQUENCES,
  emergentPolicySchema,
} from './core/emergent.js';
export type {
  ToolRole,
  EmergentFindingClass,
  EmergentSeverity,
  EmergentFinding,
  EmergentEvent,
  EmergentInspectResult,
  EmergentPolicy,
  DangerousSequence,
} from './core/emergent.js';

// Policy management
export {
  loadPolicyFromString,
  validatePolicy,
  getDefaultPolicy,
  mergePolicy,
  policySchema
} from './core/policy.js';
export { loadPolicy } from './core/policy-load.js';
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
  decodeHtmlEntities,
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

export { PolicyRegistry } from './core/policy-registry.js';
export { localSimilarity, tfidfCosine, ngramJaccard } from './core/similarity.js';
export { RateLimiter, estimateTokens } from './core/rate-limiter.js';
export type { RateLimitConfig, RateLimitDecision } from './core/rate-limiter.js';
export {
  hashAttackPattern,
  normalizeForRegistry,
  syncPatternRegistry,
  mergeRegistryPatterns,
} from './registry/index.js';
export { SpearCallbackHandler } from './adapters/langchain.js';
export type { SpearCallbackOptions } from './adapters/langchain.js';
export { withSpear } from './adapters/vercel-ai.js';
export type { WithSpearOptions, SpearHandlerContext } from './adapters/vercel-ai.js';
export { base64Decode } from './core/platform.js';

/**
 * Package version
 */
export const VERSION = '0.1.1';

/**
 * Quick start helper: Create runtime from policy name
 *
 * @param policyName Policy file name (balanced, safe, permissive)
 * @param options Optional runtime options
 * @returns SPEAR runtime instance
 *
 * @example
 * ```typescript
 * import { quick } from '@spear-secure/core';
 *
 * const runtime = quick('balanced', {
 *   mode: 'shadow',
 *   sidecarUrl: process.env.SPEAR_SIDECAR_URL
 * });
 * ```
 */
export function quick(
  policyName = 'balanced',
  options: Partial<RuntimeOptions> = {}
): SpearRuntime {
  const policy = options.policy || loadPolicyImpl(`${policyName}.yaml`);
  return createRuntimeImpl({ ...options, policy });
}
