/**
 * ToolMediator: RBAC, schema validation, and capability enforcement for tool calls
 *
 * Mediates all tool invocations with:
 * 1. RBAC allow/deny lists from policy
 * 2. Call-depth tracking to prevent recursion attacks
 * 3. Call-count limits per session
 * 4. Optional schema validation for tool arguments
 * 5. CaMeL-inspired capability enforcement (provenance-based security)
 *
 * CaMeL Security Model:
 * - Tool selection must come from trusted sources (user/system)
 * - Tool arguments are checked against capability requirements
 * - Untrusted data cannot influence tool selection (prevents indirect injection)
 */

import type { Policy } from '../core/policy.js';
import { z, type ZodSchema } from 'zod';
import type {
  Provenance,
  ProvenanceLevel,
  Capability,
  ToolCapabilityRequirement,
  ProvenancePolicy,
  TaggedValue
} from '../core/provenance.js';
import {
  hasCapability,
  canSelectTool,
  canUseAsToolArg,
  meetsMinimumLevel,
  createProvenance,
  deriveProvenance,
  DEFAULT_CAPABILITY_MATRIX,
  buildCapabilityMatrix
} from '../core/provenance.js';

/**
 * Tool argument with provenance tracking
 */
export interface TaggedArgument {
  value: unknown;
  provenance: Provenance;
}

/**
 * Tool call structure with CaMeL provenance support
 */
export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
  id?: string;

  /**
   * Provenance of the tool selection decision
   * Used to prevent indirect prompt injection
   */
  selectionProvenance?: Provenance;

  /**
   * Provenance for each argument (optional, for fine-grained control)
   * Keys match argument names
   */
  argumentProvenance?: Record<string, Provenance>;
}

/**
 * Tool mediation context (session tracking with provenance)
 */
export interface MediationContext {
  sessionId?: string;
  callCount: number;
  callDepth: number;
  history: ToolCall[];

  /**
   * Provenance policy for capability enforcement
   */
  provenancePolicy?: ProvenancePolicy;

  /**
   * Accumulated provenance from tool outputs (for taint tracking)
   */
  outputProvenance?: Provenance[];
}

/**
 * Capability violation details
 */
export interface CapabilityViolation {
  type: 'tool_selection' | 'argument' | 'minimum_level';
  capability?: Capability;
  argumentName?: string;
  provenanceLevel: ProvenanceLevel;
  requiredLevel?: ProvenanceLevel;
  message: string;
}

/**
 * Tool mediation result with provenance info
 */
export interface ToolMediatorResult {
  allowed: boolean;
  reason?: string;
  context: MediationContext;

  /**
   * CaMeL capability violations (if any)
   */
  capabilityViolations?: CapabilityViolation[];

  /**
   * Was this blocked due to provenance/capability issues?
   */
  provenanceBlocked?: boolean;
}

/**
 * Tool schema registry for argument validation
 */
export class ToolSchemaRegistry {
  private schemas: Map<string, ZodSchema> = new Map();
  
  /**
   * Register a schema for a tool
   */
  register(toolName: string, schema: ZodSchema): void {
    this.schemas.set(toolName, schema);
  }
  
  /**
   * Get schema for a tool
   */
  get(toolName: string): ZodSchema | undefined {
    return this.schemas.get(toolName);
  }
  
  /**
   * Validate tool arguments against registered schema
   */
  validate(toolName: string, args: Record<string, unknown>): { valid: boolean; error?: string } {
    const schema = this.schemas.get(toolName);
    if (!schema) {
      // No schema registered = allow (permissive by default)
      return { valid: true };
    }
    
    try {
      schema.parse(args);
      return { valid: true };
    } catch (error) {
      if (error instanceof z.ZodError) {
        return {
          valid: false,
          error: error.errors.map(e => e.message).join('; ')
        };
      }
      return {
        valid: false,
        error: String(error)
      };
    }
  }
}

/**
 * Global schema registry instance
 */
export const globalSchemaRegistry = new ToolSchemaRegistry();

/**
 * Check if tool is allowed by RBAC policy
 */
function checkRBAC(toolName: string, policy: Policy): { allowed: boolean; reason?: string } {
  const { allow, deny } = policy.tools.rbac;
  
  // If deny list has entries and tool is in deny list, block
  if (deny.length > 0 && deny.includes(toolName)) {
    return {
      allowed: false,
      reason: `Tool '${toolName}' is in deny list`
    };
  }
  
  // If allow list has entries, only allow listed tools
  if (allow.length > 0 && !allow.includes(toolName)) {
    return {
      allowed: false,
      reason: `Tool '${toolName}' not in allow list`
    };
  }
  
  // Otherwise allow
  return { allowed: true };
}

/**
 * Check if call count exceeds limit
 */
function checkCallCount(context: MediationContext, policy: Policy): { allowed: boolean; reason?: string } {
  if (context.callCount >= policy.tools.rbac.max_calls) {
    return {
      allowed: false,
      reason: `Max tool calls (${policy.tools.rbac.max_calls}) exceeded`
    };
  }
  
  return { allowed: true };
}

/**
 * Check if call depth exceeds limit
 */
function checkCallDepth(context: MediationContext, policy: Policy): { allowed: boolean; reason?: string } {
  if (context.callDepth >= policy.tools.rbac.max_depth) {
    return {
      allowed: false,
      reason: `Max call depth (${policy.tools.rbac.max_depth}) exceeded`
    };
  }
  
  return { allowed: true };
}

/**
 * Check for suspicious recursion patterns
 */
function checkRecursion(toolCall: ToolCall, context: MediationContext): { allowed: boolean; reason?: string } {
  // Check if same tool called multiple times recently
  const recentSame = context.history
    .slice(-3)  // Last 3 calls
    .filter(call => call.name === toolCall.name);

  if (recentSame.length >= 3) {
    return {
      allowed: false,
      reason: `Suspicious recursion: tool '${toolCall.name}' called 3+ times consecutively`
    };
  }

  return { allowed: true };
}

// ============================================================================
// CAMEL-INSPIRED CAPABILITY ENFORCEMENT
// ============================================================================

/**
 * Check if tool selection provenance meets requirements
 *
 * This is the core CaMeL security check: preventing untrusted data
 * from influencing which tool gets called.
 */
function checkToolSelectionProvenance(
  toolCall: ToolCall,
  context: MediationContext
): { allowed: boolean; violation?: CapabilityViolation } {
  // Skip if provenance tracking not enabled
  if (!context.provenancePolicy?.enabled) {
    return { allowed: true };
  }

  // If no selection provenance provided, allow in shadow mode
  if (!toolCall.selectionProvenance) {
    if (context.provenancePolicy.mode === 'enforce') {
      return {
        allowed: false,
        violation: {
          type: 'tool_selection',
          provenanceLevel: 'untrusted',
          message: 'Tool selection provenance required but not provided'
        }
      };
    }
    return { allowed: true };
  }

  // Check if provenance allows tool selection
  const selectionCheck = canSelectTool(toolCall.selectionProvenance);
  if (!selectionCheck.allowed) {
    return {
      allowed: false,
      violation: {
        type: 'tool_selection',
        capability: 'tool_select',
        provenanceLevel: toolCall.selectionProvenance.level,
        message: selectionCheck.reason || 'Tool selection not allowed for this provenance level'
      }
    };
  }

  // Check minimum level requirement from policy
  const minLevel = context.provenancePolicy.defaultToolSelectionMinLevel || 'user';
  if (!meetsMinimumLevel(toolCall.selectionProvenance.level, minLevel)) {
    return {
      allowed: false,
      violation: {
        type: 'minimum_level',
        provenanceLevel: toolCall.selectionProvenance.level,
        requiredLevel: minLevel,
        message: `Tool selection requires minimum provenance level '${minLevel}', got '${toolCall.selectionProvenance.level}'`
      }
    };
  }

  return { allowed: true };
}

/**
 * Check if tool arguments meet capability requirements
 */
function checkArgumentProvenance(
  toolCall: ToolCall,
  context: MediationContext
): { allowed: boolean; violations: CapabilityViolation[] } {
  const violations: CapabilityViolation[] = [];

  // Skip if provenance tracking not enabled
  if (!context.provenancePolicy?.enabled) {
    return { allowed: true, violations: [] };
  }

  // Find tool-specific requirements
  const toolReq = context.provenancePolicy.toolRequirements?.find(
    r => r.tool === toolCall.name || new RegExp(r.tool).test(toolCall.name)
  );

  // If no specific requirements, allow
  if (!toolReq) {
    return { allowed: true, violations: [] };
  }

  // Check each argument with defined requirements
  for (const [argName, requirements] of Object.entries(toolReq.arguments) as [string, { required: Capability[]; description?: string }][]) {
    const argProvenance = toolCall.argumentProvenance?.[argName];

    // If provenance not provided for required argument
    if (!argProvenance) {
      if (context.provenancePolicy.mode === 'enforce') {
        violations.push({
          type: 'argument',
          argumentName: argName,
          provenanceLevel: 'untrusted',
          message: `Argument '${argName}' requires provenance but none provided`
        });
      }
      continue;
    }

    // Check each required capability
    for (const cap of requirements.required) {
      if (!hasCapability(argProvenance.level, cap)) {
        violations.push({
          type: 'argument',
          capability: cap,
          argumentName: argName,
          provenanceLevel: argProvenance.level,
          message: `Argument '${argName}' requires capability '${cap}', but provenance '${argProvenance.level}' lacks it`
        });
      }
    }
  }

  return {
    allowed: violations.length === 0,
    violations
  };
}

/**
 * Check if tool selection is influenced by previous tool outputs (taint tracking)
 *
 * This prevents indirect prompt injection where:
 * 1. Tool A returns malicious data
 * 2. LLM uses that data to decide to call Tool B
 * 3. Tool B performs a dangerous action
 */
function checkToolChainTaint(
  toolCall: ToolCall,
  context: MediationContext
): { allowed: boolean; violation?: CapabilityViolation } {
  // Skip if tool chain blocking not enabled
  if (!context.provenancePolicy?.blockToolChainInfluence) {
    return { allowed: true };
  }

  // Skip if no previous tool outputs to check
  if (!context.outputProvenance || context.outputProvenance.length === 0) {
    return { allowed: true };
  }

  // If selection provenance derives from tool output, this is suspicious
  if (toolCall.selectionProvenance) {
    const selectionLevel = toolCall.selectionProvenance.level;

    // If tool selection comes from 'tool' or lower trust, flag it
    if (selectionLevel === 'tool' || selectionLevel === 'external' || selectionLevel === 'untrusted') {
      return {
        allowed: false,
        violation: {
          type: 'tool_selection',
          capability: 'tool_select',
          provenanceLevel: selectionLevel,
          message: `Tool selection influenced by ${selectionLevel} data (potential indirect injection). ` +
                   `Previous tool outputs should not influence which tools are called.`
        }
      };
    }

    // Check if selection provenance has tool output in its parent chain
    if (toolCall.selectionProvenance.parents) {
      const toolOutputIds = context.outputProvenance.map(p => p.id);
      const hasToolParent = toolCall.selectionProvenance.parents.some(
        parentId => toolOutputIds.includes(parentId)
      );

      if (hasToolParent) {
        return {
          allowed: false,
          violation: {
            type: 'tool_selection',
            capability: 'tool_select',
            provenanceLevel: toolCall.selectionProvenance.level,
            message: `Tool selection derived from previous tool output (taint detected). ` +
                     `This pattern is commonly used in indirect prompt injection attacks.`
          }
        };
      }
    }
  }

  return { allowed: true };
}

/**
 * Check all CaMeL-style capability requirements
 */
function checkCapabilities(
  toolCall: ToolCall,
  context: MediationContext
): { allowed: boolean; violations: CapabilityViolation[]; reason?: string } {
  const violations: CapabilityViolation[] = [];

  // Check tool chain taint (NEW - prevents indirect injection)
  const taintCheck = checkToolChainTaint(toolCall, context);
  if (!taintCheck.allowed && taintCheck.violation) {
    violations.push(taintCheck.violation);
  }

  // Check tool selection provenance
  const selectionCheck = checkToolSelectionProvenance(toolCall, context);
  if (!selectionCheck.allowed && selectionCheck.violation) {
    violations.push(selectionCheck.violation);
  }

  // Check argument provenance
  const argCheck = checkArgumentProvenance(toolCall, context);
  violations.push(...argCheck.violations);

  if (violations.length === 0) {
    return { allowed: true, violations: [] };
  }

  // Determine overall result based on mode
  const enforceMode = context.provenancePolicy?.mode === 'enforce';
  const allowed = !enforceMode;

  return {
    allowed,
    violations,
    reason: enforceMode
      ? `Capability violations: ${violations.map(v => v.message).join('; ')}`
      : undefined
  };
}

/**
 * Tool mediator gate: Validate and authorize tool calls
 *
 * Enhanced with CaMeL-inspired capability enforcement:
 * - Checks tool selection provenance (prevents indirect injection)
 * - Validates argument capabilities against requirements
 * - Supports shadow mode for gradual rollout
 *
 * @param toolCall Tool call to validate
 * @param context Mediation context with session state
 * @param policy SPEAR policy configuration
 * @param schemaRegistry Optional schema registry for validation
 * @returns Mediation result
 *
 * @example
 * ```typescript
 * const call = {
 *   name: 'search',
 *   arguments: { query: 'hello' },
 *   selectionProvenance: createProvenance('user', 'chat_input')
 * };
 * const context = { callCount: 0, callDepth: 0, history: [] };
 * const result = await toolMediator(call, context, policy);
 * // result.allowed === true (search in allow list + valid provenance)
 * ```
 */
export async function toolMediator(
  toolCall: ToolCall,
  context: MediationContext,
  policy: Policy,
  schemaRegistry: ToolSchemaRegistry = globalSchemaRegistry
): Promise<ToolMediatorResult> {
  // Step 1: RBAC check
  const rbacCheck = checkRBAC(toolCall.name, policy);
  if (!rbacCheck.allowed) {
    return {
      allowed: false,
      reason: rbacCheck.reason,
      context
    };
  }

  // Step 2: Call count check
  const countCheck = checkCallCount(context, policy);
  if (!countCheck.allowed) {
    return {
      allowed: false,
      reason: countCheck.reason,
      context
    };
  }

  // Step 3: Call depth check
  const depthCheck = checkCallDepth(context, policy);
  if (!depthCheck.allowed) {
    return {
      allowed: false,
      reason: depthCheck.reason,
      context
    };
  }

  // Step 4: Recursion check
  const recursionCheck = checkRecursion(toolCall, context);
  if (!recursionCheck.allowed) {
    return {
      allowed: false,
      reason: recursionCheck.reason,
      context
    };
  }

  // Step 5: Schema validation
  const schemaCheck = schemaRegistry.validate(toolCall.name, toolCall.arguments);
  if (!schemaCheck.valid) {
    return {
      allowed: false,
      reason: `Schema validation failed: ${schemaCheck.error}`,
      context
    };
  }

  // Step 6: CaMeL capability enforcement (NEW)
  const capabilityCheck = checkCapabilities(toolCall, context);
  if (!capabilityCheck.allowed) {
    return {
      allowed: false,
      reason: capabilityCheck.reason,
      context,
      capabilityViolations: capabilityCheck.violations,
      provenanceBlocked: true
    };
  }

  // Update context
  const updatedContext: MediationContext = {
    ...context,
    callCount: context.callCount + 1,
    history: [...context.history, toolCall]
  };

  // Include any violations for shadow mode logging
  const result: ToolMediatorResult = {
    allowed: true,
    context: updatedContext
  };

  // In shadow mode, include violations for logging but still allow
  if (capabilityCheck.violations.length > 0) {
    result.capabilityViolations = capabilityCheck.violations;
  }

  return result;
}

/**
 * Batch mediate multiple tool calls
 */
export async function toolMediatorBatch(
  toolCalls: ToolCall[],
  initialContext: MediationContext,
  policy: Policy,
  schemaRegistry: ToolSchemaRegistry = globalSchemaRegistry
): Promise<ToolMediatorResult[]> {
  const results: ToolMediatorResult[] = [];
  let context = initialContext;
  
  for (const call of toolCalls) {
    const result = await toolMediator(call, context, policy, schemaRegistry);
    results.push(result);
    
    // Update context for next call
    context = result.context;
    
    // If any call is blocked, stop processing
    if (!result.allowed) {
      break;
    }
  }
  
  return results;
}

/**
 * Create a new mediation context for a session
 *
 * @param sessionId Optional session identifier
 * @param provenancePolicy Optional provenance policy for CaMeL enforcement
 */
export function createMediationContext(
  sessionId?: string,
  provenancePolicy?: ProvenancePolicy
): MediationContext {
  return {
    sessionId,
    callCount: 0,
    callDepth: 0,
    history: [],
    provenancePolicy,
    outputProvenance: []
  };
}

/**
 * Increment call depth (when entering nested tool execution)
 */
export function incrementDepth(context: MediationContext): MediationContext {
  return {
    ...context,
    callDepth: context.callDepth + 1
  };
}

/**
 * Decrement call depth (when exiting nested tool execution)
 */
export function decrementDepth(context: MediationContext): MediationContext {
  return {
    ...context,
    callDepth: Math.max(0, context.callDepth - 1)
  };
}

/**
 * Reset context for a new turn (keeps history but resets counts)
 */
export function resetForNewTurn(context: MediationContext): MediationContext {
  return {
    ...context,
    callCount: 0,
    callDepth: 0
  };
}

/**
 * Update provenance policy on context
 */
export function setProvenancePolicy(
  context: MediationContext,
  policy: ProvenancePolicy
): MediationContext {
  return {
    ...context,
    provenancePolicy: policy
  };
}

/**
 * Record tool output provenance (for taint tracking)
 */
export function recordToolOutput(
  context: MediationContext,
  toolName: string,
  provenance?: Provenance
): MediationContext {
  const outputProv = provenance || createProvenance('tool', `tool_${toolName}`);
  return {
    ...context,
    outputProvenance: [...(context.outputProvenance || []), outputProv]
  };
}

