/**
 * SAPPS Runtime: Main orchestrator for all security gates
 *
 * Creates a runtime instance that orchestrates:
 * - InputGate → InstructionShield → [LLM Call] → OutputGate
 * - ToolMediator for agent/tool calls
 * - Canary management across sessions
 * - CaMeL-inspired provenance tracking for data flow security
 */

import type { Policy } from './policy.js';
import { inputGate, type Message, type InputGateResult } from '../gates/input_gate.js';
import { instructionShield, type ShieldResult } from '../gates/instruction_shield.js';
import { outputGate, type OutputGateInput, type OutputGateResult, type SidecarOptions } from '../gates/output_gate.js';
import {
  toolMediator,
  createMediationContext,
  setProvenancePolicy,
  recordToolOutput,
  type ToolCall,
  type MediationContext,
  type ToolMediatorResult,
  type CapabilityViolation
} from '../gates/tool_mediator.js';
import { CanaryManager } from './canary.js';
import type { Provenance, ProvenanceLevel, ProvenancePolicy } from './provenance.js';
import { createProvenance, deriveProvenance, serializeProvenance } from './provenance.js';
import { SpearSession, type SessionOptions } from './session.js';

/**
 * Runtime configuration options
 */
export interface RuntimeOptions {
  policy: Policy;
  mode?: 'shadow' | 'enforce';
  sidecarUrl?: string | null;
  budgetMs?: number;
  enableLogging?: boolean;
}

/**
 * Pre-processing (input) context
 */
export interface PreContext {
  userId?: string;
  sessionId?: string;
  lang?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Pre-processing result
 */
export interface PreResult {
  allowed: boolean;
  reason?: string;
  messages: Message[];
  canary?: string;
  riskScore: number;
}

/**
 * Post-processing (output) input
 */
export interface PostInput {
  output: string;
  canary?: string;
  systemPrompt?: string;
}

/**
 * Post-processing result
 */
export interface PostResult {
  allowed: boolean;
  reason?: string;
  output: string;
  riskScore: number;
}

/**
 * Telemetry event (extended with CaMeL provenance data)
 */
export interface TelemetryEvent {
  timestamp: string;
  type: 'input' | 'output' | 'tool' | 'block' | 'capability_violation';
  allowed: boolean;
  reason?: string;
  score?: number;
  sessionId?: string;
  userId?: string;

  /** CaMeL provenance data */
  provenance?: {
    level?: ProvenanceLevel;
    source?: string;
  };

  /** Capability violations (for shadow mode logging) */
  capabilityViolations?: CapabilityViolation[];
}

/**
 * SAPPS Runtime class
 */
export class SpearRuntime {
  private policy: Policy;
  private mode: 'shadow' | 'enforce';
  private sidecarOptions: SidecarOptions;
  private canaryManager: CanaryManager;
  private enableLogging: boolean;
  private telemetry: TelemetryEvent[] = [];
  private toolContexts: Map<string, MediationContext> = new Map();
  
  constructor(options: RuntimeOptions) {
    this.policy = options.policy;
    this.mode = options.mode || options.policy.mode;
    this.sidecarOptions = {
      url: options.sidecarUrl || undefined,
      budgetMs: options.budgetMs || options.policy.sidecar_budget_ms,
      enabled: !!options.sidecarUrl
    };
    this.canaryManager = new CanaryManager(options.policy.canary.token_len);
    this.enableLogging = options.enableLogging !== false;
  }
  
  /**
   * Log telemetry event
   */
  private log(event: Omit<TelemetryEvent, 'timestamp'>): void {
    if (!this.enableLogging) return;
    
    const fullEvent: TelemetryEvent = {
      ...event,
      timestamp: new Date().toISOString()
    };
    
    this.telemetry.push(fullEvent);
    
    // Keep only last 1000 events
    if (this.telemetry.length > 1000) {
      this.telemetry = this.telemetry.slice(-1000);
    }
  }
  
  /**
   * Pre-process messages before LLM call
   * 
   * Runs InputGate and InstructionShield, generates canary if enabled.
   * 
   * @param messages Messages to process
   * @param context Processing context
   * @returns Pre-processing result
   */
  async pre(messages: Message[], context: PreContext = {}): Promise<PreResult> {
    const startTime = Date.now();
    
    try {
      // Step 1: Input gate (Unicode sanitization + pattern matching)
      const inputResult: InputGateResult = await inputGate(messages, this.policy);
      
      if (!inputResult.allowed) {
        this.log({
          type: 'block',
          allowed: false,
          reason: `InputGate: ${inputResult.reason}`,
          score: inputResult.score,
          sessionId: context.sessionId,
          userId: context.userId
        });
        
        // In enforce mode, block immediately
        if (this.mode === 'enforce') {
          return {
            allowed: false,
            reason: inputResult.reason,
            messages: inputResult.messages,
            riskScore: inputResult.score
          };
        }
        // Shadow mode: log but allow
      }
      
      // Step 2: Instruction shield (role hierarchy enforcement)
      const shieldResult: ShieldResult = await instructionShield(inputResult.messages, this.policy);
      
      if (!shieldResult.allowed) {
        this.log({
          type: 'block',
          allowed: false,
          reason: `InstructionShield: ${shieldResult.reason}`,
          sessionId: context.sessionId,
          userId: context.userId
        });
        
        if (this.mode === 'enforce') {
          return {
            allowed: false,
            reason: shieldResult.reason,
            messages: shieldResult.messages,
            riskScore: 1.0
          };
        }
      }
      
      // Step 3: Generate canary if enabled and session exists
      let canary: string | undefined;
      if (this.policy.canary.enabled && context.sessionId) {
        canary = this.canaryManager.generateForSession(context.sessionId);
      }
      
      // Log successful pre-processing
      this.log({
        type: 'input',
        allowed: true,
        score: inputResult.score,
        sessionId: context.sessionId,
        userId: context.userId
      });
      
      return {
        allowed: true,
        messages: shieldResult.messages,
        canary,
        riskScore: inputResult.score
      };
      
    } catch (error) {
      this.log({
        type: 'block',
        allowed: false,
        reason: `Pre-processing error: ${error instanceof Error ? error.message : String(error)}`,
        sessionId: context.sessionId,
        userId: context.userId
      });
      
      // Fail-open: allow but log error
      return {
        allowed: true,
        messages,
        riskScore: 0
      };
    }
  }
  
  /**
   * Post-process LLM output before returning
   * 
   * Runs OutputGate with canary detection, n-gram filtering, PII masking, and similarity checks.
   * 
   * @param input Output to process
   * @param context Processing context
   * @returns Post-processing result
   */
  async post(input: PostInput, context: PreContext = {}): Promise<PostResult> {
    try {
      // Get canary for session if exists
      const canaries: string[] = [];
      if (context.sessionId) {
        const sessionCanary = this.canaryManager.getCanary(context.sessionId);
        if (sessionCanary) {
          canaries.push(sessionCanary);
        }
      }
      if (input.canary) {
        canaries.push(input.canary);
      }
      
      // Run output gate
      const gateInput: OutputGateInput = {
        output: input.output,
        canaries,
        systemPrompt: input.systemPrompt
      };
      
      const result: OutputGateResult = await outputGate(
        gateInput,
        this.policy,
        this.sidecarOptions
      );
      
      // Log result
      this.log({
        type: result.allowed ? 'output' : 'block',
        allowed: result.allowed,
        reason: result.reason,
        score: result.score,
        sessionId: context.sessionId,
        userId: context.userId
      });
      
      return {
        allowed: result.allowed,
        reason: result.reason,
        output: result.output,
        riskScore: result.score
      };
      
    } catch (error) {
      this.log({
        type: 'block',
        allowed: false,
        reason: `Post-processing error: ${error instanceof Error ? error.message : String(error)}`,
        sessionId: context.sessionId,
        userId: context.userId
      });
      
      // Fail-open: allow but log error
      return {
        allowed: true,
        output: input.output,
        riskScore: 0
      };
    }
  }
  
  /**
   * Mediate a tool call with CaMeL capability enforcement
   *
   * @param toolCall Tool call to mediate (with optional provenance)
   * @param sessionId Session identifier for context tracking
   * @returns Mediation result
   */
  async mediateToolCall(toolCall: ToolCall, sessionId?: string): Promise<ToolMediatorResult> {
    const contextKey = sessionId || 'default';

    // Get or create context for session
    let context = this.toolContexts.get(contextKey);
    if (!context) {
      // Initialize with provenance policy from main policy
      context = createMediationContext(sessionId, this.policy.provenance);
      this.toolContexts.set(contextKey, context);
    } else if (!context.provenancePolicy && this.policy.provenance) {
      // Ensure provenance policy is set if added after context creation
      context = setProvenancePolicy(context, this.policy.provenance);
      this.toolContexts.set(contextKey, context);
    }

    // Mediate call
    const result = await toolMediator(toolCall, context, this.policy);

    // Update context
    this.toolContexts.set(contextKey, result.context);

    // Log with provenance info
    this.log({
      type: result.allowed ? 'tool' : 'block',
      allowed: result.allowed,
      reason: result.reason,
      sessionId,
      provenance: toolCall.selectionProvenance ? {
        level: toolCall.selectionProvenance.level,
        source: toolCall.selectionProvenance.source
      } : undefined,
      capabilityViolations: result.capabilityViolations
    });

    // Log capability violations separately for shadow mode monitoring
    if (result.capabilityViolations && result.capabilityViolations.length > 0) {
      this.log({
        type: 'capability_violation',
        allowed: result.allowed, // May be true in shadow mode
        reason: result.capabilityViolations.map(v => v.message).join('; '),
        sessionId,
        capabilityViolations: result.capabilityViolations
      });
    }

    return result;
  }

  /**
   * Record tool output for taint tracking
   *
   * Call this after a tool executes to track output provenance.
   * Enables detection of data flow from untrusted sources.
   *
   * @param toolName Name of the tool that produced output
   * @param sessionId Session identifier
   * @param outputProvenance Optional specific provenance for the output
   */
  recordToolOutput(
    toolName: string,
    sessionId?: string,
    outputProvenance?: Provenance
  ): void {
    const contextKey = sessionId || 'default';
    const context = this.toolContexts.get(contextKey);

    if (context) {
      const updated = recordToolOutput(context, toolName, outputProvenance);
      this.toolContexts.set(contextKey, updated);
    }
  }
  
  /**
   * Get telemetry events
   */
  getTelemetry(): TelemetryEvent[] {
    return [...this.telemetry];
  }
  
  /**
   * Clear telemetry
   */
  clearTelemetry(): void {
    this.telemetry = [];
  }
  
  /**
   * Get policy configuration
   */
  getPolicy(): Policy {
    return this.policy;
  }
  
  /**
   * Update policy (creates new runtime instance internally)
   */
  updatePolicy(newPolicy: Policy): void {
    this.policy = newPolicy;
    this.mode = newPolicy.mode;

    // Update provenance policy on all existing contexts
    if (newPolicy.provenance) {
      for (const [key, context] of this.toolContexts) {
        this.toolContexts.set(key, setProvenancePolicy(context, newPolicy.provenance));
      }
    }
  }

  /**
   * Check if provenance tracking is enabled
   */
  isProvenanceEnabled(): boolean {
    return this.policy.provenance?.enabled ?? false;
  }

  /**
   * Get provenance policy configuration
   */
  getProvenancePolicy(): ProvenancePolicy | undefined {
    return this.policy.provenance;
  }

  /**
   * Get all capability violations from recent telemetry
   *
   * Useful for monitoring and alerting on security issues in shadow mode.
   */
  getCapabilityViolations(): TelemetryEvent[] {
    return this.telemetry.filter(
      e => e.type === 'capability_violation' || (e.capabilityViolations && e.capabilityViolations.length > 0)
    );
  }

  /**
   * Get accumulated output provenance for a session
   *
   * Returns all provenance records from tool outputs in this session.
   * Useful for understanding data flow and taint propagation.
   */
  getSessionOutputProvenance(sessionId?: string): Provenance[] {
    const contextKey = sessionId || 'default';
    const context = this.toolContexts.get(contextKey);
    return context?.outputProvenance || [];
  }

  /**
   * Create a session-scoped security context for multi-step agent loops
   *
   * The session wraps pre/post/tools into a stateful object that:
   * - Threads a single canary across ALL steps in the loop
   * - Accumulates peak risk score across the full session
   * - Provides batch parallel tool checking for concurrent tool_calls
   *
   * @param options Session configuration (sessionId required)
   * @returns SpearSession instance for this agent loop
   *
   * @example
   * ```typescript
   * const session = spear.session({ sessionId: 'agent-001' });
   *
   * // ReAct loop
   * while (true) {
   *   const step = await session.step(messages);
   *   if (!step.allowed) break;
   *
   *   const llmResponse = await llm(step.messages);
   *   if (!llmResponse.tool_calls?.length) {
   *     const final = await session.complete(llmResponse.content);
   *     return final.output;
   *   }
   *
   *   const { allowed } = await session.tools(llmResponse.tool_calls);
   *   session.observe(await executeAll(allowed), { source: 'external' });
   *   messages = buildFollowUp(llmResponse, results);
   * }
   * ```
   */
  session(options: SessionOptions): SpearSession {
    return new SpearSession(this, options);
  }
}

/**
 * Create a SAPPS runtime instance
 * 
 * @param options Runtime configuration
 * @returns SAPPS runtime instance
 * 
 * @example
 * ```typescript
 * import { createRuntime, loadPolicy } from '@sunnypatneedi/spear';
 * 
 * const policy = loadPolicy('balanced.yaml');
 * const runtime = createRuntime({ policy, mode: 'shadow' });
 * 
 * // Pre-process
 * const preResult = await runtime.pre(messages, { sessionId: 'abc123' });
 * 
 * // Call LLM
 * const llmOutput = await callLLM(preResult.messages);
 * 
 * // Post-process
 * const postResult = await runtime.post({
 *   output: llmOutput,
 *   canary: preResult.canary
 * });
 * ```
 */
export function createRuntime(options: RuntimeOptions): SpearRuntime {
  return new SpearRuntime(options);
}

