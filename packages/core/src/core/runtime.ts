/**
 * SPEAR Runtime: Main orchestrator for all security gates
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
import { CanaryManager, containsCanary } from './canary.js';
import type { Provenance, ProvenanceLevel, ProvenancePolicy } from './provenance.js';
import { SpearSession, type SessionOptions } from './session.js';
import { PolicyRegistry } from './policy-registry.js';
import { RateLimiter, estimateTokens } from './rate-limiter.js';
import { syncPatternRegistry, mergeRegistryPatterns } from '../registry/index.js';

/**
 * Runtime configuration options
 */
export interface RuntimeOptions {
  policy: Policy | PolicyRegistry;
  mode?: 'shadow' | 'enforce';
  sidecarUrl?: string | null;
  sidecarApiKey?: string | null;
  budgetMs?: number;
  enableLogging?: boolean;
  /** Optional exporter (OpenTelemetry or any sink). Core does not depend on OTel. */
  telemetryExporter?: TelemetryExporter;
}

/**
 * Pluggable telemetry sink. Wire OpenTelemetry from the application:
 *
 * ```ts
 * import { trace } from '@opentelemetry/api';
 * const tracer = trace.getTracer('spear');
 * createRuntime({
 *   policy,
 *   telemetryExporter: {
 *     export(event) {
 *       const span = tracer.startSpan(`spear.${event.type}`);
 *       span.setAttribute('spear.allowed', event.allowed);
 *       span.setAttribute('spear.riskScore', event.score ?? 0);
 *       if (event.reason) span.setAttribute('spear.reason', event.reason);
 *       if (event.sessionId) span.setAttribute('spear.sessionId', event.sessionId);
 *       span.end();
 *     }
 *   }
 * });
 * ```
 */
export interface TelemetryExporter {
  export(event: TelemetryEvent): void;
}

/**
 * Pre-processing (input) context
 */
export interface PreContext {
  userId?: string;
  sessionId?: string;
  tenantId?: string;
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
  /** Present when the request was rejected by the rate limiter. */
  retryAfterMs?: number;
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
  type: 'input' | 'output' | 'tool' | 'block' | 'capability_violation' | 'emergent' | 'rate_limit';
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
 * SPEAR Runtime class
 */
export class SpearRuntime {
  private policy: Policy;
  private registry?: PolicyRegistry;
  private mode: 'shadow' | 'enforce';
  private sidecarOptions: SidecarOptions;
  private canaryManager: CanaryManager;
  private enableLogging: boolean;
  private telemetry: TelemetryEvent[] = [];
  private toolContexts: Map<string, { ctx: MediationContext; createdAt: number }> = new Map();
  private readonly contextTtlMs = 30 * 60 * 1000;
  private rateLimiter: RateLimiter;
  private telemetryExporter?: TelemetryExporter;

  constructor(options: RuntimeOptions) {
    if (options.policy instanceof PolicyRegistry) {
      this.registry = options.policy;
      this.policy = options.policy.getBase();
    } else {
      this.policy = options.policy;
    }
    this.mode = options.mode || this.policy.mode;
    const sidecarKey =
      options.sidecarApiKey ??
      (typeof process !== 'undefined' && process.env
        ? process.env.SPEAR_SIDECAR_KEY
        : undefined) ??
      undefined;
    this.sidecarOptions = {
      url: options.sidecarUrl || undefined,
      budgetMs: options.budgetMs || this.policy.sidecar_budget_ms,
      enabled: !!options.sidecarUrl,
      apiKey: sidecarKey
    };
    this.canaryManager = new CanaryManager(this.policy.canary.token_len);
    this.enableLogging = options.enableLogging !== false;
    this.rateLimiter = new RateLimiter(this.policy.rate_limit);
    this.telemetryExporter = options.telemetryExporter;
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

    this.telemetryExporter?.export(fullEvent);
  }

  private resolvePolicy(context: PreContext): Policy {
    if (this.registry && context.tenantId) {
      return this.registry.resolve(context.tenantId);
    }
    return this.policy;
  }

  private evictToolContexts(): void {
    const now = Date.now();
    for (const [id, entry] of this.toolContexts) {
      if (now - entry.createdAt > this.contextTtlMs) {
        this.toolContexts.delete(id);
      }
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
    const policy = this.resolvePolicy(context);

    try {
      const chars = messages.map(m => m.content).join('');
      const rate = this.rateLimiter.check(
        context.sessionId || context.userId || 'anon',
        context.userId,
        estimateTokens(chars)
      );
      if (!rate.allowed) {
        this.log({
          type: 'rate_limit',
          allowed: false,
          reason: rate.reason,
          sessionId: context.sessionId,
          userId: context.userId
        });
        if (this.mode === 'enforce') {
          return {
            allowed: false,
            reason: rate.reason,
            messages,
            riskScore: 0,
            retryAfterMs: rate.retryAfterMs
          };
        }
      }

      // Step 1: Input gate (Unicode sanitization + pattern matching)
      const inputResult: InputGateResult = await inputGate(messages, policy);

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
      const shieldResult: ShieldResult = await instructionShield(inputResult.messages, policy);

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
      if (policy.canary.enabled && context.sessionId) {
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

      if (this.mode === 'enforce') {
        return {
          allowed: false,
          reason: `Security gate internal error`,
          messages: [],
          riskScore: 1.0
        };
      }
      // Shadow mode: fail-open, log the error
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
    const policy = this.resolvePolicy(context);
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
        policy,
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

      if (this.mode === 'enforce') {
        return {
          allowed: false,
          reason: 'Security gate internal error',
          output: '',
          riskScore: 1.0
        };
      }
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
    this.evictToolContexts();

    try {
      const entry = this.toolContexts.get(contextKey);
      let context = entry?.ctx;
      if (!context) {
        context = createMediationContext(sessionId, this.policy.provenance);
        this.toolContexts.set(contextKey, { ctx: context, createdAt: Date.now() });
      } else if (!context.provenancePolicy && this.policy.provenance) {
        context = setProvenancePolicy(context, this.policy.provenance);
        this.toolContexts.set(contextKey, { ctx: context, createdAt: entry?.createdAt ?? Date.now() });
      }

      const result = await toolMediator(toolCall, context, this.policy);
      this.toolContexts.set(contextKey, { ctx: result.context, createdAt: entry?.createdAt ?? Date.now() });

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

      if (result.capabilityViolations && result.capabilityViolations.length > 0) {
        this.log({
          type: 'capability_violation',
          allowed: result.allowed,
          reason: result.capabilityViolations.map(v => v.message).join('; '),
          sessionId,
          capabilityViolations: result.capabilityViolations
        });
      }

      return result;
    } catch (error) {
      this.log({
        type: 'block',
        allowed: false,
        reason: `Tool mediation error: ${error instanceof Error ? error.message : String(error)}`,
        sessionId
      });
      if (this.mode === 'enforce') {
        return {
          allowed: false,
          reason: 'Security gate internal error',
          context: createMediationContext(sessionId, this.policy.provenance)
        };
      }
      return {
        allowed: true,
        context: createMediationContext(sessionId, this.policy.provenance)
      };
    }
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
    this.evictToolContexts();
    const entry = this.toolContexts.get(contextKey);
    let context = entry?.ctx;
    if (!context) {
      context = createMediationContext(sessionId, this.policy.provenance);
    }
    const updated = recordToolOutput(context, toolName, outputProvenance);
    this.toolContexts.set(contextKey, { ctx: updated, createdAt: entry?.createdAt ?? Date.now() });
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
   * Record a telemetry event (used by SpearSession for emergent findings).
   *
   * @param event Telemetry fields excluding timestamp
   */
  logTelemetry(event: Omit<TelemetryEvent, 'timestamp'>): void {
    this.log(event);
  }

  /**
   * Effective runtime mode (constructor override or policy.mode).
   */
  getMode(): 'shadow' | 'enforce' {
    return this.mode;
  }

  /**
   * Session canary token, if one has been generated.
   *
   * @param sessionId Session identifier
   */
  getSessionCanary(sessionId: string): string | undefined {
    return this.canaryManager.getCanary(sessionId);
  }

  /**
   * Stream-aware output gate.
   *
   * Yields chunks as they arrive. Aborts if a canary or deny-listed n-gram
   * appears mid-stream (enforce mode). After the stream ends, runs the full
   * OutputGate; if that blocks, the generator throws.
   *
   * @param chunks Async iterable of output chunks
   * @param context Session context plus optional canary / system prompt
   */
  async *postStream(
    chunks: AsyncIterable<string>,
    context: PreContext & { canary?: string; systemPrompt?: string } = {}
  ): AsyncGenerator<string> {
    const policy = this.resolvePolicy(context);
    let buffer = '';
    const canary = context.canary ?? (context.sessionId ? this.canaryManager.getCanary(context.sessionId) : undefined);

    for await (const chunk of chunks) {
      buffer += chunk;
      if (canary && containsCanary(buffer, canary)) {
        this.log({
          type: 'block',
          allowed: false,
          reason: 'Canary token detected mid-stream',
          sessionId: context.sessionId,
          userId: context.userId,
          score: 1
        });
        throw new Error('Canary token detected mid-stream');
      }
      if (this.mode === 'enforce') {
        const lower = buffer.toLowerCase();
        const hit = policy.output_rules.deny_ngrams.find(n => lower.includes(n.toLowerCase()));
        if (hit) {
          throw new Error(`Output contains deny-listed phrase: ${hit}`);
        }
      }
      yield chunk;
    }

    const final = await this.post(
      { output: buffer, canary, systemPrompt: context.systemPrompt },
      context
    );
    if (!final.allowed) {
      throw new Error(final.reason || 'Output blocked');
    }
  }

  /**
   * Fetch promoted attack patterns from the community registry and merge
   * them into the active policy. Optionally contribute a hash of a blocked
   * snippet. Never sends raw user content.
   *
   * @param attackText Optional blocked input to contribute as a hash
   */
  async syncPatternRegistry(attackText?: string): Promise<{ patterns: number }> {
    const result = await syncPatternRegistry(this.policy, attackText);
    if (result.patterns.length > 0) {
      this.policy = mergeRegistryPatterns(this.policy, result.patterns);
    }
    return { patterns: result.patterns.length };
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
      for (const [key, entry] of this.toolContexts) {
        this.toolContexts.set(key, {
          ctx: setProvenancePolicy(entry.ctx, newPolicy.provenance),
          createdAt: entry.createdAt,
        });
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
    this.evictToolContexts();
    const context = this.toolContexts.get(contextKey)?.ctx;
    return context?.outputProvenance || [];
  }

  /**
   * Create a session-scoped security context for multi-step agent loops
   *
   * The session wraps pre/post/tools into a stateful object that:
   * - Threads a single canary across ALL steps in the loop
   * - Accumulates peak risk score across the full session
   * - Provides batch parallel tool checking for concurrent tool_calls
   * - Runs emergent defense on composed step/tool/observe traces
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
 * Create a SPEAR runtime instance
 *
 * @param options Runtime configuration
 * @returns SPEAR runtime instance
 *
 * @example
 * ```typescript
 * import { createRuntime, loadPolicy } from '@spear-secure/core';
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
