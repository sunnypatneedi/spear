/**
 * SpearSession: session-scoped security context for multi-step agent loops
 *
 * Wraps SpearRuntime with a stateful per-agent-loop context that:
 * - Threads a single canary across ALL steps (not regenerated per call)
 * - Accumulates peak risk score across the full loop
 * - Provides batch parallel tool checking for agents that fire multiple
 *   tool calls simultaneously
 * - Exposes an observe() hook to annotate tool results with provenance source
 * - Runs emergent agent defense across the composed step/tool/observe trace
 *
 * Designed for ReAct loops, LangChain agents, and any multi-step pipeline:
 *
 *   const session = spear.session({ sessionId: 'agent-001' });
 *
 *   // Step 1 — pre-gate user message + injected context
 *   const s1 = await session.step(messages);
 *   if (!s1.allowed) return blocked();
 *
 *   // LLM call → tool_calls[] arrive in parallel
 *   const { allowed } = await session.tools([searchCall, readCall]);
 *   const results = await Promise.all(allowed.map(executeToolCall));
 *
 *   // Tag results with provenance before next step
 *   session.observe(results, { source: 'external' });
 *
 *   // Step 2 — pre-gate follow-up messages
 *   const s2 = await session.step(followUpMessages);
 *
 *   // Final output gate with session-accumulated canary
 *   const final = await session.complete(llmFinalOutput);
 */

import type { SpearRuntime } from './runtime.js';
import type { Message } from '../gates/input_gate.js';
import type { ToolCall, ToolMediatorResult, MediationContext } from '../gates/tool_mediator.js';
import { toolMediator, createMediationContext } from '../gates/tool_mediator.js';
import { createProvenance } from './provenance.js';
import {
  createEmergentTracker,
  sourceToProvenanceLevel,
  type EmergentInspectResult,
  type EmergentTracker,
} from './emergent.js';

/**
 * Result from a single agent step (session.step())
 */
export interface StepResult {
  allowed: boolean;
  reason?: string;
  /** Sanitized messages — pass these to your LLM, not the originals */
  messages: Message[];
  /** Which step number this was (1-indexed) */
  stepIndex: number;
  riskScore: number;
  /** Emergent-defense inspection for this step (compositions across the session) */
  emergent?: EmergentInspectResult;
}

/**
 * Result from a batch parallel tool check (session.tools())
 */
export interface ToolBatchResult {
  /** Tool calls that passed mediation — safe to execute */
  allowed: ToolMediatorResult[];
  /** Tool calls that were blocked */
  blocked: ToolMediatorResult[];
  /** Total number of calls submitted (= allowed.length + blocked.length) */
  total: number;
  /** Emergent-defense inspection after this batch */
  emergent?: EmergentInspectResult;
}

/**
 * Result from session.complete() — the final output gate
 */
export interface SessionCompletionResult {
  allowed: boolean;
  reason?: string;
  /** Post-gated (PII-masked, canary-checked) output */
  output: string;
  /** Peak risk score accumulated across all steps in this session */
  sessionRiskScore: number;
  /** Total number of steps executed */
  stepCount: number;
  /** Emergent-defense inspection at session close */
  emergent?: EmergentInspectResult;
}

/**
 * Options for creating a SpearSession
 */
export interface SessionOptions {
  sessionId: string;
  userId?: string;
}

/**
 * SpearSession: stateful per-agent-loop security context
 *
 * Created via `runtime.session(options)`. Never instantiate directly.
 */
export class SpearSession {
  private runtime: SpearRuntime;
  private sessionId: string;
  private userId?: string;
  private stepIndex = 0;
  private peakRisk = 0;
  private mediationContext: MediationContext;
  private tracker: EmergentTracker;

  constructor(runtime: SpearRuntime, options: SessionOptions) {
    this.runtime = runtime;
    this.sessionId = options.sessionId;
    this.userId = options.userId;
    const policy = runtime.getPolicy();
    this.mediationContext = createMediationContext(options.sessionId, policy.provenance);
    this.tracker = createEmergentTracker(policy.emergent, runtime.getMode());
  }

  /**
   * Pre-gate a single agent step
   *
   * Runs InputGate + InstructionShield on the messages, embeds the
   * session canary (same canary persists across all steps — pass it
   * to your system prompt and it will be detected if leaked in any step's
   * output). Also records the step for emergent composition checks.
   *
   * @param messages User message + any context injected into the conversation
   * @returns StepResult with sanitized messages safe to send to LLM
   */
  async step(messages: Message[]): Promise<StepResult> {
    const result = await this.runtime.pre(messages, {
      sessionId: this.sessionId,
      userId: this.userId,
    });

    this.stepIndex++;
    this.peakRisk = Math.max(this.peakRisk, result.riskScore);

    const canary = this.runtime.getSessionCanary(this.sessionId);
    if (canary) {
      this.tracker.setCanary(canary);
    }

    const emergent = this.tracker.recordStep(messages, result.riskScore);
    this.logEmergent(emergent);

    const allowed = result.allowed && emergent.allowed;
    return {
      allowed,
      reason: allowed ? undefined : (result.reason ?? emergent.reason),
      messages: result.messages,
      stepIndex: this.stepIndex,
      riskScore: Math.max(result.riskScore, emergent.sessionRisk),
      emergent,
    };
  }

  /**
   * Batch-check parallel tool calls
   *
   * Agents commonly receive multiple tool_calls from the LLM simultaneously.
   * This method checks all of them in one call, returning allowed and blocked
   * subsets. Note: mediation stops at the first blocked call; any calls after
   * the first block are auto-classified as blocked. Emergent defense then
   * blocks compositions (e.g. read_file then send_email) that RBAC alone
   * would allow.
   *
   * @param toolCalls Array of tool calls (e.g. from response.choices[0].message.tool_calls)
   * @returns ToolBatchResult with allowed and blocked subsets
   *
   * @example
   * ```typescript
   * const { allowed, blocked } = await session.tools([
   *   { name: 'web_search', arguments: { query } },
   *   { name: 'read_file', arguments: { path } },
   * ]);
   *
   * if (blocked.length > 0) console.warn('Some tools were blocked:', blocked);
   * const results = await Promise.all(allowed.map(r => executeTool(r)));
   * ```
   */
  async tools(toolCalls: ToolCall[]): Promise<ToolBatchResult> {
    if (toolCalls.length === 0) {
      return { allowed: [], blocked: [], total: 0, emergent: this.tracker.inspect() };
    }

    const policy = this.runtime.getPolicy();
    const allowed: ToolMediatorResult[] = [];
    const blocked: ToolMediatorResult[] = [];
    let emergent = this.tracker.inspect();

    for (let i = 0; i < toolCalls.length; i++) {
      const call = toolCalls[i];
      const mediated = await toolMediator(call, this.mediationContext, policy);
      this.mediationContext = mediated.context;

      if (!mediated.allowed) {
        blocked.push(mediated);
        this.blockRemaining(toolCalls, i + 1, blocked, 'Batch stopped at earlier blocked call');
        break;
      }

      emergent = this.tracker.recordTool(call);
      this.logEmergent(emergent);

      if (!emergent.allowed) {
        blocked.push({
          allowed: false,
          reason: emergent.reason,
          context: this.mediationContext,
        });
        this.blockRemaining(toolCalls, i + 1, blocked, 'Batch stopped at earlier blocked call');
        break;
      }

      allowed.push(mediated);
      this.runtime.recordToolOutput(call.name, this.sessionId);
    }

    return { allowed, blocked, total: toolCalls.length, emergent };
  }

  /**
   * Tag incoming data (tool results, RAG chunks, external fetches) with provenance
   *
   * Call this after executing tools to annotate where the data came from.
   * The annotation is stored on the session mediation context as output
   * provenance and fed to emergent defense (collect-then-exfiltrate,
   * sensitive-then-transmit, goal hijack in tool results).
   *
   * @param results Tool outputs or fetched data
   * @param options.source Provenance source tag ('external' | 'user' | 'system' | 'tool' | 'untrusted')
   * @returns Emergent inspection after recording the observation
   *
   * @example
   * ```typescript
   * const webResults = await searchTool(query);
   * session.observe([webResults], { source: 'external' });
   * // Next step's tool calls will carry this source annotation
   * ```
   */
  observe(results: unknown[], options: { source: string }): EmergentInspectResult {
    const level = sourceToProvenanceLevel(options.source);
    const provenance = createProvenance(level, `observed_${options.source}`);
    this.mediationContext = {
      ...this.mediationContext,
      outputProvenance: [...(this.mediationContext.outputProvenance || []), provenance],
    };
    this.runtime.recordToolOutput(`observed_${options.source}`, this.sessionId, provenance);

    const emergent = this.tracker.recordObserve(results, options.source);
    this.logEmergent(emergent);
    return emergent;
  }

  /**
   * Post-gate the final agent output
   *
   * Checks the final LLM response against:
   * - The session-scoped canary (threaded across ALL steps — if the LLM
   *   repeats the canary from step 1 in its final output, it's caught here)
   * - PII masking
   * - N-gram similarity to system prompt fragments
   * - Encoded leak scanning
   * - Emergent compositions accumulated across the loop
   *
   * @param finalOutput The LLM's final response string
   * @returns SessionCompletionResult with post-gated output and session metrics
   */
  async complete(finalOutput: string): Promise<SessionCompletionResult> {
    const result = await this.runtime.post(
      { output: finalOutput },
      { sessionId: this.sessionId, userId: this.userId }
    );

    const emergent = this.tracker.recordComplete(finalOutput);
    this.logEmergent(emergent);

    const sessionRiskScore = Math.max(this.peakRisk, result.riskScore, emergent.sessionRisk);
    const allowed = result.allowed && emergent.allowed;

    return {
      allowed,
      reason: allowed ? undefined : (result.reason ?? emergent.reason),
      output: result.output,
      sessionRiskScore,
      stepCount: this.stepIndex,
      emergent,
    };
  }

  /**
   * Inspect emergent findings without recording a new event.
   *
   * @returns Current emergent inspection
   */
  inspect(): EmergentInspectResult {
    return this.tracker.inspect();
  }

  /** Number of steps executed so far */
  get currentStep(): number {
    return this.stepIndex;
  }

  /** Peak risk score across all steps executed so far */
  get peakRiskScore(): number {
    return this.peakRisk;
  }

  /** Session identifier */
  get id(): string {
    return this.sessionId;
  }

  private blockRemaining(
    toolCalls: ToolCall[],
    start: number,
    blocked: ToolMediatorResult[],
    reason: string,
  ): void {
    for (let i = start; i < toolCalls.length; i++) {
      blocked.push({
        allowed: false,
        reason,
        context: this.mediationContext,
      });
    }
  }

  private logEmergent(emergent: EmergentInspectResult): void {
    if (emergent.findings.length === 0) return;
    this.runtime.logTelemetry({
      type: 'emergent',
      allowed: emergent.allowed,
      reason: emergent.reason ?? emergent.findings.map(f => f.reason).join('; '),
      score: emergent.sessionRisk,
      sessionId: this.sessionId,
      userId: this.userId,
    });
  }
}
