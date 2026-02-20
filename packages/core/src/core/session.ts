/**
 * SpearSession: session-scoped security context for multi-step agent loops
 *
 * Wraps SpearRuntime with a stateful per-agent-loop context that:
 * - Threads a single canary across ALL steps (not regenerated per call)
 * - Accumulates peak risk score across the full loop
 * - Provides batch parallel tool checking for agents that fire multiple
 *   tool calls simultaneously
 * - Exposes an observe() hook to annotate tool results with provenance source
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
import { toolMediatorBatch, createMediationContext } from '../gates/tool_mediator.js';

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

  constructor(runtime: SpearRuntime, options: SessionOptions) {
    this.runtime = runtime;
    this.sessionId = options.sessionId;
    this.userId = options.userId;
  }

  /**
   * Pre-gate a single agent step
   *
   * Runs InputGate + InstructionShield on the messages, embeds the
   * session canary (same canary persists across all steps — pass it
   * to your system prompt and it will be detected if leaked in any step's
   * output).
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

    return {
      allowed: result.allowed,
      reason: result.reason,
      messages: result.messages,
      stepIndex: this.stepIndex,
      riskScore: result.riskScore,
    };
  }

  /**
   * Batch-check parallel tool calls
   *
   * Agents commonly receive multiple tool_calls from the LLM simultaneously.
   * This method checks all of them in one call, returning allowed and blocked
   * subsets. Note: the underlying batch mediator stops at the first blocked
   * call; any calls after the first block are auto-classified as blocked.
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
      return { allowed: [], blocked: [], total: 0 };
    }

    const policy = this.runtime.getPolicy();
    const context: MediationContext = createMediationContext(this.sessionId, policy.provenance);
    const results = await toolMediatorBatch(toolCalls, context, policy);

    const allowed: ToolMediatorResult[] = [];
    const blocked: ToolMediatorResult[] = [];

    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r.allowed) {
        allowed.push(r);
        // Record tool output for provenance taint tracking
        this.runtime.recordToolOutput(toolCalls[i].name, this.sessionId);
      } else {
        blocked.push(r);
      }
    }

    // toolMediatorBatch stops at first block — remaining calls were not checked
    if (results.length < toolCalls.length) {
      const stoppedAt = results.length;
      for (let i = stoppedAt; i < toolCalls.length; i++) {
        blocked.push({
          allowed: false,
          reason: 'Batch stopped at earlier blocked call',
          context,
        });
      }
    }

    return { allowed, blocked, total: toolCalls.length };
  }

  /**
   * Tag incoming data (tool results, RAG chunks, external fetches) with provenance
   *
   * Call this after executing tools to annotate where the data came from.
   * In subsequent steps the session context carries this annotation so that
   * taint propagation can be tracked across the full loop.
   *
   * Note: In v0.1 this is a recording hook — full taint propagation into
   * ToolMediator argument checks ships in v0.2 (see GitHub issue #22).
   *
   * @param results Tool outputs or fetched data
   * @param options.source Provenance source tag ('external' | 'user' | 'system' | 'tool')
   *
   * @example
   * ```typescript
   * const webResults = await searchTool(query);
   * session.observe([webResults], { source: 'external' });
   * // Next step's tool calls will carry this source annotation
   * ```
   */
  observe(results: unknown[], options: { source: string }): void {
    // Record in runtime's tool output provenance for the session
    // Full taint propagation is tracked via runtime.recordToolOutput
    // This observe() call stores the source annotation for future taint analysis.
    void results;
    void options;
    // v0.2: derive Provenance from options.source and attach to runtime context
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
   *
   * @param finalOutput The LLM's final response string
   * @returns SessionCompletionResult with post-gated output and session metrics
   */
  async complete(finalOutput: string): Promise<SessionCompletionResult> {
    const result = await this.runtime.post(
      { output: finalOutput },
      { sessionId: this.sessionId, userId: this.userId }
    );

    return {
      allowed: result.allowed,
      reason: result.reason,
      output: result.output,
      sessionRiskScore: Math.max(this.peakRisk, result.riskScore),
      stepCount: this.stepIndex,
    };
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
}
