/**
 * SpearSession: session-scoped security context for multi-step agent loops.
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
 *   await session.observe(results, { source: 'external' });
 *
 *   // Step 2 — pre-gate follow-up messages
 *   const s2 = await session.step(followUpMessages);
 *
 *   // Final output gate with session-accumulated canary
 *   const final = await session.complete(llmFinalOutput);
 */

import type { SpearRuntime } from './runtime.js';
import { inputGate, type Message } from '../gates/input_gate.js';
import type { ToolCall, ToolMediatorResult, MediationContext } from '../gates/tool_mediator.js';
import { toolMediator, createMediationContext } from '../gates/tool_mediator.js';
import { createProvenance, minProvenance, type Provenance } from './provenance.js';
import {
  createEmergentTracker,
  classifyToolRole,
  type EmergentInspectResult,
  type EmergentTracker,
} from './emergent.js';
import type { ProvenanceLevel } from './provenance.js';
import { scanSecrets, stringifyForInspection } from './secrets.js';

/** Result from a single agent step. */
export interface StepResult {
  allowed: boolean;
  reason?: string;
  /** Sanitized messages — pass these to your LLM, not the originals. */
  messages: Message[];
  /** Session-stable canary to embed in the privileged system prompt. */
  canary?: string;
  /** Which step number this was (1-indexed). */
  stepIndex: number;
  riskScore: number;
  /** Emergent-defense inspection for this step (compositions across the session) */
  emergent?: EmergentInspectResult;
}

/** Result from a batch of tool checks. */
export interface ToolBatchResult {
  /** Tool calls that passed mediation — safe to execute. */
  allowed: ToolMediatorResult[];
  /** Tool calls that were blocked. */
  blocked: ToolMediatorResult[];
  /** Total number of calls submitted. */
  total: number;
  /** Emergent-defense inspection after this batch */
  emergent?: EmergentInspectResult;
}

/** Result of tagging and scanning tool/RAG/external data. */
export interface ObservationResult extends EmergentInspectResult {
  /** False when the observation contains a detected injection or secret. */
  accepted: boolean;
  /** True means the session is tainted and should not cross a trust boundary. */
  tainted: boolean;
  /** Highest risk score observed across supplied values. */
  riskScore: number;
  /** Number of possible secrets found; raw values are never returned. */
  secretCount: number;
  reason?: string;
  provenance: Provenance;
}

/** Result from session.complete(). */
export interface SessionCompletionResult {
  allowed: boolean;
  reason?: string;
  /** Post-gated (PII-masked, canary-checked) output. */
  output: string;
  /** Peak risk score accumulated across this session. */
  sessionRiskScore: number;
  /** Total number of steps executed. */
  stepCount: number;
  /** Emergent-defense inspection at session close */
  emergent?: EmergentInspectResult;
}

/** Options for creating a SpearSession. */
export interface SessionOptions {
  sessionId: string;
  userId?: string;
}

const PROVENANCE_LEVELS: ProvenanceLevel[] = [
  'system', 'user', 'assistant', 'tool', 'external', 'untrusted'
];

/** Stateful per-agent-loop security context. */
export class SpearSession {
  private readonly runtime: SpearRuntime;
  private readonly sessionId: string;
  private readonly userId?: string;
  private readonly startedAt = Date.now();
  private stepIndex = 0;
  private peakRisk = 0;
  private mediationContext: MediationContext;
  private tracker: EmergentTracker;
  private attemptedToolCalls = 0;
  private toolHistory: string[] = [];
  private taintReason?: string;
  private completed = false;
  private operations: Promise<void> = Promise.resolve();

  constructor(runtime: SpearRuntime, options: SessionOptions) {
    this.runtime = runtime;
    this.sessionId = options.sessionId;
    this.userId = options.userId;
    const policy = runtime.getPolicy();
    this.mediationContext = createMediationContext(options.sessionId, policy.provenance);
    this.tracker = createEmergentTracker(policy.emergent, runtime.getMode());
  }

  /** Pre-gate one agent step and enforce the session circuit breakers. */
  step(messages: Message[]): Promise<StepResult> {
    return this.enqueue(() => this.stepInternal(messages));
  }

  private async stepInternal(messages: Message[]): Promise<StepResult> {
    if (this.completed) {
      return this.blockedStep(messages, 'SPEAR session is already closed');
    }
    const budgetReason = this.getCircuitBreakerReason(0, true);
    if (budgetReason && this.runtime.getMode() === 'enforce') {
      return this.blockedStep(messages, budgetReason);
    }

    const result = await this.runtime.pre(messages, {
      sessionId: this.sessionId,
      userId: this.userId
    });

    this.stepIndex++;
    this.peakRisk = Math.max(this.peakRisk, result.riskScore);

    if (budgetReason) {
      this.runtime.recordObservation({
        sessionId: this.sessionId,
        allowed: false,
        reason: budgetReason,
        score: 1
      });
    }

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
      canary: result.canary,
      stepIndex: this.stepIndex,
      riskScore: Math.max(result.riskScore, emergent.sessionRisk),
      emergent,
    };
  }

  /**
   * Mediate a batch of tool calls while preserving one context across turns.
   * Once one call is denied, later calls are not executed or silently retried.
   */
  tools(toolCalls: ToolCall[]): Promise<ToolBatchResult> {
    return this.enqueue(() => this.toolsInternal(toolCalls));
  }

  private async toolsInternal(toolCalls: ToolCall[]): Promise<ToolBatchResult> {
    if (toolCalls.length === 0) {
      return { allowed: [], blocked: [], total: 0, emergent: this.tracker.inspect() };
    }

    const policy = this.runtime.getPolicy();
    let emergent = this.tracker.inspect();
    const blocked: ToolMediatorResult[] = [];
    const allowed: ToolMediatorResult[] = [];
    const contextFallback = (): MediationContext => createMediationContext(
      this.sessionId,
      policy.provenance,
      { enforcementMode: this.runtime.getMode() }
    );

    if (this.completed) {
      return {
        allowed,
        blocked: toolCalls.map(() => ({
          allowed: false,
          reason: 'SPEAR session is already closed',
          context: contextFallback()
        })),
        total: toolCalls.length
      };
    }

    const reason = this.getCircuitBreakerReason(toolCalls.length);
    if (reason && this.runtime.getMode() === 'enforce') {
      return {
        allowed,
        blocked: toolCalls.map(() => ({
          allowed: false,
          reason,
          context: contextFallback()
        })),
        total: toolCalls.length
      };
    }

    this.attemptedToolCalls += toolCalls.length;

    let stopped = false;
    let lastContext = contextFallback();
    for (const rawCall of toolCalls) {
      const toolCall = this.applyObservedTaint(rawCall);
      if (stopped) {
        blocked.push({
          allowed: false,
          reason: 'Batch stopped at earlier blocked call',
          context: lastContext
        });
        continue;
      }

      const consecutive = this.getConsecutiveToolCount(toolCall.name);
      if (policy.agent.enabled && this.runtime.getMode() === 'enforce' && consecutive >= policy.agent.max_consecutive_same_tool) {
        const result: ToolMediatorResult = {
          allowed: false,
          reason: `Agent circuit breaker: '${toolCall.name}' repeated ${consecutive} times`,
          context: lastContext
        };
        blocked.push(result);
        stopped = true;
        continue;
      }

      // Going through the runtime is intentional: it retrieves and updates the
      // persistent context, unlike the old implementation which reset counts
      // and provenance on every session.tools() call.
      const result = await this.runtime.mediateToolCall(toolCall, this.sessionId);
      lastContext = result.context;
      this.mediationContext = result.context;
      this.toolHistory.push(toolCall.name);

      if (result.allowed) {
        emergent = this.tracker.recordTool(toolCall);
        this.logEmergent(emergent);
        if (!emergent.allowed) {
          blocked.push({ allowed: false, reason: emergent.reason, context: lastContext });
          stopped = true;
          continue;
        }
        allowed.push(result);
        this.runtime.recordToolOutput(toolCall.name, this.sessionId);
      } else {
        blocked.push(result);
        stopped = true;
      }
    }

    if (reason) {
      this.runtime.recordObservation({
        sessionId: this.sessionId,
        allowed: false,
        reason,
        score: 1
      });
    }

    return { allowed, blocked, total: toolCalls.length, emergent };
  }

  /**
   * Scan and tag tool output, retrieval data, or external content.
   *
   * This is an active boundary now—not a no-op recording hook. Suspicious
   * content taints the session, and enforce mode trips the circuit breaker
   * before the agent can use it to select a privileged next action.
   */
  observe(results: unknown[], options: { source: string }): Promise<ObservationResult> {
    return this.enqueue(() => this.observeInternal(results, options));
  }

  private async observeInternal(
    results: unknown[],
    options: { source: string } // source must be assigned by the application, not the model
  ): Promise<ObservationResult> {
    if (this.completed) throw new Error('SPEAR session is already closed');
    const level = PROVENANCE_LEVELS.includes(options.source as ProvenanceLevel)
      ? options.source as ProvenanceLevel
      : 'external';
    const provenance = createProvenance(level, options.source, {
      sanitized: false,
      metadata: { itemCount: results.length }
    });

    const emergent = this.tracker.recordObserve(results, options.source);
    this.logEmergent(emergent);
    this.mediationContext = {
      ...this.mediationContext,
      outputProvenance: [...(this.mediationContext.outputProvenance || []), provenance],
    };
    let riskScore = emergent.sessionRisk;
    let secretCount = 0;
    const reasons: string[] = emergent.allowed ? [] : [emergent.reason || 'Emergent attack detected'];

    try {
      for (const value of results) {
        const text = stringifyForInspection(value, 100_000);
        const secretScan = this.runtime.getPolicy().egress.scan_secrets
          ? scanSecrets(text)
          : { detected: false, matches: [] };
        secretCount += secretScan.matches.length;

        const inputResult = await inputGate([{
          role: 'user',
          content: text,
          provenance
        }], this.runtime.getPolicy());
        riskScore = Math.max(riskScore, inputResult.score);

        if (!inputResult.allowed) reasons.push(inputResult.reason || 'Injection detected in observed data');
        if (secretScan.detected) reasons.push('Possible secret detected in observed data');
      }

    } catch {
      reasons.push('Observation inspection failed');
      riskScore = 1;
    }

    const tainted = reasons.length > 0;
    if (tainted && !this.taintReason) {
      this.taintReason = reasons[0];
    }
    this.peakRisk = Math.max(this.peakRisk, riskScore, tainted ? 1 : 0);

    // The runtime provenance record stores metadata; the existing tracker retains its bounded trace.
    this.runtime.recordToolOutput(`observed:${options.source}`, this.sessionId, provenance);
    this.runtime.recordObservation({
      sessionId: this.sessionId,
      allowed: !tainted || this.runtime.getMode() === 'shadow',
      reason: tainted ? reasons.join('; ') : undefined,
      score: riskScore,
      provenance: { level: provenance.level, source: provenance.source }
    });

    return {
      ...emergent,
      allowed: !tainted || this.runtime.getMode() === 'shadow',
      accepted: !tainted || this.runtime.getMode() === 'shadow',
      tainted,
      riskScore,
      secretCount,
      reason: tainted ? reasons.join('; ') : undefined,
      provenance
    };
  }

  /** Post-gate final output and close the session. */
  complete(finalOutput: string): Promise<SessionCompletionResult> {
    return this.enqueue(() => this.completeInternal(finalOutput));
  }

  private async completeInternal(finalOutput: string): Promise<SessionCompletionResult> {
    if (this.completed) {
      return {
        allowed: false,
        reason: 'SPEAR session is already closed',
        output: '',
        sessionRiskScore: this.peakRisk,
        stepCount: this.stepIndex
      };
    }

    const circuitReason = this.getCircuitBreakerReason();
    if (circuitReason && this.runtime.getMode() === 'enforce') {
      this.close();
      return {
        allowed: false,
        reason: circuitReason,
        output: '',
        sessionRiskScore: 1,
        stepCount: this.stepIndex
      };
    }

    const result = await this.runtime.post(
      { output: finalOutput },
      { sessionId: this.sessionId, userId: this.userId }
    );
    this.completed = true;
    this.runtime.closeSession(this.sessionId);

    const emergent = this.tracker.recordComplete(finalOutput);
    this.logEmergent(emergent);

    const sessionRiskScore = Math.max(this.peakRisk, result.riskScore, emergent.sessionRisk);
    const allowed = result.allowed && emergent.allowed;

    return {
      allowed,
      reason: allowed ? undefined : (result.reason ?? emergent.reason),
      output: allowed ? result.output : '',
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

  /** Explicitly close the session without producing an output. */
  close(): void {
    this.completed = true;
    this.runtime.closeSession(this.sessionId);
  }

  /** Number of steps executed so far */
  get currentStep(): number {
    return this.stepIndex;
  }

  /** Peak risk score across all steps executed so far. */
  get peakRiskScore(): number {
    return this.peakRisk;
  }

  /** Session identifier. */
  get id(): string {
    return this.sessionId;
  }

  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.operations.then(operation);
    this.operations = result.then(() => undefined, () => undefined);
    return result;
  }

  private applyObservedTaint(call: ToolCall): ToolCall {
    if (call.argumentProvenance) return call;
    const tainted = this.minObservedProvenance();
    if (!tainted) return call;
    const role = classifyToolRole(call.name);
    if (role !== 'exfil' && role !== 'execute' && role !== 'write') return call;
    const argumentProvenance: Record<string, Provenance> = {};
    for (const key of Object.keys(call.arguments)) {
      argumentProvenance[key] = tainted;
    }
    return { ...call, argumentProvenance };
  }

  private minObservedProvenance(): Provenance | undefined {
    const records = this.mediationContext.outputProvenance;
    if (!records || records.length === 0) return undefined;
    let min = records[0];
    for (const rec of records.slice(1)) {
      if (minProvenance(rec.level, min.level) === rec.level) {
        min = rec;
      }
    }
    return min;
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

  private getCircuitBreakerReason(additionalToolCalls = 0, startingStep = false): string | undefined {
    if (this.completed) return 'SPEAR session is already closed';

    const agent = this.runtime.getAgentPolicy();
    if (!agent.enabled) return undefined;
    if (startingStep && this.stepIndex >= agent.max_steps) {
      return `Agent circuit breaker: maximum session steps (${agent.max_steps}) exceeded`;
    }
    if (Date.now() - this.startedAt >= agent.max_duration_ms) {
      return `Agent circuit breaker: maximum session duration (${agent.max_duration_ms}ms) exceeded`;
    }
    if (this.attemptedToolCalls + additionalToolCalls > agent.max_tool_calls) {
      return `Agent circuit breaker: maximum tool calls (${agent.max_tool_calls}) exceeded`;
    }
    if (this.taintReason && agent.circuit_breaker_on_taint) {
      return `Agent circuit breaker: session tainted (${this.taintReason})`;
    }
    return undefined;
  }

  private getConsecutiveToolCount(toolName: string): number {
    let count = 0;
    for (let i = this.toolHistory.length - 1; i >= 0; i--) {
      if (this.toolHistory[i] !== toolName) break;
      count++;
    }
    return count;
  }

  private blockedStep(messages: Message[], reason: string): StepResult {
    this.stepIndex++;
    this.peakRisk = Math.max(this.peakRisk, 1);
    this.runtime.recordObservation({
      sessionId: this.sessionId,
      allowed: false,
      reason,
      score: 1
    });
    return {
      allowed: false,
      reason,
      messages,
      stepIndex: this.stepIndex,
      riskScore: 1
    };
  }
}
