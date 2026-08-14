/**
 * LangChain-compatible callback handler (no langchain dependency).
 *
 * Pass an instance as a callback on LLMChain / AgentExecutor. In enforce
 * mode a blocked call throws; in shadow mode it logs via Spear telemetry.
 */

import { createRuntime, type SpearRuntime } from '../core/runtime.js';
import { loadPolicy } from '../core/policy-load.js';
import { SpearSession } from '../core/session.js';

export interface SpearCallbackOptions {
  profile?: string;
  mode?: 'shadow' | 'enforce';
  sessionId?: string;
  userId?: string;
}

/**
 * Duck-typed BaseCallbackHandler for LangChain JS.
 */
export class SpearCallbackHandler {
  /** LangChain reads this name for logging. */
  name = 'spear_callback';
  private runtime: SpearRuntime;
  private session: SpearSession;
  private mode: 'shadow' | 'enforce';

  /**
   * @param options Profile, mode, and session identity
   */
  constructor(options: SpearCallbackOptions = {}) {
    this.mode = options.mode ?? 'shadow';
    this.runtime = createRuntime({
      policy: loadPolicy(`${options.profile ?? 'balanced'}.yaml`),
      mode: this.mode,
    });
    this.session = this.runtime.session({
      sessionId: options.sessionId ?? `langchain-${Date.now()}`,
      userId: options.userId,
    });
  }

  /**
   * LangChain `handleLLMStart` — pre-gate prompts.
   */
  async handleLLMStart(_llm: unknown, prompts: string[]): Promise<void> {
    const step = await this.session.step([
      { role: 'system', content: 'Spear-guarded LangChain call.' },
      ...prompts.map(content => ({ role: 'user' as const, content })),
    ]);
    if (!step.allowed && this.mode === 'enforce') {
      throw new Error(step.reason ?? 'Spear blocked LLM start');
    }
  }

  /**
   * LangChain `handleLLMEnd` — post-gate the concatenated generation text.
   */
  async handleLLMEnd(output: { generations?: Array<Array<{ text?: string }>> }): Promise<void> {
    const text = output.generations?.flat().map(g => g.text ?? '').join('\n') ?? '';
    if (!text) return;
    const result = await this.session.complete(text);
    if (!result.allowed && this.mode === 'enforce') {
      throw new Error(result.reason ?? 'Spear blocked LLM output');
    }
  }

  /**
   * LangChain `handleToolStart` — mediate the tool call.
   */
  async handleToolStart(tool: { name?: string }, input: unknown): Promise<void> {
    const name = tool.name ?? 'unknown';
    const args = typeof input === 'object' && input !== null
      ? (input as Record<string, unknown>)
      : { input };
    const { blocked } = await this.session.tools([{ name, arguments: args }]);
    if (blocked.length > 0 && this.mode === 'enforce') {
      throw new Error(blocked[0].reason ?? `Spear blocked tool ${name}`);
    }
  }

  /**
   * LangChain `handleToolEnd` — observe tool output as external data.
   */
  handleToolEnd(output: unknown): void {
    this.session.observe([output], { source: 'external' });
  }
}
