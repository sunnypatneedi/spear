/**
 * SayMake OpenAI Client Adapter
 * 
 * Provides guardChat() wrapper for protecting all LLM calls in SayMake.
 * Integrates with @saymake/openai-client and provides drop-in security.
 */

import { createRuntime, type SAPPSRuntime } from '../core/runtime.js';
import { loadPolicy } from '../core/policy.js';
import type { Message } from '../gates/input_gate.js';

/**
 * Guard context for SayMake integrations
 */
export interface GuardContext {
  userId?: string;
  sessionId?: string;
  tenantId?: string;
  lang?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Guard result
 */
export interface GuardResult {
  allowed: boolean;
  reason?: string;
  output: string;
  telemetry?: {
    inputScore: number;
    outputScore: number;
    latencyMs: number;
  };
}

/**
 * LLM function signature (compatible with SayMake's openai-client)
 */
export type LLMFunction = (messages: Message[]) => Promise<string> | string;

/**
 * Global SAPPS runtime instance (singleton)
 */
let globalRuntime: SAPPSRuntime | null = null;

/**
 * Initialize global SAPPS runtime
 * 
 * Call this once at application startup to configure SAPPS.
 * 
 * @param options Initialization options
 * 
 * @example
 * ```typescript
 * import { initializeSAPPS } from '@saymake/sapps/adapters/openai-client';
 * 
 * initializeSAPPS({
 *   policyName: 'balanced',
 *   mode: process.env.SAPPS_MODE as any,
 *   sidecarUrl: process.env.SAPPS_SIDECAR_URL
 * });
 * ```
 */
export function initializeSAPPS(options: {
  policyName?: string;
  policyPath?: string;
  mode?: 'shadow' | 'enforce';
  sidecarUrl?: string;
  budgetMs?: number;
} = {}): SAPPSRuntime {
  const {
    policyName = 'balanced',
    policyPath,
    mode,
    sidecarUrl,
    budgetMs
  } = options;
  
  // Load policy
  const policy = loadPolicy(policyPath || `${policyName}.yaml`);
  
  // Create runtime
  globalRuntime = createRuntime({
    policy,
    mode: mode || policy.mode,
    sidecarUrl: sidecarUrl || null,
    budgetMs
  });
  
  return globalRuntime;
}

/**
 * Get global SAPPS runtime (initializes with defaults if not already initialized)
 */
export function getRuntime(): SAPPSRuntime {
  if (!globalRuntime) {
    globalRuntime = initializeSAPPS();
  }
  return globalRuntime;
}

/**
 * Guard an LLM chat call
 * 
 * Wraps any LLM function with SAPPS input/output gates.
 * 
 * @param messages Messages to send to LLM
 * @param llmFn LLM function to call
 * @param context Guard context
 * @returns Guard result with LLM output
 * 
 * @example
 * ```typescript
 * import { guardChat } from '@saymake/sapps/adapters/openai-client';
 * import { runAssistant } from '@saymake/openai-client';
 * 
 * const result = await guardChat(
 *   [{ role: 'user', content: 'Hello!' }],
 *   async (msgs) => {
 *     const response = await runAssistant({
 *       assistantId: 'asst_123',
 *       content: msgs[msgs.length - 1].content,
 *       metadata: { userId: 'user_123', tenantId: 'tenant_123' }
 *     });
 *     return response.content;
 *   },
 *   { userId: 'user_123', sessionId: 'session_abc' }
 * );
 * 
 * console.log(result.output);
 * ```
 */
export async function guardChat(
  messages: Message[],
  llmFn: LLMFunction,
  context: GuardContext = {}
): Promise<GuardResult> {
  const runtime = getRuntime();
  const startTime = Date.now();
  
  try {
    // Step 1: Pre-process (InputGate + InstructionShield)
    const preResult = await runtime.pre(messages, {
      userId: context.userId,
      sessionId: context.sessionId,
      lang: context.lang,
      metadata: context.metadata
    });
    
    if (!preResult.allowed) {
      return {
        allowed: false,
        reason: preResult.reason,
        output: runtime.getPolicy().refusal_phrases[0] || 'Request blocked by security policy.',
        telemetry: {
          inputScore: preResult.riskScore,
          outputScore: 0,
          latencyMs: Date.now() - startTime
        }
      };
    }
    
    // Step 2: Call LLM with sanitized messages
    const llmOutput = await llmFn(preResult.messages);
    
    // Step 3: Post-process (OutputGate)
    const postResult = await runtime.post(
      {
        output: llmOutput,
        canary: preResult.canary
        // TODO: Add systemPrompt for similarity check
      },
      {
        userId: context.userId,
        sessionId: context.sessionId
      }
    );
    
    const latencyMs = Date.now() - startTime;
    
    return {
      allowed: postResult.allowed,
      reason: postResult.reason,
      output: postResult.output,
      telemetry: {
        inputScore: preResult.riskScore,
        outputScore: postResult.riskScore,
        latencyMs
      }
    };
    
  } catch (error) {
    // Fail-open on errors
    const latencyMs = Date.now() - startTime;
    
    return {
      allowed: true,
      reason: `SAPPS error (fail-open): ${error instanceof Error ? error.message : String(error)}`,
      output: error instanceof Error ? error.message : 'An error occurred',
      telemetry: {
        inputScore: 0,
        outputScore: 0,
        latencyMs
      }
    };
  }
}

/**
 * Quick guard for simple string-in, string-out LLM calls
 * 
 * @param userMessage User message string
 * @param llmFn LLM function
 * @param context Guard context
 * @returns LLM output string
 */
export async function guardSimple(
  userMessage: string,
  llmFn: LLMFunction,
  context: GuardContext = {}
): Promise<string> {
  const messages: Message[] = [{ role: 'user', content: userMessage }];
  const result = await guardChat(messages, llmFn, context);
  return result.output;
}

/**
 * Check if SAPPS is initialized
 */
export function isInitialized(): boolean {
  return globalRuntime !== null;
}

/**
 * Reset SAPPS (for testing)
 */
export function reset(): void {
  globalRuntime = null;
}

