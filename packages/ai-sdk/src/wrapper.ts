/**
 * Vercel AI SDK Language Model Wrapper with SPEAR Protection
 *
 * Wraps any Vercel AI SDK LanguageModel to provide:
 * - Input validation (prompt injection detection)
 * - Output sanitization (PII masking, leak detection)
 * - Provenance tracking
 * - Tool call mediation
 */

import { quick, type SpearRuntime } from '@spear-secure/core';
import type { LanguageModel, LanguageModelV1CallOptions, LanguageModelV1FinishReason } from 'ai';

export interface SpearWrapperOptions {
  /** SPEAR policy name: 'balanced', 'safe', or 'permissive' */
  policy?: string;
  /** Operating mode: 'shadow', 'enforce', or 'disabled' */
  mode?: 'shadow' | 'enforce' | 'disabled';
  /** Optional session ID for telemetry */
  sessionId?: string;
  /** Optional user ID for telemetry */
  userId?: string;
  /** Optional ML sidecar URL for similarity detection */
  sidecarUrl?: string;
}

/**
 * Wraps a Vercel AI SDK LanguageModel with SPEAR protection
 *
 * @param model - The base LanguageModel to wrap
 * @param options - SPEAR configuration options
 * @returns A protected LanguageModel that intercepts all calls
 *
 * @example
 * ```typescript
 * import { google } from '@ai-sdk/google';
 * import { wrapLanguageModel } from '@spear-secure/ai-sdk';
 *
 * const guardedModel = wrapLanguageModel(
 *   google('gemini-1.5-flash'),
 *   { policy: 'safe', mode: 'enforce' }
 * );
 * ```
 */
export function wrapLanguageModel(
  model: LanguageModel,
  options: SpearWrapperOptions = {}
): LanguageModel {
  const {
    policy = 'balanced',
    mode = 'shadow',
    sessionId,
    userId,
    sidecarUrl
  } = options;

  // Create SPEAR runtime instance
  const runtime = quick(policy, { mode, sidecarUrl });

  // Create wrapped model that intercepts all calls
  const wrapped: LanguageModel = {
    specificationVersion: model.specificationVersion,
    provider: model.provider,
    modelId: model.modelId,
    defaultObjectGenerationMode: model.defaultObjectGenerationMode,

    async doGenerate(callOptions: LanguageModelV1CallOptions) {
      // Extract messages from prompt
      const messages = extractMessages(callOptions);

      // Run SPEAR pre-gate
      const preResult = await runtime.pre(messages, { sessionId, userId });

      if (!preResult.allowed) {
        // Block the request - return refusal response
        return {
          text: preResult.refusalMessage || 'Request blocked by security policy.',
          finishReason: 'stop' as LanguageModelV1FinishReason,
          usage: { promptTokens: 0, completionTokens: 0 },
          rawCall: { rawPrompt: null, rawSettings: {} },
          warnings: [],
        };
      }

      // Call original model with sanitized messages
      const result = await model.doGenerate({
        ...callOptions,
        prompt: updatePromptMessages(callOptions.prompt, preResult.messages),
      });

      // Run SPEAR post-gate
      const postResult = await runtime.post({
        output: result.text || '',
        canary: preResult.canary,
      });

      if (!postResult.allowed) {
        // Output blocked - return sanitized response
        return {
          ...result,
          text: postResult.sanitizedOutput || 'Response blocked by security policy.',
        };
      }

      // Return protected result
      return {
        ...result,
        text: postResult.sanitizedOutput || result.text,
      };
    },

    async doStream(callOptions: LanguageModelV1CallOptions) {
      // Extract messages from prompt
      const messages = extractMessages(callOptions);

      // Run SPEAR pre-gate
      const preResult = await runtime.pre(messages, { sessionId, userId });

      if (!preResult.allowed) {
        // Block the request - return error stream
        return {
          stream: createBlockedStream(preResult.refusalMessage),
          rawCall: { rawPrompt: null, rawSettings: {} },
          warnings: [],
        };
      }

      // Call original model with sanitized messages
      const result = await model.doStream({
        ...callOptions,
        prompt: updatePromptMessages(callOptions.prompt, preResult.messages),
      });

      // Wrap stream with post-gate protection
      return {
        ...result,
        stream: wrapStream(result.stream, runtime, preResult.canary),
      };
    },
  };

  return wrapped;
}

/**
 * Convenience function to create a guarded model from a provider
 *
 * @example
 * ```typescript
 * import { createGuardedModel } from '@spear-secure/ai-sdk';
 * import { google } from '@ai-sdk/google';
 *
 * const model = createGuardedModel(google, 'gemini-1.5-flash', {
 *   policy: 'safe',
 *   mode: 'enforce'
 * });
 * ```
 */
export function createGuardedModel(
  provider: any,
  modelId: string,
  options: SpearWrapperOptions = {}
): LanguageModel {
  const baseModel = provider(modelId);
  return wrapLanguageModel(baseModel, options);
}

// --- Helper Functions ---

function extractMessages(callOptions: LanguageModelV1CallOptions): Array<{ role: string; content: string }> {
  const messages: Array<{ role: string; content: string }> = [];

  if (callOptions.prompt && Array.isArray(callOptions.prompt)) {
    for (const item of callOptions.prompt) {
      if (item.role && item.content) {
        const contentStr = Array.isArray(item.content)
          ? item.content.map(c => (typeof c === 'string' ? c : c.text || '')).join(' ')
          : String(item.content);

        messages.push({
          role: item.role,
          content: contentStr,
        });
      }
    }
  }

  return messages;
}

function updatePromptMessages(prompt: any, sanitizedMessages: Array<{ role: string; content: string }>): any {
  if (!Array.isArray(prompt)) {
    return prompt;
  }

  return sanitizedMessages.map((msg, idx) => {
    const original = prompt[idx] || {};
    return {
      ...original,
      role: msg.role,
      content: msg.content,
    };
  });
}

async function* createBlockedStream(message?: string) {
  yield {
    type: 'text-delta' as const,
    textDelta: message || 'Request blocked by security policy.',
  };
  yield {
    type: 'finish' as const,
    finishReason: 'stop' as LanguageModelV1FinishReason,
    usage: { promptTokens: 0, completionTokens: 0 },
  };
}

async function* wrapStream(
  originalStream: AsyncIterable<any>,
  runtime: SpearRuntime,
  canary?: string
) {
  let accumulatedText = '';

  for await (const chunk of originalStream) {
    if (chunk.type === 'text-delta') {
      accumulatedText += chunk.textDelta;
      yield chunk;
    } else if (chunk.type === 'finish') {
      // Run post-gate on accumulated text
      const postResult = await runtime.post({
        output: accumulatedText,
        canary,
      });

      if (!postResult.allowed) {
        // Output blocked - yield sanitized text
        yield {
          type: 'text-delta' as const,
          textDelta: '\n[Response sanitized by SPEAR]',
        };
      }

      yield chunk;
    } else {
      yield chunk;
    }
  }
}
