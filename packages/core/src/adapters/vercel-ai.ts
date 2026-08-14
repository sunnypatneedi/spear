/**
 * Thin Vercel AI SDK / Next.js adapter. No `ai` package dependency.
 *
 * Wraps a route handler: runs Spear `pre()` on `messages`, injects the
 * canary, and runs `postStream()` on the handler's response body so
 * streaming LLM output is still scanned for canaries and deny-listed n-grams.
 */

import { createRuntime } from '../core/runtime.js';
import { loadPolicy } from '../core/policy-load.js';
import type { Message } from '../gates/input_gate.js';

export interface WithSpearOptions {
  profile?: string;
  mode?: 'shadow' | 'enforce';
  sessionId?: string;
}

export interface SpearHandlerContext {
  messages: Message[];
  canary?: string;
}

/**
 * Convert a fetch Response body into an async iterable of UTF-8 chunks.
 *
 * @param body Readable stream from the inner handler
 */
async function* readTextChunks(body: ReadableStream<Uint8Array>): AsyncIterable<string> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        const tail = decoder.decode();
        if (tail) yield tail;
        break;
      }
      yield decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
}

function stripContentLength(headers: Headers): Headers {
  const next = new Headers(headers);
  next.delete('content-length');
  return next;
}

/**
 * Wrap a fetch-style handler with Spear pre-gating and streaming post-gating.
 *
 * The inner handler should use `ctx.messages` and `ctx.canary` (the request
 * body has already been consumed).
 *
 * @param handler User handler receiving sanitized messages + canary
 * @param options Spear profile / mode
 */
export function withSpear(
  handler: (req: Request, ctx: SpearHandlerContext) => Promise<Response>,
  options: WithSpearOptions = {}
): (req: Request) => Promise<Response> {
  const runtime = createRuntime({
    policy: loadPolicy(`${options.profile ?? 'balanced'}.yaml`),
    mode: options.mode,
  });

  return async (req: Request): Promise<Response> => {
    let body: { messages?: Message[] };
    try {
      body = await req.json() as { messages?: Message[] };
    } catch {
      return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      });
    }

    const messages = body.messages ?? [];
    const pre = await runtime.pre(messages, { sessionId: options.sessionId });
    if (!pre.allowed) {
      return new Response(JSON.stringify({ error: pre.reason, retryAfterMs: pre.retryAfterMs }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      });
    }

    const inner = await handler(req, { messages: pre.messages, canary: pre.canary });
    if (!inner.body) {
      return inner;
    }

    const encoder = new TextEncoder();
    const chunks = readTextChunks(inner.body);
    const gated = new ReadableStream<Uint8Array>({
      async start(controller) {
        try {
          for await (const chunk of runtime.postStream(chunks, {
            sessionId: options.sessionId,
            canary: pre.canary,
          })) {
            controller.enqueue(encoder.encode(chunk));
          }
          controller.close();
        } catch (err) {
          controller.error(err);
        }
      },
    });

    return new Response(gated, {
      status: inner.status,
      headers: stripContentLength(inner.headers),
    });
  };
}
