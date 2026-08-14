#!/usr/bin/env node
/**
 * Language-agnostic HTTP API for Spear gates.
 *
 * Endpoints:
 *   POST /pre
 *   POST /post
 *   POST /session/start
 *   POST /session/:id/step
 *   POST /session/:id/tools
 *   POST /session/:id/observe
 *   POST /session/:id/complete
 *   GET  /health
 *   GET  /metrics
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { quick, type SpearRuntime, type SpearSession, type Message, type ToolCall } from '@spear-secure/core';

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

function parseUrl(url: string): { path: string; id?: string; action?: string } {
  const path = url.split('?')[0] ?? url;
  const session = /^\/session\/([^/]+)(?:\/([^/]+))?$/.exec(path);
  if (session) {
    return { path, id: decodeURIComponent(session[1]), action: session[2] };
  }
  return { path };
}

/**
 * Create an HTTP server exposing Spear as REST.
 *
 * @param options.port Listen port (default 7700 or PORT)
 * @param options.runtime Optional pre-built runtime
 */
export function createApiServer(options: {
  port?: number;
  runtime?: SpearRuntime;
} = {}): { server: ReturnType<typeof createServer>; runtime: SpearRuntime } {
  const runtime = options.runtime ?? quick(process.env.SPEAR_POLICY || 'balanced', {
    mode: (process.env.SPEAR_MODE as 'shadow' | 'enforce') || 'shadow',
    sidecarUrl: process.env.SPEAR_SIDECAR_URL || null,
  });
  const sessions = new Map<string, SpearSession>();

  const server = createServer(async (req, res) => {
    try {
      const method = req.method ?? 'GET';
      const { path, id, action } = parseUrl(req.url ?? '/');

      if (method === 'GET' && path === '/health') {
        json(res, 200, { status: 'ok' });
        return;
      }
      if (method === 'GET' && path === '/metrics') {
        json(res, 200, { sessions: sessions.size, telemetry: runtime.getTelemetry().length });
        return;
      }

      const raw = method === 'GET' ? '{}' : await readBody(req);
      const body = raw ? JSON.parse(raw) as Record<string, unknown> : {};

      if (method === 'POST' && path === '/pre') {
        const result = await runtime.pre((body.messages as Message[]) ?? [], {
          sessionId: body.session_id as string | undefined,
          userId: body.user_id as string | undefined,
          tenantId: body.tenant_id as string | undefined,
        });
        json(res, 200, result);
        return;
      }

      if (method === 'POST' && path === '/post') {
        const result = await runtime.post(
          { output: String(body.output ?? ''), canary: body.canary as string | undefined },
          { sessionId: body.session_id as string | undefined }
        );
        json(res, 200, result);
        return;
      }

      if (method === 'POST' && path === '/session/start') {
        const sessionId = String(body.session_id ?? body.sessionId ?? `s-${Date.now()}`);
        if (sessions.has(sessionId)) {
          json(res, 409, { error: `Session "${sessionId}" already exists` });
          return;
        }
        const session = runtime.session({ sessionId, userId: body.user_id as string | undefined });
        sessions.set(sessionId, session);
        json(res, 200, { id: sessionId, session_id: sessionId, status: 'created' });
        return;
      }

      if (id && method === 'POST') {
        const session = sessions.get(id);
        if (!session) {
          json(res, 404, { error: `Session "${id}" not found` });
          return;
        }
        if (action === 'step') {
          json(res, 200, await session.step((body.messages as Message[]) ?? []));
          return;
        }
        if (action === 'tools') {
          json(res, 200, await session.tools((body.tool_calls as ToolCall[]) ?? []));
          return;
        }
        if (action === 'observe') {
          json(res, 200, session.observe(body.results as unknown[] ?? [], {
            source: String(body.source ?? 'external'),
          }));
          return;
        }
        if (action === 'complete') {
          const result = await session.complete(String(body.output ?? ''));
          sessions.delete(id);
          json(res, 200, result);
          return;
        }
      }

      json(res, 404, { error: 'Not found' });
    } catch (err) {
      json(res, 500, { error: err instanceof Error ? err.message : String(err) });
    }
  });

  return { server, runtime };
}

const port = Number(process.env.PORT || process.env.SPEAR_API_PORT || 7700);

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('index.js')) {
  const { server } = createApiServer();
  server.listen(port, () => {
    process.stdout.write(`spear-api listening on ${port}\n`);
  });
}
