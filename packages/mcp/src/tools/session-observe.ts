import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getSession } from '../state.js';
import { jsonResponse, errorResponse } from '../helpers.js';

const inputSchema = {
  sessionId: z.string(),
  results: z.array(z.unknown()),
  source: z.enum(['external', 'tool', 'untrusted']).default('external'),
};

export function registerSessionObserve(server: McpServer): void {
  server.tool(
    'spear_session_observe',
    'Scan and tag tool/RAG/external results. Suspicious results taint the session and trip enforce-mode circuit breakers.',
    inputSchema,
    async ({ sessionId, results, source }) => {
      try {
        const session = getSession(sessionId);
        if (!session) {
          return errorResponse(`Session "${sessionId}" not found. Call spear_session_start first.`);
        }
        return jsonResponse(await session.observe(results, { source }));
      } catch (err) {
        return errorResponse(err instanceof Error ? err.message : String(err));
      }
    },
  );
}
