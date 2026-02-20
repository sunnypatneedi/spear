import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getSession, removeSession } from '../state.js';
import { jsonResponse, errorResponse } from '../helpers.js';

const inputSchema = {
  sessionId: z.string(),
  output: z.string(),
};

export function registerSessionComplete(server: McpServer): void {
  server.tool(
    'spear_session_complete',
    'Post-gate the final agent output and close the session. Checks canary leaks, PII, and returns accumulated session risk score.',
    inputSchema,
    async ({ sessionId, output }) => {
      try {
        const session = getSession(sessionId);
        if (!session) {
          return errorResponse(`Session "${sessionId}" not found. Call spear_session_start first.`);
        }
        const result = await session.complete(output);
        removeSession(sessionId);
        return jsonResponse(result);
      } catch (err) {
        return errorResponse(err instanceof Error ? err.message : String(err));
      }
    },
  );
}
