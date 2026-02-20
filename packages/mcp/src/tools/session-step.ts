import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getSession } from '../state.js';
import { jsonResponse, errorResponse } from '../helpers.js';

const inputSchema = {
  sessionId: z.string(),
  messages: z.array(z.object({
    role: z.enum(['system', 'user', 'assistant', 'developer']),
    content: z.string(),
  })),
};

export function registerSessionStep(server: McpServer): void {
  server.tool(
    'spear_session_step',
    'Pre-gate a single step within an active session. Runs input gate and instruction shield while threading the session canary.',
    inputSchema,
    async ({ sessionId, messages }) => {
      try {
        const session = getSession(sessionId);
        if (!session) {
          return errorResponse(`Session "${sessionId}" not found. Call spear_session_start first.`);
        }
        const result = await session.step(messages);
        return jsonResponse(result);
      } catch (err) {
        return errorResponse(err instanceof Error ? err.message : String(err));
      }
    },
  );
}
