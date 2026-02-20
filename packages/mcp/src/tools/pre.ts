import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getRuntime } from '../state.js';
import { jsonResponse, errorResponse } from '../helpers.js';

const inputSchema = {
  messages: z.array(z.object({
    role: z.enum(['system', 'user', 'assistant', 'developer']),
    content: z.string(),
  })),
  sessionId: z.string().optional(),
  userId: z.string().optional(),
};

export function registerPre(server: McpServer): void {
  server.tool(
    'spear_pre',
    'Pre-process messages through input gate and instruction shield before sending to LLM. Detects prompt injection, enforces role hierarchy, generates canary tokens.',
    inputSchema,
    async ({ messages, sessionId, userId }) => {
      try {
        const result = await getRuntime().pre(messages, { sessionId, userId });
        return jsonResponse(result);
      } catch (err) {
        return errorResponse(err instanceof Error ? err.message : String(err));
      }
    },
  );
}
