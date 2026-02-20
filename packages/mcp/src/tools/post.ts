import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getRuntime } from '../state.js';
import { jsonResponse, errorResponse } from '../helpers.js';

const inputSchema = {
  output: z.string(),
  canary: z.string().optional(),
  systemPrompt: z.string().optional(),
  sessionId: z.string().optional(),
  userId: z.string().optional(),
};

export function registerPost(server: McpServer): void {
  server.tool(
    'spear_post',
    'Post-process LLM output through output gate. Checks for canary leaks, PII exposure, n-gram similarity to system prompt, and encoded data exfiltration.',
    inputSchema,
    async ({ output, canary, systemPrompt, sessionId, userId }) => {
      try {
        const result = await getRuntime().post(
          { output, canary, systemPrompt },
          { sessionId, userId },
        );
        return jsonResponse(result);
      } catch (err) {
        return errorResponse(err instanceof Error ? err.message : String(err));
      }
    },
  );
}
