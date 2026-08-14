import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getSession } from '../state.js';
import { jsonResponse, errorResponse } from '../helpers.js';

const inputSchema = {
  sessionId: z.string(),
  toolCalls: z.array(z.object({
    name: z.string(),
    arguments: z.record(z.unknown()),
    id: z.string().optional(),
  })),
};

export function registerSessionTools(server: McpServer): void {
  server.tool(
    'spear_session_tools',
    'Batch-check parallel tool calls within an active session. Returns allowed and blocked subsets with RBAC, capability, and emergent composition enforcement.',
    inputSchema,
    async ({ sessionId, toolCalls }) => {
      try {
        const session = getSession(sessionId);
        if (!session) {
          return errorResponse(`Session "${sessionId}" not found. Call spear_session_start first.`);
        }
        const result = await session.tools(toolCalls);
        return jsonResponse({
          allowed: result.allowed.map(r => ({ allowed: r.allowed, reason: r.reason })),
          blocked: result.blocked.map(r => ({ allowed: r.allowed, reason: r.reason })),
          total: result.total,
          emergent: result.emergent,
        });
      } catch (err) {
        return errorResponse(err instanceof Error ? err.message : String(err));
      }
    },
  );
}
