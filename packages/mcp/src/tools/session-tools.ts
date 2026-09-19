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
    approvalToken: z.string().optional(),
    outboundRequest: z.object({
      url: z.string(),
      method: z.string().optional(),
      redirect: z.enum(['follow', 'error', 'manual']).optional(),
      headers: z.record(z.union([z.string(), z.number(), z.boolean()])).optional(),
      body: z.unknown().optional(),
    }).optional(),
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
          allowed: result.allowed.map(r => ({
            allowed: r.allowed,
            reason: r.reason,
            requiresApproval: r.requiresApproval,
            egressViolations: r.egressViolations,
            payloadViolations: r.payloadViolations,
          })),
          blocked: result.blocked.map(r => ({
            allowed: r.allowed,
            reason: r.reason,
            requiresApproval: r.requiresApproval,
            egressViolations: r.egressViolations,
            payloadViolations: r.payloadViolations,
          })),
          total: result.total,
          emergent: result.emergent,
        });
      } catch (err) {
        return errorResponse(err instanceof Error ? err.message : String(err));
      }
    },
  );
}
