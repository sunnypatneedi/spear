import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getRuntime } from '../state.js';
import { jsonResponse, errorResponse } from '../helpers.js';

const inputSchema = {
  toolName: z.string(),
  arguments: z.record(z.unknown()),
  toolCallId: z.string().optional(),
  sessionId: z.string().optional(),
  approvalToken: z.string().optional(),
  outboundRequest: z.object({
    url: z.string(),
    method: z.string().optional(),
    redirect: z.enum(['follow', 'error', 'manual']).optional(),
    headers: z.record(z.union([z.string(), z.number(), z.boolean()])).optional(),
    body: z.unknown().optional(),
  }).optional(),
};

export function registerMediateTool(server: McpServer): void {
  server.tool(
    'spear_mediate_tool',
    'Mediate a tool call through RBAC, call-depth tracking, and CaMeL capability enforcement. Returns whether the tool call is allowed.',
    inputSchema,
    async ({ toolName, arguments: args, toolCallId, sessionId, approvalToken, outboundRequest }) => {
      try {
        const result = await getRuntime().mediateToolCall(
          {
            name: toolName,
            arguments: args,
            id: toolCallId,
            approvalToken,
            outboundRequest,
          },
          sessionId,
        );
        return jsonResponse({
          allowed: result.allowed,
          reason: result.reason,
          capabilityViolations: result.capabilityViolations,
          requiresApproval: result.requiresApproval,
          egressViolations: result.egressViolations,
          payloadViolations: result.payloadViolations,
        });
      } catch (err) {
        return errorResponse(err instanceof Error ? err.message : String(err));
      }
    },
  );
}
