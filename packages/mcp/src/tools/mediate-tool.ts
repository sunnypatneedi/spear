import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getRuntime } from '../state.js';
import { jsonResponse, errorResponse } from '../helpers.js';

const inputSchema = {
  toolName: z.string(),
  arguments: z.record(z.unknown()),
  toolCallId: z.string().optional(),
  sessionId: z.string().optional(),
};

export function registerMediateTool(server: McpServer): void {
  server.tool(
    'spear_mediate_tool',
    'Mediate a tool call through RBAC, call-depth tracking, and CaMeL capability enforcement. Returns whether the tool call is allowed.',
    inputSchema,
    async ({ toolName, arguments: args, toolCallId, sessionId }) => {
      try {
        const result = await getRuntime().mediateToolCall(
          { name: toolName, arguments: args, id: toolCallId },
          sessionId,
        );
        return jsonResponse({
          allowed: result.allowed,
          reason: result.reason,
          capabilityViolations: result.capabilityViolations,
        });
      } catch (err) {
        return errorResponse(err instanceof Error ? err.message : String(err));
      }
    },
  );
}
