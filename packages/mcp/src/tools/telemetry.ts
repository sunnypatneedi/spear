import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getRuntime } from '../state.js';
import { jsonResponse, errorResponse } from '../helpers.js';

const inputSchema = {
  limit: z.number().int().positive().optional(),
};

export function registerTelemetry(server: McpServer): void {
  server.tool(
    'spear_get_telemetry',
    'Retrieve recent security telemetry events (input/output blocks, tool mediations, capability violations).',
    inputSchema,
    async ({ limit }) => {
      try {
        let events = getRuntime().getTelemetry();
        if (limit) {
          events = events.slice(-limit);
        }
        return jsonResponse(events);
      } catch (err) {
        return errorResponse(err instanceof Error ? err.message : String(err));
      }
    },
  );
}
