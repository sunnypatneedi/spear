import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createSession, getSession } from '../state.js';
import { jsonResponse, errorResponse } from '../helpers.js';

const inputSchema = {
  sessionId: z.string(),
  userId: z.string().optional(),
};

export function registerSessionStart(server: McpServer): void {
  server.tool(
    'spear_session_start',
    'Start a new security session for a multi-step agent loop. The session threads canary tokens and accumulates risk scores across all steps.',
    inputSchema,
    async ({ sessionId, userId }) => {
      try {
        if (getSession(sessionId)) {
          return errorResponse(`Session "${sessionId}" already exists`);
        }
        createSession(sessionId, userId);
        return jsonResponse({ sessionId, status: 'created' });
      } catch (err) {
        return errorResponse(err instanceof Error ? err.message : String(err));
      }
    },
  );
}
