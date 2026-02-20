import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { sanitize, hasSuspiciousUnicode } from '@spear-secure/core';
import { jsonResponse, errorResponse } from '../helpers.js';

const inputSchema = {
  text: z.string(),
};

export function registerSanitizeText(server: McpServer): void {
  server.tool(
    'spear_sanitize_text',
    'Sanitize text by normalizing Unicode (NFKC), stripping bidirectional control characters and zero-width characters. Reports if suspicious characters were found.',
    inputSchema,
    async ({ text }) => {
      try {
        const hadSuspiciousChars = hasSuspiciousUnicode(text);
        const sanitized = sanitize(text);
        return jsonResponse({ sanitized, hadSuspiciousChars });
      } catch (err) {
        return errorResponse(err instanceof Error ? err.message : String(err));
      }
    },
  );
}
