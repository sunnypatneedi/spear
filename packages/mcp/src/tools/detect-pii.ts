import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { detectPII, maskPII } from '@spear-secure/core';
import { jsonResponse, errorResponse } from '../helpers.js';

const inputSchema = {
  text: z.string(),
  types: z.object({
    email: z.boolean().optional(),
    phone: z.boolean().optional(),
    credit_card: z.boolean().optional(),
    ssn: z.boolean().optional(),
  }).optional(),
  mask: z.boolean().optional(),
};

export function registerDetectPII(server: McpServer): void {
  server.tool(
    'spear_detect_pii',
    'Detect PII (email, phone, credit card, SSN) in text. Optionally mask detected values.',
    inputSchema,
    async ({ text, types, mask }) => {
      try {
        const config = types ?? {};
        const matches = detectPII(text, config);
        const maskedText = mask ? maskPII(text, config) : undefined;
        return jsonResponse({ matches, maskedText, count: matches.length });
      } catch (err) {
        return errorResponse(err instanceof Error ? err.message : String(err));
      }
    },
  );
}
