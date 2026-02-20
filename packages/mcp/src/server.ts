import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { registerPre } from './tools/pre.js';
import { registerPost } from './tools/post.js';
import { registerMediateTool } from './tools/mediate-tool.js';
import { registerSessionStart } from './tools/session-start.js';
import { registerSessionStep } from './tools/session-step.js';
import { registerSessionTools } from './tools/session-tools.js';
import { registerSessionComplete } from './tools/session-complete.js';
import { registerDetectPII } from './tools/detect-pii.js';
import { registerSanitizeText } from './tools/sanitize-text.js';
import { registerTelemetry } from './tools/telemetry.js';
import { registerPolicyResources } from './resources/policies.js';

export function createMcpServer(): McpServer {
  const server = new McpServer({
    name: 'spear-security',
    version: '0.1.0',
  });

  // Runtime tools
  registerPre(server);
  registerPost(server);
  registerMediateTool(server);

  // Session tools
  registerSessionStart(server);
  registerSessionStep(server);
  registerSessionTools(server);
  registerSessionComplete(server);

  // Utility tools
  registerDetectPII(server);
  registerSanitizeText(server);
  registerTelemetry(server);

  // Resources
  registerPolicyResources(server);

  return server;
}
