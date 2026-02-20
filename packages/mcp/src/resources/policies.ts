import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { loadPolicy } from '@spear-secure/core';
import { getRuntime, getSessionCount } from '../state.js';

const POLICY_NAMES = ['balanced', 'safe', 'permissive'] as const;

export function registerPolicyResources(server: McpServer): void {
  for (const name of POLICY_NAMES) {
    server.resource(
      `policy-${name}`,
      `spear://policy/${name}`,
      { mimeType: 'application/json', description: `Spear ${name} policy profile` },
      async () => {
        const policy = loadPolicy(`${name}.yaml`);
        return {
          contents: [{
            uri: `spear://policy/${name}`,
            mimeType: 'application/json',
            text: JSON.stringify(policy, null, 2),
          }],
        };
      },
    );
  }

  server.resource(
    'config',
    'spear://config',
    { mimeType: 'application/json', description: 'Active Spear runtime configuration' },
    async () => {
      const runtime = getRuntime();
      const policy = runtime.getPolicy();
      return {
        contents: [{
          uri: 'spear://config',
          mimeType: 'application/json',
          text: JSON.stringify({
            policy: process.env.SPEAR_POLICY || 'balanced',
            mode: policy.mode,
            sidecar: !!process.env.SPEAR_SIDECAR_URL,
            sessionCount: getSessionCount(),
          }, null, 2),
        }],
      };
    },
  );
}
