import { describe, it, expect, beforeAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createMcpServer } from '../src/server.js';

let client: Client;

beforeAll(async () => {
  const server = createMcpServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: 'test-client', version: '1.0.0' });
  await client.connect(clientTransport);
});

describe('server registration', () => {
  it('registers all 10 tools', async () => {
    const { tools } = await client.listTools();
    const toolNames = tools.map(t => t.name).sort();
    expect(toolNames).toEqual([
      'spear_detect_pii',
      'spear_get_telemetry',
      'spear_mediate_tool',
      'spear_post',
      'spear_pre',
      'spear_sanitize_text',
      'spear_session_complete',
      'spear_session_start',
      'spear_session_step',
      'spear_session_tools',
    ]);
  });

  it('registers policy resources', async () => {
    const { resources } = await client.listResources();
    const uris = resources.map(r => r.uri).sort();
    expect(uris).toContain('spear://policy/balanced');
    expect(uris).toContain('spear://policy/safe');
    expect(uris).toContain('spear://policy/permissive');
    expect(uris).toContain('spear://config');
  });

  it('reads the balanced policy resource', async () => {
    const result = await client.readResource({ uri: 'spear://policy/balanced' });
    const content = result.contents[0];
    expect(content.mimeType).toBe('application/json');
    const policy = JSON.parse(content.text as string);
    expect(policy.mode).toBeDefined();
    expect(policy.canary).toBeDefined();
  });

  it('reads the config resource', async () => {
    const result = await client.readResource({ uri: 'spear://config' });
    const content = result.contents[0];
    const config = JSON.parse(content.text as string);
    expect(config.policy).toBe('balanced');
    expect(config.mode).toBeDefined();
    expect(typeof config.sessionCount).toBe('number');
  });
});
