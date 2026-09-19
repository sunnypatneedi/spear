/**
 * Outbound egress guard for agent tools and HTTP clients.
 *
 * Spear cannot create a kernel-level sandbox from a TypeScript library. This
 * module provides the application-level boundary: validate destinations,
 * prevent common SSRF targets, and stop credentials from being transmitted.
 * For shell/code-execution tools, use the approval gate and a real container or
 * network policy as well.
 */

import type { Policy } from './policy.js';
import type { Provenance } from './provenance.js';
import { scanSecrets, stringifyForInspection } from './secrets.js';

/** A request description suitable for egress inspection. */
export interface OutboundRequest {
  url: string;
  method?: string;
  redirect?: 'follow' | 'error' | 'manual';
  headers?: Record<string, string | number | boolean>;
  body?: unknown;
  provenance?: Provenance;
}

/** Detailed result from an egress inspection. */
export interface EgressCheckResult {
  safe: boolean;
  host?: string;
  method: string;
  violations: string[];
  secretCount: number;
}

const DEFAULT_METADATA_HOSTS = new Set([
  'metadata.google.internal',
  'metadata.google',
  'instance-data.ec2.internal',
  'metadata.azure.internal',
  '100.100.100.200'
]);

const DEFAULT_SUSPICIOUS_HOSTS = new Set([
  'requestbin.com',
  'webhook.site',
  'pastebin.com',
  'transfer.sh',
  'file.io',
  '0x0.st'
]);

/**
 * Inspect an outbound request without performing it.
 *
 * The result is deliberately independent of shadow/enforce mode. Callers can
 * observe violations in shadow mode and reject them in enforce mode.
 */
export function inspectOutboundRequest(
  request: OutboundRequest,
  policy: Policy
): EgressCheckResult {
  const method = (request.method || 'GET').toUpperCase();
  const violations: string[] = [];

  if (!policy.egress.enabled) {
    return { safe: true, method, violations, secretCount: 0 };
  }

  let parsed: URL;
  try {
    if (!request.url || request.url.length > policy.egress.max_url_length) {
      violations.push(`URL exceeds maximum length (${policy.egress.max_url_length})`);
      return { safe: false, method, violations, secretCount: 0 };
    }
    parsed = new URL(request.url);
  } catch {
    return {
      safe: false,
      method,
      violations: ['Outbound URL is invalid'],
      secretCount: 0
    };
  }

  const host = normalizeHost(parsed.hostname);
  const scheme = parsed.protocol.replace(/:$/, '').toLowerCase();

  if (!policy.egress.allow_schemes.includes(scheme)) {
    violations.push(`URL scheme '${scheme}' is not allowed`);
  }

  if (policy.egress.block_credentials_in_url && (parsed.username || parsed.password)) {
    violations.push('Credentials in outbound URL are not allowed');
  }

  if (request.redirect === 'follow' && !policy.egress.allow_redirects) {
    violations.push('Following redirects is disabled for guarded requests');
  }

  if (policy.egress.allowed_hosts.length > 0 &&
      !matchesHostList(host, policy.egress.allowed_hosts)) {
    violations.push(`Destination host '${host}' is not on the egress allowlist`);
  }

  if (matchesHostList(host, policy.egress.denied_hosts)) {
    violations.push(`Destination host '${host}' is explicitly denied`);
  }

  if (policy.egress.block_private_networks && isPrivateHost(host)) {
    violations.push(`Private or loopback destination '${host}' is blocked`);
  }

  if (DEFAULT_METADATA_HOSTS.has(host)) {
    violations.push(`Cloud metadata destination '${host}' is blocked`);
  }

  const suspiciousHosts = new Set([
    ...DEFAULT_SUSPICIOUS_HOSTS,
    ...policy.egress.suspicious_hosts.map(normalizeHost)
  ]);
  if (suspiciousHosts.has(host) || [...suspiciousHosts].some(suffix => host.endsWith(`.${suffix}`))) {
    violations.push(`High-risk dead-drop or capture host '${host}' requires review`);
  }

  let secretCount = 0;
  if (policy.egress.scan_secrets) {
    try {
      const body = request.body;
      if (body !== undefined && body !== null && typeof body !== 'string' &&
          (typeof body !== 'object' ||
           (!Array.isArray(body) && Object.getPrototypeOf(body) !== Object.prototype &&
            Object.getPrototypeOf(body) !== null))) {
        throw new Error('Unsupported outbound body');
      }
      const transmitted = stringifyForInspection({
        url: decodeURIComponent(parsed.href), headers: request.headers, body
      });
      secretCount = scanSecrets(transmitted).matches.length;
      if (secretCount > 0) violations.push(`Outbound request contains ${secretCount} possible secret(s)`);
    } catch {
      violations.push('Outbound payload cannot be fully inspected');
    }
  }

  if (policy.egress.block_untrusted_transmit && request.provenance &&
      !['GET', 'HEAD', 'OPTIONS'].includes(method) &&
      ['tool', 'external', 'untrusted'].includes(request.provenance.level)) {
    violations.push(`Untrusted '${request.provenance.level}' data cannot be transmitted with ${method}`);
  }

  return {
    safe: violations.length === 0,
    host,
    method,
    violations,
    secretCount
  };
}

/**
 * Fetch through the egress boundary.
 *
 * In enforce mode this throws before the network request. In shadow mode it
 * allows the request, so applications can measure impact before rollout.
 */
export async function guardedFetch(
  input: string | URL,
  policy: Policy,
  init: RequestInit = {},
  options: { mode?: 'shadow' | 'enforce'; provenance?: Provenance } = {}
): Promise<Response> {
  const url = typeof input === 'string' ? input : input.toString();
  const headers = headersToRecord(init.headers);
  let body: unknown = init.body;
  if (body instanceof URLSearchParams) body = body.toString();
  else if (body instanceof ArrayBuffer) body = new TextDecoder().decode(body);
  else if (ArrayBuffer.isView(body)) body = new TextDecoder().decode(new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
  else if (typeof Blob !== 'undefined' && body instanceof Blob && body.size <= 100_000) {
    body = await body.text();
  }
  const check = inspectOutboundRequest({
    url,
    method: init.method,
    redirect: init.redirect,
    headers,
    body,
    provenance: options.provenance
  }, policy);

  const mode = options.mode || policy.mode;
  if (!check.safe && mode === 'enforce') {
    throw new Error(`SPEAR blocked outbound request: ${check.violations.join('; ')}`);
  }

  if (typeof fetch !== 'function') {
    throw new Error('Global fetch is unavailable in this runtime');
  }

  return fetch(url, {
    ...init,
    // Avoid redirect-based SSRF unless the policy explicitly opts in.
    redirect: init.redirect || (policy.egress.allow_redirects ? 'follow' : 'error')
  });
}

function headersToRecord(headers: RequestInit['headers']): Record<string, string> {
  if (!headers) return {};
  if (typeof Headers !== 'undefined' && headers instanceof Headers) {
    return Object.fromEntries(headers.entries());
  }
  if (Array.isArray(headers)) {
    return Object.fromEntries(headers);
  }
  return Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key, String(value)])
  );
}

function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}

function matchesHostList(host: string, patterns: string[]): boolean {
  return patterns.some(pattern => {
    const normalized = normalizeHost(pattern);
    return normalized.startsWith('*.')
      ? host === normalized.slice(2) || host.endsWith(`.${normalized.slice(2)}`)
      : host === normalized;
  });
}

function isPrivateHost(host: string): boolean {
  if (host === 'localhost' || host.endsWith('.localhost') || host === '0.0.0.0') return true;

  const ipv4 = parseIPv4(host);
  if (ipv4) {
    const [a, b] = ipv4;
    return a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224;
  }

  if (host.includes(':')) {
    const lower = host.toLowerCase();
    const mappedIPv4 = parseMappedIPv4(lower);
    if (mappedIPv4) {
      return isPrivateHost(mappedIPv4.join('.'));
    }
    return lower === '::1' ||
      lower === '::' ||
      lower.startsWith('fc') ||
      lower.startsWith('fd') ||
      lower.startsWith('fe8') ||
      lower.startsWith('fe9') ||
      lower.startsWith('fea') ||
      lower.startsWith('feb') ||
      lower.startsWith('ff') ||
      lower.includes('::ffff:127.') ||
      lower.includes('::ffff:10.') ||
      lower.includes('::ffff:192.168.');
  }

  return false;
}

function parseIPv4(host: string): [number, number, number, number] | undefined {
  const parts = host.split('.');
  if (parts.length !== 4 || parts.some(part => !/^\d{1,3}$/.test(part))) return undefined;
  const numbers = parts.map(Number);
  if (numbers.some(part => part < 0 || part > 255)) return undefined;
  return numbers as [number, number, number, number];
}

function parseMappedIPv4(host: string): [number, number, number, number] | undefined {
  const match = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (!match) return undefined;
  const high = Number.parseInt(match[1], 16);
  const low = Number.parseInt(match[2], 16);
  return [high >> 8, high & 0xff, low >> 8, low & 0xff];
}
