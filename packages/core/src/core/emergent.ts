/**
 * Emergent agent defense
 *
 * Detects attacks that no single gate sees because each individual step or
 * tool call looks allowed. Harm arises from composition across a session:
 * collect-then-exfiltrate, dangerous tool sequences, mid-loop goal hijack,
 * split canary exfil, and argument escalation.
 *
 * Designed to run inside SpearSession. Enforcement follows policy.mode
 * (or emergent.mode when set). Shadow mode records findings without blocking.
 */

import { z } from 'zod';
import type { Message } from '../gates/input_gate.js';
import type { ToolCall } from '../gates/tool_mediator.js';
import type { ProvenanceLevel } from './provenance.js';

/**
 * Role a tool plays in an agent loop, used to detect unsafe compositions.
 */
export type ToolRole = 'collect' | 'exfil' | 'execute' | 'write' | 'other';

/**
 * Emergent attack class.
 *
 * - dangerous_sequence: policy-listed collect/exfil (or execute) pair fired
 * - collect_then_exfiltrate: untrusted/external data was observed, then a transmit/execute tool ran
 * - sensitive_then_transmit: secrets/keys/system-prompt material appeared, then a transmit/execute tool ran
 * - goal_hijack: instruction-override language appeared after the session started
 * - split_exfil: canary reconstructed across multiple tool arguments
 * - argument_escalation: the same tool shifted from a benign arg to a sensitive path/secret
 * - risk_ramp: accumulated session risk crossed the configured threshold
 */
export type EmergentFindingClass =
  | 'dangerous_sequence'
  | 'collect_then_exfiltrate'
  | 'sensitive_then_transmit'
  | 'goal_hijack'
  | 'split_exfil'
  | 'argument_escalation'
  | 'risk_ramp';

/**
 * Severity of an emergent finding. Low is observational; medium/high block in enforce mode.
 */
export type EmergentSeverity = 'low' | 'medium' | 'high';

/**
 * A single detected emergent pattern.
 */
export interface EmergentFinding {
  class: EmergentFindingClass;
  severity: EmergentSeverity;
  reason: string;
  evidence: string[];
  riskScore: number;
}

/**
 * One recorded session event used by the analyzer.
 */
export interface EmergentEvent {
  kind: 'step' | 'tool' | 'observe' | 'complete';
  timestamp: number;
  toolName?: string;
  argumentsText?: string;
  /** Concatenated string leaves — used for split-canary reconstruction. */
  stringsBlob?: string;
  riskScore?: number;
  source?: string;
  content?: string;
}

/**
 * Result of an emergent inspection.
 */
export interface EmergentInspectResult {
  allowed: boolean;
  reason?: string;
  findings: EmergentFinding[];
  sessionRisk: number;
}

/**
 * A from→to tool name pair that should be blocked when both fire in one session.
 */
export interface DangerousSequence {
  from: string;
  to: string;
}

/**
 * Default high-confidence compositions. Conservative enough for balanced:
 * file/secret collection followed by email, HTTP, webhook, or shell.
 */
export const DEFAULT_DANGEROUS_SEQUENCES: DangerousSequence[] = [
  { from: 'read_file', to: 'send_email' },
  { from: 'read_file', to: 'send_mail' },
  { from: 'read_file', to: 'http_request' },
  { from: 'read_file', to: 'http_post' },
  { from: 'read_file', to: 'webhook' },
  { from: 'read_file', to: 'shell' },
  { from: 'read_file', to: 'execute' },
  { from: 'cat', to: 'send_email' },
  { from: 'get_file', to: 'send_email' },
  { from: 'get_secret', to: 'send_email' },
  { from: 'get_secret', to: 'http_request' },
  { from: 'get_credentials', to: 'send_email' },
  { from: 'read_env', to: 'http_request' },
  { from: 'download', to: 'execute' },
  { from: 'web_search', to: 'shell' },
];

const dangerousSequenceSchema = z.object({
  from: z.string().min(1),
  to: z.string().min(1),
});

/**
 * Zod schema for the `emergent` policy section.
 */
export const emergentPolicySchema = z.object({
  /** Master switch. When false, the tracker is a no-op. */
  enabled: z.boolean().default(true),

  /**
   * Optional enforcement override. When omitted, the tracker uses the
   * parent policy / runtime mode (shadow | enforce).
   */
  mode: z.enum(['shadow', 'enforce']).optional(),

  /** Explicit from→to tool pairs that are unsafe in combination. */
  dangerous_sequences: z.array(dangerousSequenceSchema).default(DEFAULT_DANGEROUS_SEQUENCES),

  /**
   * Block transmit/execute tools after observe(external|untrusted), even when
   * the pair is not in dangerous_sequences. Off by default (too strict for
   * "search then email me the summary" workflows). Safe profile enables this.
   */
  collect_then_exfiltrate: z.boolean().default(false),

  /** Block transmit/execute after secrets, keys, or system-prompt material appeared. */
  sensitive_then_transmit: z.boolean().default(true),

  /** Detect instruction-override language injected mid-session (tool results, later steps). */
  goal_hijack: z.boolean().default(true),

  /** Detect a session canary reconstructed across multiple tool arguments. */
  split_exfil: z.boolean().default(true),

  /** Detect the same tool shifting from a benign argument to a sensitive path/secret. */
  argument_escalation: z.boolean().default(true),

  /** Session risk score that triggers a risk_ramp finding (0–1). */
  risk_ramp_threshold: z.number().min(0).max(1).default(0.9),
}).default({
  enabled: true,
  dangerous_sequences: DEFAULT_DANGEROUS_SEQUENCES,
  collect_then_exfiltrate: false,
  sensitive_then_transmit: true,
  goal_hijack: true,
  split_exfil: true,
  argument_escalation: true,
  risk_ramp_threshold: 0.9,
});

export type EmergentPolicy = z.infer<typeof emergentPolicySchema>;

const COLLECT_PATTERNS = [
  'read_file', 'cat', 'get_file', 'search', 'web_search', 'browse',
  'scrape', 'download', 'get_secret', 'read_env', 'get_credentials',
  'fetch', 'http_get', 'open_file',
];

const EXFIL_PATTERNS = [
  'send_email', 'send_mail', 'http_post', 'http_put', 'http_request',
  'webhook', 'upload', 'slack', 'notify', 'share', 'smtp', 'post_message',
];

const EXECUTE_PATTERNS = [
  'shell', 'bash', 'exec', 'execute', 'run_code', 'eval', 'python', 'terminal',
];

const WRITE_PATTERNS = [
  'write_file', 'delete_file', 'chmod', 'sql', 'insert', 'update_db',
];

/**
 * Normalize a tool name for comparison (`sendEmail` → `send_email`).
 *
 * @param name Raw tool name from the model or registry
 */
export function normalizeToolName(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[.-]/g, '_')
    .toLowerCase();
}

/**
 * True when `name` equals `pattern` or contains it as a `_`-delimited token.
 *
 * @param name Tool name (raw or normalized)
 * @param pattern Token to match (`read_file`, `send_email`, …)
 */
export function toolNameMatches(name: string, pattern: string): boolean {
  const n = normalizeToolName(name);
  const p = normalizeToolName(pattern);
  if (n === p) return true;
  if (n.startsWith(`${p}_`) || n.endsWith(`_${p}`)) return true;
  return n.includes(`_${p}_`);
}

/**
 * Classify a tool by the role it plays in collect / exfil / execute compositions.
 *
 * @param name Tool name
 */
export function classifyToolRole(name: string): ToolRole {
  if (matchesAnyPattern(name, EXECUTE_PATTERNS)) return 'execute';
  if (matchesAnyPattern(name, EXFIL_PATTERNS)) return 'exfil';
  if (matchesAnyPattern(name, WRITE_PATTERNS)) return 'write';
  if (matchesAnyPattern(name, COLLECT_PATTERNS)) return 'collect';
  return 'other';
}

/**
 * Map an observe() source tag to a provenance level. Unknown sources are untrusted.
 *
 * @param source Source string from `session.observe(..., { source })`
 */
export function sourceToProvenanceLevel(source: string): ProvenanceLevel {
  switch (source) {
    case 'system':
      return 'system';
    case 'user':
      return 'user';
    case 'assistant':
      return 'assistant';
    case 'tool':
      return 'tool';
    case 'external':
      return 'external';
    case 'untrusted':
      return 'untrusted';
    default:
      return 'untrusted';
  }
}

/**
 * True when text looks like secrets, private keys, or system-prompt material.
 *
 * @param text Content to scan
 */
export function containsSensitiveContent(text: string): boolean {
  if (!text) return false;
  if (/(?:^|\/|\b)\.env(?:\b|$)/.test(text)) return true;
  if (/(?:^|\/)id_rsa(?:\b|$)/.test(text)) return true;
  if (/\/etc\/(?:passwd|shadow)/.test(text)) return true;
  if (/(?:aws_)?secret_access_key/.test(text)) return true;
  if (/-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/.test(text)) return true;
  if (/\b(?:api[_-]?key|bearer\s+[a-z0-9._\-]+|password\s*[:=])/i.test(text)) return true;
  if (/\b(?:system|developer|inner)\s+prompt\b/i.test(text)) return true;
  return false;
}

/**
 * True when text tries to override the agent's original objective.
 *
 * @param text Content to scan
 */
export function containsGoalHijack(text: string): boolean {
  if (!text) return false;
  if (/ignore (?:all )?(?:previous|prior|earlier) (?:instructions|commands|rules)/i.test(text)) {
    return true;
  }
  if (/disregard (?:your|the) (?:original|previous) (?:instructions|prompt|rules)/i.test(text)) {
    return true;
  }
  if (/your new (?:task|goal|objective|mission) is/i.test(text)) return true;
  if (/\byou are now\b.{0,60}\b(?:unrestricted|jailbroken|developer mode)\b/i.test(text)) {
    return true;
  }
  if (/\bexfiltrat(?:e|ion)\b/i.test(text)) return true;
  return false;
}

/**
 * Session-scoped analyzer. Record steps/tools/observations, then inspect().
 */
export class EmergentTracker {
  private events: EmergentEvent[] = [];
  private findings: EmergentFinding[] = [];
  private canary: string | undefined;
  private observedUntrusted = false;
  private sawSensitive = false;

  /**
   * @param policy Emergent policy section
   * @param mode Effective enforcement mode (policy.emergent.mode ?? runtime mode)
   */
  constructor(
    private readonly policy: EmergentPolicy,
    private readonly mode: 'shadow' | 'enforce',
  ) {}

  /**
   * Attach the session canary so split-exfil can reconstruct it across tool args.
   *
   * @param canary Session canary token
   */
  setCanary(canary: string): void {
    this.canary = canary;
  }

  /**
   * Record a session.step() and scan later-step messages for goal hijack.
   *
   * @param messages Messages submitted to this step
   * @param riskScore Input-gate risk score for the step
   */
  recordStep(messages: Message[], riskScore: number): EmergentInspectResult {
    if (!this.policy.enabled) return this.passthrough();

    const content = messages.map(m => m.content).join('\n');
    this.events.push({
      kind: 'step',
      timestamp: Date.now(),
      riskScore,
      content,
    });
    this.noteSensitive(content);
    this.analyze();
    return this.inspect();
  }

  /**
   * Record a single tool call and evaluate compositions against prior events.
   *
   * @param toolCall Tool the model wants to invoke
   */
  recordTool(toolCall: ToolCall): EmergentInspectResult {
    if (!this.policy.enabled) return this.passthrough();

    const argumentsText = stringifyValue(toolCall.arguments);
    this.events.push({
      kind: 'tool',
      timestamp: Date.now(),
      toolName: toolCall.name,
      argumentsText,
      stringsBlob: extractStrings(toolCall.arguments),
    });
    this.noteSensitive(argumentsText);
    this.analyze();
    return this.inspect();
  }

  /**
   * Record session.observe() data. External/untrusted sources taint the session
   * for collect-then-exfiltrate. Tool results are also scanned for goal hijack.
   *
   * @param results Observed tool/RAG outputs
   * @param source Provenance source tag
   */
  recordObserve(results: unknown[], source: string): EmergentInspectResult {
    if (!this.policy.enabled) return this.passthrough();

    const content = stringifyValue(results);
    const level = sourceToProvenanceLevel(source);
    if (level === 'external' || level === 'untrusted') {
      this.observedUntrusted = true;
    }
    this.events.push({
      kind: 'observe',
      timestamp: Date.now(),
      source,
      content,
    });
    this.noteSensitive(content);
    this.analyze();
    return this.inspect();
  }

  /**
   * Record session.complete() output (split-exfil / goal hijack on the final text).
   *
   * @param output Final model output
   */
  recordComplete(output: string): EmergentInspectResult {
    if (!this.policy.enabled) return this.passthrough();

    this.events.push({
      kind: 'complete',
      timestamp: Date.now(),
      content: output,
    });
    this.noteSensitive(output);
    this.analyze();
    return this.inspect();
  }

  /**
   * Current findings and allow/block decision without recording a new event.
   */
  inspect(): EmergentInspectResult {
    if (!this.policy.enabled) return this.passthrough();

    const blocking = this.findings.filter(f => f.severity !== 'low');
    const sessionRisk = this.sessionRisk();
    const shouldBlock = this.mode === 'enforce' && blocking.length > 0;
    const top = blocking[0];

    return {
      allowed: !shouldBlock,
      reason: shouldBlock ? top?.reason : undefined,
      findings: [...this.findings],
      sessionRisk,
    };
  }

  /** Recorded events (for tests and telemetry). */
  getEvents(): EmergentEvent[] {
    return [...this.events];
  }

  private passthrough(): EmergentInspectResult {
    return { allowed: true, findings: [], sessionRisk: 0 };
  }

  private sessionRisk(): number {
    let peak = this.eventRisk();
    for (const finding of this.findings) {
      peak = Math.max(peak, finding.riskScore);
    }
    return peak;
  }

  private eventRisk(): number {
    let peak = 0;
    for (const event of this.events) {
      if (typeof event.riskScore === 'number') {
        peak = Math.max(peak, event.riskScore);
      }
    }
    return peak;
  }

  private noteSensitive(text: string): void {
    if (containsSensitiveContent(text)) {
      this.sawSensitive = true;
    }
  }

  private addFinding(finding: EmergentFinding): void {
    const exists = this.findings.some(
      f => f.class === finding.class && f.reason === finding.reason
    );
    if (!exists) {
      this.findings.push(finding);
    }
  }

  private analyze(): void {
    this.detectDangerousSequences();
    this.detectCollectThenExfiltrate();
    this.detectSensitiveThenTransmit();
    this.detectGoalHijack();
    this.detectSplitExfil();
    this.detectArgumentEscalation();
    this.detectRiskRamp();
  }

  private toolEvents(): EmergentEvent[] {
    return this.events.filter(e => e.kind === 'tool' && e.toolName);
  }

  private detectDangerousSequences(): void {
    const tools = this.toolEvents();
    if (tools.length < 2) return;

    for (const seq of this.policy.dangerous_sequences) {
      const fromIdx = tools.findIndex(e => toolNameMatches(e.toolName ?? '', seq.from));
      if (fromIdx < 0) continue;
      const toIdx = tools.findIndex(
        (e, i) => i > fromIdx && toolNameMatches(e.toolName ?? '', seq.to)
      );
      if (toIdx < 0) continue;

      const fromName = tools[fromIdx].toolName ?? seq.from;
      const toName = tools[toIdx].toolName ?? seq.to;
      this.addFinding({
        class: 'dangerous_sequence',
        severity: 'high',
        reason: `Emergent sequence blocked: '${fromName}' then '${toName}'`,
        evidence: [fromName, toName],
        riskScore: 0.95,
      });
    }
  }

  private detectCollectThenExfiltrate(): void {
    if (!this.policy.collect_then_exfiltrate) return;
    if (!this.observedUntrusted) return;

    const last = this.toolEvents().at(-1);
    if (!last?.toolName) return;
    const role = classifyToolRole(last.toolName);
    if (role !== 'exfil' && role !== 'execute') return;

    this.addFinding({
      class: 'collect_then_exfiltrate',
      severity: 'medium',
      reason: `Transmit/execute tool '${last.toolName}' after untrusted/external data was observed`,
      evidence: [last.toolName],
      riskScore: 0.8,
    });
  }

  private detectSensitiveThenTransmit(): void {
    if (!this.policy.sensitive_then_transmit) return;
    if (!this.sawSensitive) return;

    const last = this.toolEvents().at(-1);
    if (!last?.toolName) return;
    const role = classifyToolRole(last.toolName);
    if (role !== 'exfil' && role !== 'execute') return;

    this.addFinding({
      class: 'sensitive_then_transmit',
      severity: 'high',
      reason: `Transmit/execute tool '${last.toolName}' after sensitive material appeared in the session`,
      evidence: [last.toolName],
      riskScore: 0.95,
    });
  }

  private detectGoalHijack(): void {
    if (!this.policy.goal_hijack) return;

    // The first step is the original user request — InputGate handles that.
    // Scan everything after it (follow-up steps, tool args, observed results).
    let skippedFirstStep = false;
    for (const event of this.events) {
      if (event.kind === 'step' && !skippedFirstStep) {
        skippedFirstStep = true;
        continue;
      }
      const text = `${event.content ?? ''} ${event.argumentsText ?? ''}`;
      if (!containsGoalHijack(text)) continue;
      this.addFinding({
        class: 'goal_hijack',
        severity: 'high',
        reason: 'Goal hijack detected: instruction-override language appeared mid-session',
        evidence: [event.kind, event.toolName ?? event.source ?? 'step'].filter(Boolean),
        riskScore: 0.9,
      });
      return;
    }
  }

  private detectSplitExfil(): void {
    if (!this.policy.split_exfil) return;
    if (!this.canary || this.canary.length < 8) return;

    const pieces = this.toolEvents().map(e => e.stringsBlob ?? '');
    if (pieces.length < 2) return;
    if (pieces.some(p => containsCanaryFragment(p, this.canary ?? ''))) return;

    const joined = pieces.join('');
    if (!containsCanaryFragment(joined, this.canary)) return;

    this.addFinding({
      class: 'split_exfil',
      severity: 'high',
      reason: 'Session canary reconstructed across multiple tool arguments',
      evidence: pieces.map((_, i) => `tool[${i}]`),
      riskScore: 1,
    });
  }

  private detectArgumentEscalation(): void {
    if (!this.policy.argument_escalation) return;

    const byTool = new Map<string, EmergentEvent[]>();
    for (const event of this.toolEvents()) {
      const key = normalizeToolName(event.toolName ?? '');
      const list = byTool.get(key) ?? [];
      list.push(event);
      byTool.set(key, list);
    }

    for (const [tool, calls] of byTool) {
      if (calls.length < 2) continue;
      let sawBenign = false;
      for (const call of calls) {
        const text = call.argumentsText ?? '';
        const sensitive = containsSensitiveContent(text) || looksLikeSensitivePath(text);
        if (!sensitive) {
          sawBenign = true;
          continue;
        }
        if (sawBenign) {
          this.addFinding({
            class: 'argument_escalation',
            severity: 'medium',
            reason: `Tool '${tool}' escalated from a benign argument to a sensitive path or secret`,
            evidence: [tool, text.slice(0, 120)],
            riskScore: 0.75,
          });
          break;
        }
      }
    }
  }

  private detectRiskRamp(): void {
    const peak = this.eventRisk();
    if (peak < this.policy.risk_ramp_threshold) return;
    this.addFinding({
      class: 'risk_ramp',
      severity: 'medium',
      reason: `Session risk ${peak.toFixed(2)} exceeded ramp threshold ${this.policy.risk_ramp_threshold}`,
      evidence: [`risk=${peak}`],
      riskScore: peak,
    });
  }
}

function matchesAnyPattern(name: string, patterns: string[]): boolean {
  return patterns.some(pattern => toolNameMatches(name, pattern));
}

function stringifyValue(value: unknown, max = 4000): string {
  if (typeof value === 'string') {
    return value.length > max ? value.slice(0, max) : value;
  }
  if (value === null || value === undefined) return '';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    const encoded = JSON.stringify(value);
    if (!encoded) return '';
    return encoded.length > max ? encoded.slice(0, max) : encoded;
  } catch {
    return '';
  }
}

function extractStrings(value: unknown): string {
  const parts: string[] = [];
  collectStrings(value, parts);
  return parts.join('');
}

function collectStrings(value: unknown, out: string[]): void {
  if (typeof value === 'string') {
    out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectStrings(item, out);
    }
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const nested of Object.values(value as Record<string, unknown>)) {
      collectStrings(nested, out);
    }
  }
}

function containsCanaryFragment(text: string, canary: string): boolean {
  if (!text || !canary) return false;
  return text.toLowerCase().includes(canary.toLowerCase());
}

function looksLikeSensitivePath(text: string): boolean {
  if (!text) return false;
  return /(?:\/etc\/|\/root\/|\.ssh\/|\.aws\/|\/proc\/)/.test(text);
}

/**
 * Create a tracker from policy + effective mode.
 *
 * @param policy Emergent policy section
 * @param mode Effective enforcement mode
 */
export function createEmergentTracker(
  policy: EmergentPolicy,
  mode: 'shadow' | 'enforce',
): EmergentTracker {
  return new EmergentTracker(policy, policy.mode ?? mode);
}
