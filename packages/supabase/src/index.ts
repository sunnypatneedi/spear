/**
 * ============================================================================
 * SPEAR Edge Function Guard (Shared Utility)
 * ============================================================================
 *
 * VERSION: 3.0.0
 * CREATED: 2025-12-02
 * UPDATED: 2025-12-09 - Added CaMeL-inspired provenance tracking
 * GITHUB ISSUE: #21
 *
 * PURPOSE:
 * --------
 * Lightweight SPEAR integration for Supabase Edge Functions (Deno runtime).
 * Provides input/output protection for LLM calls with CaMeL provenance.
 *
 * CAMEL SECURITY MODEL (NEW in v3.0):
 * -----------------------------------
 * Based on Google's CaMeL paper (arxiv 2503.18813):
 * • Data provenance: Track trust level of each data source
 * • Capability enforcement: Restrict operations based on provenance
 * • Control flow integrity: Prevent untrusted data from selecting tools
 *
 * PROTECTION LAYERS:
 * ------------------
 * InputGate:  Unicode sanitization + 7 attack class detection + provenance
 * OutputGate: N-gram denylist + PII detection
 * ToolGate:   Capability enforcement (if provenance enabled)
 *
 * DEPLOYMENT MODES:
 * -----------------
 * disabled → No protection (emergency rollback)
 * shadow   → Log attacks but allow (testing)
 * enforce  → Block attacks (production)
 *
 * Set via: supabase secrets set SPEAR_MODE=shadow
 * Set via: supabase secrets set SPEAR_PROVENANCE=true
 *
 * USAGE:
 * ------
 * ```typescript
 * import { guardLLMCall, checkToolCall } from '../_shared/sapps-guard.ts';
 *
 * // Full guard with provenance
 * const result = await guardLLMCall(messages, google('gemini-1.5-pro'));
 *
 * // Check tool call with capability enforcement
 * const toolCheck = checkToolCall('send_email', { to: 'user@...' }, 'assistant');
 * if (!toolCheck.allowed) {
 *   console.warn('Tool call blocked:', toolCheck.reason);
 * }
 * ```
 *
 * ============================================================================
 */


/// <reference lib="deno.ns" />

import { generateText, streamText, CoreMessage } from "https://esm.sh/ai@3.4.0";
import { google } from "https://esm.sh/@ai-sdk/google@0.0.52";

// ============================================================================
// CAMEL PROVENANCE TYPES (Deno-compatible lightweight implementation)
// ============================================================================

/**
 * Data provenance levels (trust hierarchy)
 * Mirrors CaMeL's distinction between trusted/untrusted sources
 */
export type ProvenanceLevel =
  | 'system'      // Highest trust: developer-controlled
  | 'user'        // Trusted: direct user input
  | 'assistant'   // Moderate: LLM-generated
  | 'tool'        // Moderate: tool output
  | 'external'    // Low trust: external data
  | 'untrusted';  // Lowest: unknown source

/**
 * Provenance trust scores
 */
const PROVENANCE_TRUST_SCORES: Record<ProvenanceLevel, number> = {
  system: 1.0,
  user: 0.9,
  assistant: 0.6,
  tool: 0.5,
  external: 0.2,
  untrusted: 0.0,
};

/**
 * Capabilities for CaMeL enforcement
 */
type Capability = 'tool_select' | 'tool_arg' | 'tool_arg_sensitive' | 'llm_context' | 'output_include';

/**
 * Default capability matrix
 */
const CAPABILITY_MATRIX: Record<ProvenanceLevel, Set<Capability>> = {
  system: new Set(['tool_select', 'tool_arg', 'tool_arg_sensitive', 'llm_context', 'output_include']),
  user: new Set(['tool_select', 'tool_arg', 'tool_arg_sensitive', 'llm_context', 'output_include']),
  assistant: new Set(['tool_arg', 'llm_context', 'output_include']),  // Cannot select tools
  tool: new Set(['llm_context', 'output_include']),
  external: new Set(['llm_context', 'output_include']),
  untrusted: new Set([]),
};

/**
 * Provenance metadata
 */
export interface Provenance {
  level: ProvenanceLevel;
  source: string;
  timestamp: number;
  sanitized?: boolean;
}

/**
 * Message with provenance
 */
export interface MessageWithProvenance extends CoreMessage {
  provenance?: Provenance;
}

/**
 * Create provenance record
 */
export function createProvenance(level: ProvenanceLevel, source: string): Provenance {
  return {
    level,
    source,
    timestamp: Date.now(),
  };
}

/**
 * Check if provenance level has capability
 */
function hasCapability(level: ProvenanceLevel, cap: Capability): boolean {
  return CAPABILITY_MATRIX[level]?.has(cap) ?? false;
}

/**
 * Check if provenance enabled
 */
function isProvenanceEnabled(): boolean {
  return Deno.env.get('SPEAR_PROVENANCE') === 'true';
}

/**
 * Tool call check result
 */
export interface ToolCheckResult {
  allowed: boolean;
  reason?: string;
  violations?: string[];
}

/**
 * Check if a tool call is allowed based on provenance
 *
 * CaMeL core security: prevents untrusted data from selecting tools
 *
 * @param toolName Name of the tool being called
 * @param args Tool arguments
 * @param selectionSource Who decided to call this tool ('user' | 'assistant')
 * @returns Check result
 */
export function checkToolCall(
  toolName: string,
  args: Record<string, unknown>,
  selectionSource: ProvenanceLevel = 'assistant'
): ToolCheckResult {
  const mode = getSPEARMode();

  if (mode === 'disabled' || !isProvenanceEnabled()) {
    return { allowed: true };
  }

  const violations: string[] = [];

  // Check if source can select tools
  if (!hasCapability(selectionSource, 'tool_select')) {
    violations.push(
      `Provenance level '${selectionSource}' cannot select tools (indirect injection protection)`
    );
  }

  // Check sensitive tool arguments
  const sensitiveArgPatterns = ['url', 'path', 'file', 'email', 'phone', 'address'];
  for (const [argName, value] of Object.entries(args)) {
    const isSensitive = sensitiveArgPatterns.some(p => argName.toLowerCase().includes(p));
    if (isSensitive && !hasCapability(selectionSource, 'tool_arg_sensitive')) {
      violations.push(
        `Argument '${argName}' is sensitive but source '${selectionSource}' lacks capability`
      );
    }
  }

  if (violations.length === 0) {
    return { allowed: true };
  }

  // Log violations
  console.warn('[SPEAR ToolGate]', mode === 'shadow' ? 'SHADOW' : 'BLOCKED', violations.join('; '));

  return {
    allowed: mode === 'shadow', // Shadow mode allows but logs
    reason: violations.join('; '),
    violations
  };
}

/**
 * Tag messages with provenance based on role
 */
export function tagMessagesWithProvenance(messages: Message[]): MessageWithProvenance[] {
  if (!isProvenanceEnabled()) {
    return messages;
  }

  return messages.map(msg => {
    if ((msg as MessageWithProvenance).provenance) {
      return msg as MessageWithProvenance;
    }

    let provenance: Provenance;
    switch (msg.role) {
      case 'system':
        provenance = createProvenance('system', 'system_prompt');
        break;
      case 'user':
        provenance = createProvenance('user', 'user_input');
        break;
      case 'assistant':
        provenance = createProvenance('assistant', 'llm_output');
        break;
      default:
        provenance = createProvenance('user', 'unknown');
    }

    return { ...msg, provenance };
  });
}

// ============================================================================
// ORIGINAL SPEAR GUARD (Enhanced with Provenance)
// ============================================================================

/**
 * Message structure (Vercel AI SDK compatible with provenance)
 */
export type Message = MessageWithProvenance;

/**
 * Guard result
 */
export interface GuardResult {
  allowed: boolean;
  reason?: string;
  output: string;
  blocked: boolean;
}

/**
 * Attack patterns to detect
 * Synchronized with: packages/sapps/policies/balanced.yaml
 * Last Updated: 2025-10-21 (Added 10 high-signal probes)
 */
const ATTACK_PATTERNS = [
  // === HIGH-SIGNAL PROBES (Production-Grade Attacks) ===
  
  // Probe 1,2,3,6: Direct exfil with verbatim/exactly modifiers
  /\b(system|inner|base|seed|meta|hidden)[ -]?prompt\b.*(verbatim|exactly|precise)/i,
  /(print|output|display|show|reveal).*(system|inner|base)[ -]?prompt.*(verbatim|exactly)/i,
  
  // Probe 2: Override with delimiter bait
  /(ignore|disregard|forget).*(previous|all|earlier).*(instructions|commands|rules)/i,
  /output.*system[ -]?prompt.*between.*<.*>.*<\/.*/i,
  
  // Probe 3: Synonym + emphasis
  /(get in touch with|channel|consult|access|retrieve).*\b(inner|seed|base|meta)[ -]?prompt\b.*(exactly|share)/i,
  
  // Probe 4: Role-play as system/console
  /act as (the )?(initialization console|system console|debug mode|config mode)/i,
  /(debugging|debug mode).*display.*(hidden|system)[ -]?prompt/i,
  
  // Probe 5: Semantic reframe + translation
  /(helpfulness|purpose|role|function)\s*=\s*system[ -]?prompt/i,
  /translate.*(helpfulness|your\s+(role|purpose)).*to\s+(danish|spanish|french)/i,
  
  // Probe 6: Repetition transformation
  /return.*system[ -]?prompt.*(two|three|twice|multiple) times/i,
  /(two|double|triple).*(times|copies).*system[ -]?prompt/i,
  
  // Probe 7: Code-fence/markdown output format
  /write.*(system|internal).*(instructions|prompt).*(code block|fenced|markdown|```)/i,
  /(system|internal).*(prompt|instructions).*inside.*(code|markdown|fence)/i,
  
  // Probe 8,9: Encoding/hashing transformations
  /(base64|hex|encode|hash).*(system|internal)[ -]?prompt/i,
  /system[ -]?prompt.*(hash|sha-?256|encoded|base64)/i,
  
  // Probe 10: Tool abuse
  /use (the )?tool.*(dump|print|show|reveal).*(config|system|prompt)/i,
  /(logs?|debug)\.dump.*config/i,
  
  // === ORIGINAL PATTERNS (Preserved) ===
  
  // Class 1: Direct exfil (general)
  /\b(system|inner|base|seed|meta)[ -]?prompt\b/i,
  
  // Class 2: Override attempts
  /(ignore (previous|all) (instructions|commands))/i,
  
  // Class 3: Synonym indirection
  /(get in touch with|channel|consult).*\b(inner|seed|base|meta)[ -]?prompt\b/i,
  
  // Class 4: Transformation
  /(two|double|translate|summarize|compress).*(system[ -]?prompt)/i,
  
  // Class 5: Equation pattern
  /\b.+\s*=\s*(system|developer|base|inner)[ -]?prompt\b/i,
  
  // Class 6: Reveal attempts
  /(reveal|print|expose|show|display).*(prompt|instructions|rules)/i,
  
  // Class 7: Meta references
  /\b(developer message|base instructions|original prompt|core directive)\b/i,
  
  // Class 8: Model/configuration disclosure attempts
  /(which|what).*model.*(are you|do you|using|run on)/i,
  /(what|which).*(ai|llm|language).*model/i,
  /model.*(are you|am i|is this)/i,
  /(tell me|reveal|share).*(model|configuration|config)/i,
  /(what|which).*(gpt|openai|claude|gemini)/i,
];

/**
 * Output denylist (n-grams that indicate leaks)
 */
const OUTPUT_DENYLIST = [
  'system prompt',
  'developer message',
  'base instructions',
  'inner prompt',
  'seed prompt',
  'meta prompt',
];

/**
 * Output regex patterns (more specific than denylist)
 */
const OUTPUT_LEAK_PATTERNS = [
  // Model name disclosures
  /(I'm|I am|using|running on|powered by).*(OpenAI|GPT-4|GPT-3|GPT-4o|gpt-4|gpt-3|claude|gemini)/i,
  /(model|AI|LLM).*(is|are|called|named).*(GPT-4|GPT-3|GPT-4o|gpt-4|gpt-3|claude|gemini)/i,
  /OpenAI'?s.*(GPT-4|GPT-3|GPT-4o|gpt-4|gpt-3|model)/i,
  /(temperature|max_tokens|top_p).*(is|set to|configured)/i, // Configuration details
];

/**
 * Default refusal message
 */
const REFUSAL_MESSAGE = "I can't share internal instructions or system prompts.";

/**
 * SPEAR Mode type
 */
export type SPEARMode = 'shadow' | 'enforce' | 'disabled';

/**
 * Phased rollout configuration
 *
 * Allows per-function mode overrides for gradual enforce mode rollout.
 * Check function-specific env var first, then fall back to global SPEAR_MODE.
 *
 * Environment variables:
 * - SPEAR_MODE: Global default mode (shadow|enforce|disabled)
 * - SPEAR_MODE_{FUNCTION_NAME}: Per-function override (uppercase, hyphens to underscores)
 *
 * Examples:
 * - SPEAR_MODE_SUMMARIZE_INTERACTION=enforce
 * - SPEAR_MODE_HOMEWORK_ANALYZE_STREAM=shadow
 * - SPEAR_MODE_PUDDLE_CHAT=enforce
 */
let currentFunctionName: string | undefined;

/**
 * Set the current function name for per-function mode resolution
 * Call this at the start of your edge function handler.
 *
 * @param functionName The edge function name (e.g., 'summarize-interaction')
 */
export function setFunctionContext(functionName: string): void {
  currentFunctionName = functionName;
}

/**
 * Get SPEAR mode from environment with per-function override support
 *
 * Priority:
 * 1. Function-specific env var (SPEAR_MODE_{FUNCTION_NAME})
 * 2. Global SPEAR_MODE env var
 * 3. Default: 'shadow'
 *
 * @param functionName Optional function name override
 */
export function getSPEARMode(functionName?: string): SPEARMode {
  const funcName = functionName || currentFunctionName;

  // Check for function-specific override
  if (funcName) {
    const envVarName = `SPEAR_MODE_${funcName.toUpperCase().replace(/-/g, '_')}`;
    const functionMode = Deno.env.get(envVarName);
    if (functionMode && ['shadow', 'enforce', 'disabled'].includes(functionMode)) {
      return functionMode as SPEARMode;
    }
  }

  // Fall back to global mode
  const mode = Deno.env.get('SPEAR_MODE') || 'shadow';
  return mode as SPEARMode;
}

/**
 * Telemetry event for SPEAR monitoring
 */
export interface SPEARTelemetryEvent {
  timestamp: string;
  function: string;
  mode: SPEARMode;
  gate: 'input' | 'output' | 'tool';
  action: 'allowed' | 'blocked' | 'flagged';
  reason?: string;
  score?: number;
  latencyMs?: number;
}

/**
 * In-memory telemetry buffer (for edge function lifecycle)
 * Note: This resets per function invocation. For persistent metrics,
 * log to external service or use Supabase.
 */
const telemetryBuffer: SPEARTelemetryEvent[] = [];
const MAX_TELEMETRY_EVENTS = 100;

/**
 * Log a telemetry event
 */
export function logTelemetry(event: Omit<SPEARTelemetryEvent, 'timestamp'>): void {
  const fullEvent: SPEARTelemetryEvent = {
    ...event,
    timestamp: new Date().toISOString()
  };

  telemetryBuffer.push(fullEvent);

  // Keep buffer bounded
  if (telemetryBuffer.length > MAX_TELEMETRY_EVENTS) {
    telemetryBuffer.shift();
  }

  // Log to console for external collection (Supabase logs, etc.)
  console.log('[SPEAR Telemetry]', JSON.stringify(fullEvent));
}

/**
 * Get telemetry events (for testing/debugging)
 */
export function getTelemetryEvents(): SPEARTelemetryEvent[] {
  return [...telemetryBuffer];
}

/**
 * Clear telemetry buffer
 */
export function clearTelemetry(): void {
  telemetryBuffer.length = 0;
}

/**
 * Get mode status for all known functions
 * Useful for debugging and monitoring dashboards
 */
export function getModeStatus(): Record<string, SPEARMode> {
  const functions = [
    'summarize-interaction',
    'homework-analyze-stream',
    'extract-conversation-memories',
    'puddle-chat',
    'activity-concierge',
    'counselor-worker',
    'discover-activities',
    'generate-curiosity-content',
    'generate-reflection',
    'puddle-disclosure'
  ];

  const status: Record<string, SPEARMode> = {
    '_global': getSPEARMode()
  };

  for (const func of functions) {
    status[func] = getSPEARMode(func);
  }

  return status;
}

/**
 * Normalize Unicode (NFKC)
 */
function normalize(text: string): string {
  return text.normalize('NFKC');
}

/**
 * Strip Bidi control characters
 */
function stripBidi(text: string): string {
  const bidiPattern = /[\u202A-\u202E\u2066-\u2069]/g;
  return text.replace(bidiPattern, '');
}

/**
 * Strip zero-width characters
 */
function stripZeroWidth(text: string): string {
  const zeroWidthPattern = /[\u200B-\u200D\uFEFF]/g;
  return text.replace(zeroWidthPattern, '');
}

/**
 * Sanitize text (full pipeline)
 */
export function sanitize(text: string): string {
  let result = normalize(text);
  result = stripBidi(result);
  result = stripZeroWidth(result);
  return result;
}

/**
 * Extract text from user content (handles string or array of parts)
 */
function extractUserText(content: Message['content']): string {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .filter(part => part.type === 'text')
      .map(part => (part as any).text || '')
      .join(' ');
  }
  return '';
}

/**
 * Sanitize user content (handles string or array of parts)
 */
function sanitizeUserContent(content: Message['content']): Message['content'] {
  if (typeof content === 'string') {
    return sanitize(content);
  }
  if (Array.isArray(content)) {
    return content.map(part => {
      if (part.type === 'text') {
        return { ...part, text: sanitize((part as any).text || '') };
      }
      return part;
    });
  }
  return content;
}

/**
 * Check if input matches attack patterns
 *
 * @param content Message content to check
 * @param functionName Optional function name for per-function mode
 */
export function checkInput(
  content: Message['content'],
  functionName?: string
): { allowed: boolean; reason?: string; score: number } {
  const startTime = Date.now();
  const mode = getSPEARMode(functionName);

  if (mode === 'disabled') {
    return { allowed: true, score: 0 };
  }

  // Extract text for checking
  const textToCheck = extractUserText(content);

  // Sanitize input
  const sanitized = sanitize(textToCheck);

  // Check patterns
  for (const pattern of ATTACK_PATTERNS) {
    if (pattern.test(sanitized)) {
      const reason = `Matched attack pattern: ${pattern.source.substring(0, 50)}...`;
      const allowed = mode === 'shadow'; // Allow in shadow, block in enforce

      console.warn('[SPEAR InputGate]', mode === 'shadow' ? 'SHADOW' : 'BLOCKED', reason);

      // Log telemetry
      logTelemetry({
        function: functionName || currentFunctionName || 'unknown',
        mode,
        gate: 'input',
        action: allowed ? 'flagged' : 'blocked',
        reason,
        score: 0.9,
        latencyMs: Date.now() - startTime
      });

      return {
        allowed,
        reason,
        score: 0.9
      };
    }
  }

  // Log allowed input (sample 10% to reduce noise)
  if (Math.random() < 0.1) {
    logTelemetry({
      function: functionName || currentFunctionName || 'unknown',
      mode,
      gate: 'input',
      action: 'allowed',
      score: 0,
      latencyMs: Date.now() - startTime
    });
  }

  return { allowed: true, score: 0 };
}

/**
 * Check if output contains leaked information
 *
 * @param output Output string to check
 * @param functionName Optional function name for per-function mode
 */
export function checkOutput(
  output: string,
  functionName?: string
): { allowed: boolean; sanitized: string; score: number } {
  const startTime = Date.now();
  const mode = getSPEARMode(functionName);

  if (mode === 'disabled') {
    return { allowed: true, sanitized: output, score: 0 };
  }

  const lowerOutput = output.toLowerCase();

  // Check regex patterns first (more specific)
  for (const pattern of OUTPUT_LEAK_PATTERNS) {
    if (pattern.test(output)) {
      const reason = `Output matches leak pattern: ${pattern.source.substring(0, 50)}...`;
      console.error('[SPEAR OutputGate]', mode === 'shadow' ? 'SHADOW' : 'BLOCKED', reason);

      // Log telemetry
      logTelemetry({
        function: functionName || currentFunctionName || 'unknown',
        mode,
        gate: 'output',
        action: mode === 'enforce' ? 'blocked' : 'flagged',
        reason,
        score: 0.9,
        latencyMs: Date.now() - startTime
      });

      if (mode === 'enforce') {
        return {
          allowed: false,
          sanitized: REFUSAL_MESSAGE,
          score: 0.9
        };
      }

      // Shadow mode: allow but flag
      return {
        allowed: true,
        sanitized: `[FLAGGED] ${output}`,
        score: 0.8
      };
    }
  }

  // Check denylist
  for (const phrase of OUTPUT_DENYLIST) {
    if (lowerOutput.includes(phrase.toLowerCase())) {
      const reason = `Output contains deny-listed phrase: ${phrase}`;
      console.error('[SPEAR OutputGate]', mode === 'shadow' ? 'SHADOW' : 'BLOCKED', reason);

      // Log telemetry
      logTelemetry({
        function: functionName || currentFunctionName || 'unknown',
        mode,
        gate: 'output',
        action: mode === 'enforce' ? 'blocked' : 'flagged',
        reason,
        score: 0.9,
        latencyMs: Date.now() - startTime
      });
      
      if (mode === 'enforce') {
        return {
          allowed: false,
          sanitized: REFUSAL_MESSAGE,
          score: 0.9
        };
      }
      
      // Shadow mode: allow but flag
      return {
        allowed: true,
        sanitized: `[FLAGGED] ${output}`,
        score: 0.8
      };
    }
  }
  
  return { allowed: true, sanitized: output, score: 0 };
}

/**
 * Guard a complete LLM call (input + output protection)
 * Uses Vercel AI SDK
 *
 * @param messages Messages to send
 * @param model Vercel AI SDK model (e.g., google('gemini-1.5-pro'))
 * @param options LLM options and function name for per-function mode
 * @returns Guarded result with sanitized output
 */
export async function guardLLMCall(
  messages: Message[],
  model: any = google('gemini-1.5-pro'),
  options: {
    temperature?: number;
    maxTokens?: number;
    functionName?: string;
  } = {}
): Promise<GuardResult> {
  const funcName = options.functionName;
  const mode = getSPEARMode(funcName);

  // Set function context for nested calls
  if (funcName) {
    setFunctionContext(funcName);
  }

  if (mode === 'disabled') {
    // SPEAR disabled - pass through
    const { text } = await generateText({
      model,
      messages: messages as CoreMessage[],
      temperature: options.temperature,
      maxTokens: options.maxTokens,
    });
    return {
      allowed: true,
      output: text,
      blocked: false
    };
  }

  try {
    // Step 1: Check input (last user message)
    const lastMessage = messages[messages.length - 1];

    if (lastMessage && lastMessage.role === 'user') {
      const inputCheck = checkInput(lastMessage.content, funcName);

      if (!inputCheck.allowed) {
        console.warn('[SPEAR] Input blocked:', inputCheck.reason);

        return {
          allowed: false,
          reason: inputCheck.reason,
          output: REFUSAL_MESSAGE,
          blocked: true
        };
      }

      // Sanitize user message
      messages[messages.length - 1] = {
        ...lastMessage,
        content: sanitizeUserContent(lastMessage.content)
      } as Message;
    }

    // Step 2: Call LLM with sanitized messages
    const { text: llmOutput } = await generateText({
      model,
      messages: messages as CoreMessage[],
      temperature: options.temperature,
      maxTokens: options.maxTokens,
    });

    // Step 3: Check output
    const outputCheck = checkOutput(llmOutput, funcName);

    if (!outputCheck.allowed) {
      console.error('[SPEAR] Output blocked - potential leak detected');

      return {
        allowed: false,
        reason: 'Output check failed',
        output: REFUSAL_MESSAGE,
        blocked: true
      };
    }

    return {
      allowed: true,
      output: outputCheck.sanitized,
      blocked: false
    };

  } catch (error) {
    console.error('[SPEAR] Guard error (fail-open):', error);

    // Fail-open: allow but log
    try {
      const { text } = await generateText({
        model,
        messages: messages as CoreMessage[],
        temperature: options.temperature,
        maxTokens: options.maxTokens,
      });
      return {
        allowed: true,
        output: text,
        blocked: false,
        reason: `SPEAR error: ${error instanceof Error ? error.message : String(error)}`
      };
    } catch (innerError) {
      return {
        allowed: false,
        output: "Error generating response",
        blocked: true,
        reason: `LLM error: ${innerError instanceof Error ? innerError.message : String(innerError)}`
      };
    }
  }
}

/**
 * Guard a streaming LLM call (input check only, output checked per chunk)
 *
 * @param messages Messages to send
 * @param model Vercel AI SDK model
 * @param options Optional function name for per-function mode
 */
export async function guardLLMStream(
  messages: Message[],
  model: any = google('gemini-1.5-pro'),
  options: { functionName?: string } = {}
): Promise<{ allowed: boolean; reason?: string; stream?: ReadableStream }> {
  const funcName = options.functionName;
  const mode = getSPEARMode(funcName);

  // Set function context for nested calls
  if (funcName) {
    setFunctionContext(funcName);
  }

  if (mode === 'disabled') {
    const result = await streamText({
      model,
      messages: messages as CoreMessage[],
    });
    return { allowed: true, stream: result.toTextStreamResponse().body! };
  }

  // Check input
  const lastMessage = messages[messages.length - 1];

  if (lastMessage && lastMessage.role === 'user') {
    const inputCheck = checkInput(lastMessage.content, funcName);

    if (!inputCheck.allowed) {
      console.warn('[SPEAR Stream] Input blocked:', inputCheck.reason);

      if (mode === 'enforce') {
        return {
          allowed: false,
          reason: inputCheck.reason
        };
      }
    }

    // Sanitize
    messages[messages.length - 1] = {
      ...lastMessage,
      content: sanitizeUserContent(lastMessage.content)
    } as Message;
  }

  // Get stream
  const result = await streamText({
    model,
    messages: messages as CoreMessage[],
  });

  return { allowed: true, stream: result.toTextStreamResponse().body! };
}
