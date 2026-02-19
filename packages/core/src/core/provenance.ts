/**
 * Data Provenance Module
 *
 * Implements CaMeL-inspired data flow tracking for LLM security.
 *
 * Key concepts from Google's CaMeL paper (arxiv 2503.18813):
 * - Data provenance: Track where data came from (trusted vs untrusted)
 * - Capability-based security: Restrict operations based on provenance
 * - Control flow integrity: Prevent untrusted data from influencing tool selection
 *
 * @version 1.0.0
 * @see https://arxiv.org/abs/2503.18813
 */

import { z } from 'zod';

// ============================================================================
// PROVENANCE TYPES
// ============================================================================

/**
 * Data provenance levels (trust hierarchy)
 *
 * Mirrors CaMeL's distinction between:
 * - P-LLM: Privileged planner (trusted sources)
 * - Q-LLM: Quarantined reader (untrusted sources)
 */
export type ProvenanceLevel =
  | 'system'      // Highest trust: developer-controlled (system prompts, config)
  | 'user'        // Trusted: direct user input (authenticated)
  | 'assistant'   // Moderate: LLM-generated (model output)
  | 'tool'        // Moderate: tool output (depends on tool trust level)
  | 'external'    // Low trust: external data (web scrapes, API responses)
  | 'untrusted';  // Lowest: unknown or adversarial source

/**
 * Provenance trust scores (for numeric comparisons)
 */
export const PROVENANCE_TRUST_SCORES: Record<ProvenanceLevel, number> = {
  system: 1.0,
  user: 0.9,
  assistant: 0.6,
  tool: 0.5,
  external: 0.2,
  untrusted: 0.0,
};

/**
 * Data provenance metadata attached to values
 */
export interface Provenance {
  /** Trust level of the data source */
  level: ProvenanceLevel;

  /** Unique identifier for this provenance chain */
  id: string;

  /** Source description (e.g., "user_input", "web_scrape", "openai_gpt4") */
  source: string;

  /** Timestamp when provenance was assigned */
  timestamp: number;

  /** Parent provenance IDs (for tracking data flow) */
  parents?: string[];

  /** Whether this data has been sanitized/validated */
  sanitized?: boolean;

  /** Optional metadata about the source */
  metadata?: Record<string, unknown>;
}

/**
 * A value with attached provenance
 */
export interface TaggedValue<T = unknown> {
  value: T;
  provenance: Provenance;
}

// ============================================================================
// CAPABILITY TYPES
// ============================================================================

/**
 * Capabilities that can be granted or denied based on provenance
 *
 * Inspired by CaMeL's capability system that restricts what operations
 * can be performed on data based on its origin.
 */
export type Capability =
  | 'tool_select'       // Can influence which tool is called
  | 'tool_arg'          // Can be used as a tool argument
  | 'tool_arg_write'    // Can be used in write/modify operations
  | 'tool_arg_read'     // Can be used in read-only operations
  | 'tool_arg_sensitive'// Can be used for sensitive args (URLs, file paths)
  | 'llm_context'       // Can be included in LLM context
  | 'llm_influence'     // Can influence LLM output generation
  | 'output_include'    // Can be included in final output to user
  | 'persist'           // Can be stored/persisted
  | 'transmit';         // Can be sent to external services

/**
 * Capability matrix: defines which capabilities are allowed for each provenance level
 */
export const DEFAULT_CAPABILITY_MATRIX: Record<ProvenanceLevel, Set<Capability>> = {
  // System data can do everything
  system: new Set([
    'tool_select', 'tool_arg', 'tool_arg_write', 'tool_arg_read', 'tool_arg_sensitive',
    'llm_context', 'llm_influence', 'output_include', 'persist', 'transmit'
  ]),

  // User input is highly trusted
  user: new Set([
    'tool_select', 'tool_arg', 'tool_arg_write', 'tool_arg_read', 'tool_arg_sensitive',
    'llm_context', 'llm_influence', 'output_include', 'persist', 'transmit'
  ]),

  // Assistant output: restricted to read-only operations (tightened for security)
  // Removed 'tool_arg' to prevent assistant output from being used in write operations
  assistant: new Set([
    'tool_arg_read',
    'llm_context', 'output_include', 'persist', 'transmit'
  ]),

  // Tool output is more restricted
  tool: new Set([
    'tool_arg_read',
    'llm_context', 'output_include', 'persist'
  ]),

  // External data is heavily restricted
  external: new Set([
    'llm_context', 'output_include'
  ]),

  // Untrusted data has minimal capabilities
  untrusted: new Set([
    // Untrusted data can only be displayed (after sanitization)
  ])
};

/**
 * Tool-specific capability requirements
 *
 * Defines what capabilities are required for specific tool arguments.
 * This is the "capability declaration" from CaMeL.
 */
export interface ToolCapabilityRequirement {
  /** Tool name or pattern */
  tool: string;

  /** Arguments and their required capabilities */
  arguments: Record<string, {
    required: Capability[];
    description?: string;
  }>;

  /** Minimum provenance level for tool selection */
  minSelectionProvenance?: ProvenanceLevel;
}

// ============================================================================
// PROVENANCE OPERATIONS
// ============================================================================

/**
 * Generate a unique provenance ID
 */
export function generateProvenanceId(): string {
  return `prov_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
}

/**
 * Create a new provenance record
 *
 * @param level Trust level
 * @param source Source description
 * @param options Additional options
 * @returns Provenance record
 *
 * @example
 * ```typescript
 * const prov = createProvenance('user', 'sms_input', { sanitized: true });
 * ```
 */
export function createProvenance(
  level: ProvenanceLevel,
  source: string,
  options: {
    parents?: string[];
    sanitized?: boolean;
    metadata?: Record<string, unknown>;
  } = {}
): Provenance {
  return {
    id: generateProvenanceId(),
    level,
    source,
    timestamp: Date.now(),
    ...options
  };
}

/**
 * Tag a value with provenance
 *
 * @param value The value to tag
 * @param provenance Provenance to attach
 * @returns Tagged value
 *
 * @example
 * ```typescript
 * const userInput = tagValue("Hello", createProvenance('user', 'chat_input'));
 * ```
 */
export function tagValue<T>(value: T, provenance: Provenance): TaggedValue<T> {
  return { value, provenance };
}

/**
 * Tag a value with a simple provenance
 *
 * @param value Value to tag
 * @param level Provenance level
 * @param source Source description
 * @returns Tagged value
 */
export function tag<T>(value: T, level: ProvenanceLevel, source: string): TaggedValue<T> {
  return tagValue(value, createProvenance(level, source));
}

/**
 * Get the trust score for a provenance level
 */
export function getTrustScore(level: ProvenanceLevel): number {
  return PROVENANCE_TRUST_SCORES[level] ?? 0;
}

/**
 * Compare two provenance levels
 *
 * @returns negative if a < b, 0 if equal, positive if a > b
 */
export function compareProvenance(a: ProvenanceLevel, b: ProvenanceLevel): number {
  return getTrustScore(a) - getTrustScore(b);
}

/**
 * Get the minimum (least trusted) of two provenance levels
 */
export function minProvenance(a: ProvenanceLevel, b: ProvenanceLevel): ProvenanceLevel {
  return compareProvenance(a, b) <= 0 ? a : b;
}

/**
 * Compute derived provenance when combining values
 *
 * When data from multiple sources is combined, the result inherits
 * the LOWEST trust level (taint propagation).
 *
 * @param sources Array of provenance records being combined
 * @param operation Description of the combining operation
 * @returns New provenance for the combined value
 */
export function deriveProvenance(
  sources: Provenance[],
  operation: string
): Provenance {
  if (sources.length === 0) {
    return createProvenance('untrusted', operation);
  }

  // Find the minimum trust level
  let minLevel: ProvenanceLevel = 'system';
  for (const source of sources) {
    minLevel = minProvenance(minLevel, source.level);
  }

  return createProvenance(minLevel, operation, {
    parents: sources.map(s => s.id),
    metadata: { operation, sourceCount: sources.length }
  });
}

// ============================================================================
// CAPABILITY CHECKING
// ============================================================================

/**
 * Check if a provenance level has a specific capability
 *
 * @param level Provenance level to check
 * @param capability Capability to check for
 * @param matrix Optional custom capability matrix
 * @returns True if capability is allowed
 */
export function hasCapability(
  level: ProvenanceLevel,
  capability: Capability,
  matrix: Record<ProvenanceLevel, Set<Capability>> = DEFAULT_CAPABILITY_MATRIX
): boolean {
  const capabilities = matrix[level];
  return capabilities?.has(capability) ?? false;
}

/**
 * Check if a tagged value has a specific capability
 */
export function valueHasCapability<T>(
  tagged: TaggedValue<T>,
  capability: Capability,
  matrix?: Record<ProvenanceLevel, Set<Capability>>
): boolean {
  return hasCapability(tagged.provenance.level, capability, matrix);
}

/**
 * Get all capabilities for a provenance level
 */
export function getCapabilities(
  level: ProvenanceLevel,
  matrix: Record<ProvenanceLevel, Set<Capability>> = DEFAULT_CAPABILITY_MATRIX
): Capability[] {
  return Array.from(matrix[level] ?? []);
}

/**
 * Check if provenance meets minimum level requirement
 */
export function meetsMinimumLevel(
  level: ProvenanceLevel,
  minimum: ProvenanceLevel
): boolean {
  return getTrustScore(level) >= getTrustScore(minimum);
}

// ============================================================================
// CAPABILITY ENFORCEMENT
// ============================================================================

/**
 * Result of a capability check
 */
export interface CapabilityCheckResult {
  allowed: boolean;
  reason?: string;
  missingCapabilities?: Capability[];
  provenanceLevel?: ProvenanceLevel;
}

/**
 * Check if a value can be used for tool selection
 *
 * Critical security check: prevents indirect prompt injection where
 * untrusted data influences which tool gets called.
 */
export function canSelectTool(provenance: Provenance): CapabilityCheckResult {
  const allowed = hasCapability(provenance.level, 'tool_select');

  return {
    allowed,
    reason: allowed
      ? undefined
      : `Provenance level '${provenance.level}' cannot influence tool selection`,
    missingCapabilities: allowed ? undefined : ['tool_select'],
    provenanceLevel: provenance.level
  };
}

/**
 * Check if a value can be used as a tool argument
 *
 * @param provenance Value's provenance
 * @param argumentType Type of argument (read, write, sensitive)
 */
export function canUseAsToolArg(
  provenance: Provenance,
  argumentType: 'read' | 'write' | 'sensitive' = 'read'
): CapabilityCheckResult {
  const capabilityMap: Record<string, Capability> = {
    read: 'tool_arg_read',
    write: 'tool_arg_write',
    sensitive: 'tool_arg_sensitive'
  };

  const requiredCap = capabilityMap[argumentType];
  const allowed = hasCapability(provenance.level, requiredCap);

  return {
    allowed,
    reason: allowed
      ? undefined
      : `Provenance level '${provenance.level}' cannot be used for ${argumentType} tool arguments`,
    missingCapabilities: allowed ? undefined : [requiredCap],
    provenanceLevel: provenance.level
  };
}

/**
 * Check multiple capabilities at once
 */
export function checkCapabilities(
  provenance: Provenance,
  required: Capability[]
): CapabilityCheckResult {
  const missing: Capability[] = [];

  for (const cap of required) {
    if (!hasCapability(provenance.level, cap)) {
      missing.push(cap);
    }
  }

  return {
    allowed: missing.length === 0,
    reason: missing.length === 0
      ? undefined
      : `Missing capabilities: ${missing.join(', ')}`,
    missingCapabilities: missing.length === 0 ? undefined : missing,
    provenanceLevel: provenance.level
  };
}

// ============================================================================
// ZOD SCHEMAS FOR POLICY INTEGRATION
// ============================================================================

/**
 * Zod schema for provenance level validation
 */
export const provenanceLevelSchema = z.enum([
  'system', 'user', 'assistant', 'tool', 'external', 'untrusted'
]);

/**
 * Zod schema for capability validation
 */
export const capabilitySchema = z.enum([
  'tool_select', 'tool_arg', 'tool_arg_write', 'tool_arg_read', 'tool_arg_sensitive',
  'llm_context', 'llm_influence', 'output_include', 'persist', 'transmit'
]);

/**
 * Zod schema for tool capability requirements
 */
export const toolCapabilityRequirementSchema = z.object({
  tool: z.string(),
  arguments: z.record(z.object({
    required: z.array(capabilitySchema),
    description: z.string().optional()
  })),
  minSelectionProvenance: provenanceLevelSchema.optional()
});

/**
 * Zod schema for provenance policy configuration
 */
export const provenancePolicySchema = z.object({
  /** Enable provenance tracking (enabled by default for security) */
  enabled: z.boolean().default(true),

  /** Enforcement mode: 'shadow' logs only, 'enforce' blocks */
  mode: z.enum(['shadow', 'enforce']).default('shadow'),

  /** Tool-specific capability requirements */
  toolRequirements: z.array(toolCapabilityRequirementSchema).default([]),

  /** Default minimum provenance for tool selection */
  defaultToolSelectionMinLevel: provenanceLevelSchema.default('user'),

  /** Custom capability matrix overrides */
  capabilityOverrides: z.record(
    provenanceLevelSchema,
    z.array(capabilitySchema)
  ).optional(),

  /** Block tool selection influenced by tool outputs (prevents indirect injection) */
  blockToolChainInfluence: z.boolean().default(true)
}).default({
  enabled: true,
  mode: 'shadow',
  toolRequirements: [],
  defaultToolSelectionMinLevel: 'user',
  blockToolChainInfluence: true
});

export type ProvenancePolicy = z.infer<typeof provenancePolicySchema>;

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Create a capability matrix from policy overrides
 */
export function buildCapabilityMatrix(
  policy?: ProvenancePolicy
): Record<ProvenanceLevel, Set<Capability>> {
  // Start with defaults
  const matrix: Record<ProvenanceLevel, Set<Capability>> = {
    system: new Set(DEFAULT_CAPABILITY_MATRIX.system),
    user: new Set(DEFAULT_CAPABILITY_MATRIX.user),
    assistant: new Set(DEFAULT_CAPABILITY_MATRIX.assistant),
    tool: new Set(DEFAULT_CAPABILITY_MATRIX.tool),
    external: new Set(DEFAULT_CAPABILITY_MATRIX.external),
    untrusted: new Set(DEFAULT_CAPABILITY_MATRIX.untrusted),
  };

  // Apply overrides if provided
  if (policy?.capabilityOverrides) {
    for (const [level, caps] of Object.entries(policy.capabilityOverrides)) {
      matrix[level as ProvenanceLevel] = new Set(caps as Capability[]);
    }
  }

  return matrix;
}

/**
 * Serialize provenance for logging/storage (strips internal IDs)
 */
export function serializeProvenance(provenance: Provenance): Record<string, unknown> {
  return {
    level: provenance.level,
    source: provenance.source,
    sanitized: provenance.sanitized,
    timestamp: new Date(provenance.timestamp).toISOString()
  };
}

/**
 * Create provenance for common sources
 */
export const ProvenanceSource = {
  systemPrompt: () => createProvenance('system', 'system_prompt'),
  userInput: (channel: string = 'web') => createProvenance('user', `user_input_${channel}`, { sanitized: false }),
  sanitizedUserInput: (channel: string = 'web') => createProvenance('user', `user_input_${channel}`, { sanitized: true }),
  llmOutput: (model: string) => createProvenance('assistant', `llm_${model}`),
  toolOutput: (toolName: string) => createProvenance('tool', `tool_${toolName}`),
  webScrape: (domain?: string) => createProvenance('external', domain ? `web_${domain}` : 'web_scrape'),
  apiResponse: (api: string) => createProvenance('external', `api_${api}`),
  untrusted: (source: string = 'unknown') => createProvenance('untrusted', source),
} as const;
