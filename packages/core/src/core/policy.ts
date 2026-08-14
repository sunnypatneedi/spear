/**
 * Policy configuration loader and validator
 *
 * Loads YAML policy files and validates them against a Zod schema.
 * Supports environment variable interpolation in policy values.
 *
 * Extended with CaMeL-inspired provenance policy for capability enforcement.
 */

import { z } from 'zod';
import * as yaml from 'yaml';
import { provenancePolicySchema } from './provenance.js';
import { emergentPolicySchema } from './emergent.js';

/**
 * Similarity detection configuration
 */
const similaritySchema = z.object({
  enabled: z.boolean().default(true),
  threshold: z.number().min(0).max(1).default(0.70),
  /** Run in-process TF-IDF/Jaccard first; call the sidecar only if local is below threshold. */
  local_first: z.boolean().default(true)
}).default({ enabled: true, threshold: 0.70, local_first: true });

/**
 * Canary token configuration
 */
const canarySchema = z.object({
  enabled: z.boolean().default(true),
  token_len: z.number().int().min(8).max(32).default(16)
}).default({ enabled: true, token_len: 16 });

/**
 * Input validation rules
 */
const inputRulesSchema = z.object({
  strip_bidi: z.boolean().default(true),
  regex_block: z.array(z.string()).default([])
}).default({ strip_bidi: true, regex_block: [] });

/**
 * Output validation rules
 */
const outputRulesSchema = z.object({
  deny_ngrams: z.array(z.string()).default([]),
  pii: z.object({
    email: z.boolean().default(true),
    phone: z.boolean().default(true),
    credit_card: z.boolean().default(true),
    ssn: z.boolean().default(false)
  }).default({ email: true, phone: true, credit_card: true, ssn: false })
}).default({ deny_ngrams: [], pii: { email: true, phone: true, credit_card: true, ssn: false } });

/**
 * Tool/agent RBAC configuration
 */
const toolsSchema = z.object({
  rbac: z.object({
    allow: z.array(z.string()).default([]),
    deny: z.array(z.string()).default([]),
    max_calls: z.number().int().positive().default(3),
    max_depth: z.number().int().positive().default(2)
  }).default({ allow: [], deny: [], max_calls: 3, max_depth: 2 })
}).default({ rbac: { allow: [], deny: [], max_calls: 3, max_depth: 2 } });

/**
 * Telemetry and attack pattern discovery configuration
 *
 * Enables continuous improvement of SPEAR through:
 * - Attack telemetry collection (anonymized)
 * - Anomaly detection for new attack patterns
 * - Automated pattern discovery pipeline
 */
const telemetrySchema = z.object({
  /** Enable telemetry collection */
  enabled: z.boolean().default(true),

  /** Sampling rate for blocked requests (0.0-1.0) */
  sample_rate: z.number().min(0).max(1).default(0.1),

  /** Time window for anomaly aggregation (hours) */
  aggregation_window_hours: z.number().int().positive().default(24),

  /** Anomaly detection settings */
  anomaly_detection: z.object({
    /** Enable anomaly detection */
    enabled: z.boolean().default(true),

    /** Alert when attack rate exceeds baseline by this factor */
    spike_threshold: z.number().positive().default(3.0),

    /** Minimum attacks to trigger anomaly (prevents noise) */
    min_attack_count: z.number().int().positive().default(10),

    /** Alert when same user triggers multiple attack patterns */
    pattern_diversity_threshold: z.number().int().positive().default(5)
  }).default({
    enabled: true,
    spike_threshold: 3.0,
    min_attack_count: 10,
    pattern_diversity_threshold: 5
  }),

  /** Fields to include in telemetry (for privacy) */
  include_fields: z.object({
    /** Include matched pattern name */
    pattern_name: z.boolean().default(true),

    /** Include risk score */
    risk_score: z.boolean().default(true),

    /** Include truncated/hashed input (for pattern discovery) */
    input_hash: z.boolean().default(true),

    /** Include session context (anonymized) */
    session_context: z.boolean().default(false),

    /** Include user agent */
    user_agent: z.boolean().default(false)
  }).default({
    pattern_name: true,
    risk_score: true,
    input_hash: true,
    session_context: false,
    user_agent: false
  })
}).default({
  enabled: true,
  sample_rate: 0.1,
  aggregation_window_hours: 24,
  anomaly_detection: {
    enabled: true,
    spike_threshold: 3.0,
    min_attack_count: 10,
    pattern_diversity_threshold: 5
  },
  include_fields: {
    pattern_name: true,
    risk_score: true,
    input_hash: true,
    session_context: false,
    user_agent: false
  }
});

/**
 * Sliding-window rate limit / token budget (DoS and noisy-neighbor control)
 */
const rateLimitSchema = z.object({
  enabled: z.boolean().default(false),
  requests_per_window: z.number().int().positive().default(60),
  window_seconds: z.number().int().positive().default(60),
  token_budget: z.number().int().positive().default(100000),
  per_user: z.object({
    requests_per_window: z.number().int().positive().default(20),
    window_seconds: z.number().int().positive().default(60)
  }).default({ requests_per_window: 20, window_seconds: 60 })
}).default({
  enabled: false,
  requests_per_window: 60,
  window_seconds: 60,
  token_budget: 100000,
  per_user: { requests_per_window: 20, window_seconds: 60 }
});

/**
 * Community attack-pattern registry (client). Disabled until an operator sets a URL.
 */
const registrySchema = z.object({
  enabled: z.boolean().default(false),
  contribute: z.boolean().default(false),
  url: z.string().optional()
}).default({
  enabled: false,
  contribute: false
});

/**
 * Complete policy schema
 *
 * Extended with CaMeL-inspired provenance policy for data flow tracking
 * and capability-based security enforcement.
 */
export const policySchema = z.object({
  similarity: similaritySchema,
  canary: canarySchema,
  input_rules: inputRulesSchema,
  output_rules: outputRulesSchema,
  tools: toolsSchema,
  mode: z.enum(['shadow', 'enforce']).default('shadow'),
  latency_budget_ms: z.number().int().positive().default(350),
  sidecar_budget_ms: z.number().int().positive().default(30),
  refusal_phrases: z.array(z.string()).default([
    "I can't share internal instructions or system prompts."
  ]),

  /**
   * CaMeL-inspired provenance and capability policy
   *
   * Controls data flow tracking and capability-based security:
   * - enabled: Turn on provenance tracking
   * - mode: 'shadow' logs violations, 'enforce' blocks them
   * - toolRequirements: Tool-specific capability requirements
   * - defaultToolSelectionMinLevel: Minimum trust for tool selection
   */
  provenance: provenancePolicySchema,

  /**
   * Emergent agent defense — session-level compositions that no single
   * gate can see (collect-then-exfiltrate, dangerous tool sequences,
   * mid-loop goal hijack, split canary exfil).
   */
  emergent: emergentPolicySchema,

  /**
   * Sliding-window rate limiting and per-session token budget.
   */
  rate_limit: rateLimitSchema,

  /**
   * Optional community pattern registry (hash-only contribution).
   */
  registry: registrySchema,

  /**
   * Telemetry and attack pattern discovery
   *
   * Enables continuous improvement through:
   * - Attack telemetry collection (privacy-preserving)
   * - Anomaly detection for emerging attack patterns
   * - Automated pattern discovery for evolving threats
   */
  telemetry: telemetrySchema
});

/**
 * Inferred TypeScript type from policy schema
 */
export type Policy = z.infer<typeof policySchema>;

/**
 * Interpolate environment variables in policy values
 * 
 * Supports syntax: ${VAR_NAME|default_value}
 * 
 * @param value Value to interpolate
 * @returns Interpolated value
 * 
 * @example
 * ```typescript
 * // Environment: SPEAR_MODE=enforce
 * interpolateEnvVars("${SPEAR_MODE|shadow}"); // Returns: "enforce"
 * interpolateEnvVars("${UNKNOWN|shadow}");    // Returns: "shadow"
 * ```
 */
function interpolateEnvVars(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  
  // Pattern: ${VAR_NAME|default}
  const pattern = /\$\{([^|]+)\|([^}]+)\}/g;
  
  return value.replace(pattern, (match, varName, defaultValue) => {
    const envValue =
      typeof process !== 'undefined' && process.env
        ? process.env[varName.trim()]
        : undefined;
    return envValue !== undefined ? envValue : defaultValue.trim();
  });
}

/**
 * Recursively interpolate env vars in an object
 * 
 * @param obj Object to process
 * @returns Object with interpolated values
 */
function interpolateObject(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;
  
  if (Array.isArray(obj)) {
    return obj.map(item => interpolateObject(item));
  }
  
  if (typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = interpolateObject(value);
    }
    return result;
  }
  
  return interpolateEnvVars(obj);
}

/**
 * Load policy from YAML string
 * 
 * @param yamlContent YAML content as string
 * @returns Validated policy object
 * @throws Error if parsing or validation fails
 */
export function loadPolicyFromString(yamlContent: string): Policy {
  try {
    const raw = yaml.parse(yamlContent);
    const interpolated = interpolateObject(raw);
    const validated = policySchema.parse(interpolated);
    return validated;
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to parse policy: ${error.message}`);
    }
    throw error;
  }
}

/**
 * Validate a policy object without loading from file
 * 
 * @param policyObj Raw policy object to validate
 * @returns Validated policy object
 * @throws Error if validation fails
 */
export function validatePolicy(policyObj: unknown): Policy {
  return policySchema.parse(policyObj);
}

/**
 * Get default policy (balanced mode)
 * 
 * @returns Default policy object
 */
export function getDefaultPolicy(): Policy {
  return policySchema.parse({});
}

/**
 * Merge two policies (second overrides first)
 *
 * @param base Base policy
 * @param override Override policy
 * @returns Merged policy
 */
export function mergePolicy(base: Policy, override: Partial<Policy>): Policy {
  const merged = {
    ...base,
    ...override,
    similarity: { ...base.similarity, ...override.similarity },
    canary: { ...base.canary, ...override.canary },
    input_rules: {
      ...base.input_rules,
      ...override.input_rules,
      regex_block: override.input_rules?.regex_block
        ? [
            ...base.input_rules.regex_block,
            ...override.input_rules.regex_block.filter(
              p => !base.input_rules.regex_block.includes(p)
            ),
          ]
        : base.input_rules.regex_block,
    },
    output_rules: { ...base.output_rules, ...override.output_rules },
    tools: {
      rbac: {
        ...base.tools.rbac,
        ...override.tools?.rbac
      }
    },
    provenance: {
      ...base.provenance,
      ...override.provenance,
      // Merge tool requirements arrays
      toolRequirements: [
        ...(base.provenance?.toolRequirements || []),
        ...(override.provenance?.toolRequirements || [])
      ]
    },
    emergent: {
      ...base.emergent,
      ...override.emergent,
      dangerous_sequences:
        override.emergent?.dangerous_sequences ?? base.emergent?.dangerous_sequences,
    },
    rate_limit: {
      ...base.rate_limit,
      ...override.rate_limit,
      per_user: {
        ...base.rate_limit?.per_user,
        ...override.rate_limit?.per_user,
      },
    },
    registry: {
      ...base.registry,
      ...override.registry,
    },
    telemetry: {
      ...base.telemetry,
      ...override.telemetry,
      anomaly_detection: {
        ...base.telemetry?.anomaly_detection,
        ...override.telemetry?.anomaly_detection
      },
      include_fields: {
        ...base.telemetry?.include_fields,
        ...override.telemetry?.include_fields
      }
    }
  };

  return policySchema.parse(merged);
}

