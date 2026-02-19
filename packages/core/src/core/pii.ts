/**
 * PII (Personally Identifiable Information) detection and masking
 * 
 * Detects and optionally masks sensitive information like emails,
 * phone numbers, and credit cards in LLM outputs.
 */

/**
 * Email regex pattern (basic but covers most cases)
 */
const EMAIL_PATTERN = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;

/**
 * Phone number patterns (US and international formats)
 * Matches: +1-555-123-4567, (555) 123-4567, 555.123.4567, 5551234567
 */
const PHONE_PATTERN = /(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;

/**
 * Credit card pattern (basic Luhn check not included)
 * Matches: 4111-1111-1111-1111, 4111 1111 1111 1111, 4111111111111111
 */
const CREDIT_CARD_PATTERN = /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g;

/**
 * Social Security Number pattern (US)
 * Matches: 123-45-6789, 123 45 6789, 123456789
 */
const SSN_PATTERN = /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g;

/**
 * PII types that can be detected
 */
export type PIIType = 'email' | 'phone' | 'credit_card' | 'ssn';

/**
 * Detection result for a single PII instance
 */
export interface PIIMatch {
  type: PIIType;
  value: string;
  start: number;
  end: number;
}

/**
 * Configuration for PII detection
 */
export interface PIIConfig {
  email?: boolean;
  phone?: boolean;
  credit_card?: boolean;
  ssn?: boolean;
  maskChar?: string;
}

/**
 * Detect all PII instances in text
 * 
 * @param text Text to scan
 * @param config Detection configuration
 * @returns Array of detected PII matches
 * 
 * @example
 * ```typescript
 * const text = "Contact me at john@example.com or 555-1234";
 * const matches = detectPII(text, { email: true, phone: true });
 * // Returns: [{ type: 'email', value: 'john@example.com', ... }, ...]
 * ```
 */
export function detectPII(text: string, config: PIIConfig = {}): PIIMatch[] {
  if (!text) return [];
  
  const matches: PIIMatch[] = [];
  const {
    email = true,
    phone = true,
    credit_card = true,
    ssn = true
  } = config;
  
  // Detect emails
  if (email) {
    const emailMatches = text.matchAll(EMAIL_PATTERN);
    for (const match of emailMatches) {
      if (match.index !== undefined) {
        matches.push({
          type: 'email',
          value: match[0],
          start: match.index,
          end: match.index + match[0].length
        });
      }
    }
  }
  
  // Detect phone numbers
  if (phone) {
    const phoneMatches = text.matchAll(PHONE_PATTERN);
    for (const match of phoneMatches) {
      if (match.index !== undefined) {
        matches.push({
          type: 'phone',
          value: match[0],
          start: match.index,
          end: match.index + match[0].length
        });
      }
    }
  }
  
  // Detect credit cards
  if (credit_card) {
    const ccMatches = text.matchAll(CREDIT_CARD_PATTERN);
    for (const match of ccMatches) {
      if (match.index !== undefined) {
        // Basic validation: should start with 3, 4, 5, or 6
        const digits = match[0].replace(/[-\s]/g, '');
        if (/^[3-6]/.test(digits)) {
          matches.push({
            type: 'credit_card',
            value: match[0],
            start: match.index,
            end: match.index + match[0].length
          });
        }
      }
    }
  }
  
  // Detect SSN
  if (ssn) {
    const ssnMatches = text.matchAll(SSN_PATTERN);
    for (const match of ssnMatches) {
      if (match.index !== undefined) {
        matches.push({
          type: 'ssn',
          value: match[0],
          start: match.index,
          end: match.index + match[0].length
        });
      }
    }
  }
  
  // Sort by position
  matches.sort((a, b) => a.start - b.start);
  
  return matches;
}

/**
 * Check if text contains any PII
 * 
 * @param text Text to check
 * @param config Detection configuration
 * @returns True if PII is detected
 */
export function containsPII(text: string, config: PIIConfig = {}): boolean {
  return detectPII(text, config).length > 0;
}

/**
 * Mask a single value (shows first/last chars, masks middle)
 * 
 * @param value Value to mask
 * @param maskChar Character to use for masking
 * @param visibleChars Number of visible characters at start/end
 * @returns Masked value
 * 
 * @example
 * ```typescript
 * maskValue("john@example.com", "*", 2);
 * // Returns: "jo***********om"
 * ```
 */
export function maskValue(value: string, maskChar: string = '*', visibleChars: number = 2): string {
  if (!value || value.length <= visibleChars * 2) {
    return maskChar.repeat(value.length);
  }
  
  const start = value.substring(0, visibleChars);
  const end = value.substring(value.length - visibleChars);
  const middle = maskChar.repeat(value.length - visibleChars * 2);
  
  return `${start}${middle}${end}`;
}

/**
 * Mask all PII in text
 * 
 * @param text Text to mask
 * @param config Detection and masking configuration
 * @returns Text with PII masked
 * 
 * @example
 * ```typescript
 * const text = "Email me at john@example.com or call 555-1234";
 * const masked = maskPII(text);
 * // Returns: "Email me at jo***********.com or call ***-****"
 * ```
 */
export function maskPII(text: string, config: PIIConfig = {}): string {
  if (!text) return text;
  
  const matches = detectPII(text, config);
  if (matches.length === 0) return text;
  
  const maskChar = config.maskChar || '*';
  let result = '';
  let lastEnd = 0;
  
  for (const match of matches) {
    // Add text before this match
    result += text.substring(lastEnd, match.start);
    
    // Add masked value
    if (match.type === 'credit_card') {
      // For credit cards, show last 4 digits only
      const digits = match.value.replace(/[-\s]/g, '');
      result += maskChar.repeat(12) + digits.slice(-4);
    } else {
      result += maskValue(match.value, maskChar);
    }
    
    lastEnd = match.end;
  }
  
  // Add remaining text
  result += text.substring(lastEnd);
  
  return result;
}

/**
 * Redact PII completely (replace with placeholder)
 * 
 * @param text Text to redact
 * @param config Detection configuration
 * @returns Text with PII redacted
 * 
 * @example
 * ```typescript
 * const text = "Email: john@example.com";
 * const redacted = redactPII(text);
 * // Returns: "Email: [EMAIL REDACTED]"
 * ```
 */
export function redactPII(text: string, config: PIIConfig = {}): string {
  if (!text) return text;
  
  const matches = detectPII(text, config);
  if (matches.length === 0) return text;
  
  let result = '';
  let lastEnd = 0;
  
  for (const match of matches) {
    result += text.substring(lastEnd, match.start);
    
    // Add type-specific placeholder
    switch (match.type) {
      case 'email':
        result += '[EMAIL REDACTED]';
        break;
      case 'phone':
        result += '[PHONE REDACTED]';
        break;
      case 'credit_card':
        result += '[CARD REDACTED]';
        break;
      case 'ssn':
        result += '[SSN REDACTED]';
        break;
    }
    
    lastEnd = match.end;
  }
  
  result += text.substring(lastEnd);
  
  return result;
}

/**
 * Get PII statistics for text
 *
 * @param text Text to analyze
 * @param config Detection configuration
 * @returns Count of each PII type
 */
export function getPIIStats(text: string, config: PIIConfig = {}): Record<PIIType, number> {
  const matches = detectPII(text, config);

  const stats: Record<PIIType, number> = {
    email: 0,
    phone: 0,
    credit_card: 0,
    ssn: 0
  };

  for (const match of matches) {
    stats[match.type]++;
  }

  return stats;
}

// ============================================================================
// PII Tokenization for AI Context (Privacy-Preserving)
// ============================================================================

/**
 * Token types for known entities
 */
export type TokenType =
  | 'CHILD'
  | 'CHILD_2'
  | 'CHILD_3'
  | 'SCHOOL'
  | 'REGION'
  | 'ADDRESS'
  | 'PARENT'
  | 'SIBLING';

/**
 * Known entities that should be tokenized before sending to LLM
 */
export interface KnownEntities {
  childName?: string;
  childNames?: string[];        // Multiple children
  parentName?: string;
  schoolName?: string;
  zipCode?: string;
  city?: string;
  address?: string;
  siblingNames?: string[];
}

/**
 * Result of tokenization
 */
export interface TokenizationResult {
  /** Text with known entities replaced by tokens */
  sanitized: string;
  /** Map of token -> original value for detokenization */
  tokens: Map<string, string>;
  /** Whether any tokenization was performed */
  wasTokenized: boolean;
  /** Count of tokens applied */
  tokenCount: number;
}

/**
 * Escape special regex characters in a string
 */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Convert zip code to broad region (privacy-preserving)
 *
 * @param zipCode Full zip code (e.g., "94105")
 * @returns Broad region description
 */
export function zipToRegion(zipCode: string): string {
  if (!zipCode || zipCode.length < 3) return 'Unknown Region';

  // Use first 3 digits to determine broad region
  const prefix = zipCode.substring(0, 3);
  const prefixNum = parseInt(prefix, 10);

  // Very broad US regions based on zip prefix ranges
  if (prefixNum >= 900 && prefixNum <= 961) return 'California';
  if (prefixNum >= 970 && prefixNum <= 979) return 'Pacific Northwest';
  if (prefixNum >= 800 && prefixNum <= 816) return 'Colorado';
  if (prefixNum >= 750 && prefixNum <= 799) return 'Texas';
  if (prefixNum >= 100 && prefixNum <= 149) return 'New York Area';
  if (prefixNum >= 200 && prefixNum <= 205) return 'Washington DC Area';
  if (prefixNum >= 300 && prefixNum <= 319) return 'Georgia';
  if (prefixNum >= 330 && prefixNum <= 349) return 'Florida';
  if (prefixNum >= 600 && prefixNum <= 629) return 'Illinois';
  if (prefixNum >= 980 && prefixNum <= 994) return 'Washington State';

  // Default to generic region
  return 'United States';
}

/**
 * Tokenize known entities in text for privacy-preserving AI context
 *
 * Replaces known PII (child names, school names, etc.) with tokens like [CHILD], [SCHOOL].
 * Returns a token map that can be used for detokenization after LLM response.
 *
 * Also runs standard PII detection as a fallback for unknown PII.
 *
 * @param text Text to tokenize
 * @param entities Known entities to replace
 * @param options Tokenization options
 * @returns Tokenization result with sanitized text and token map
 *
 * @example
 * ```typescript
 * const result = tokenizePII(
 *   "My daughter Emma is struggling with math at Lincoln Elementary",
 *   { childName: "Emma", schoolName: "Lincoln Elementary" }
 * );
 * // result.sanitized: "My daughter [CHILD] is struggling with math at [SCHOOL]"
 * // result.tokens: Map { "[CHILD]" => "Emma", "[SCHOOL]" => "Lincoln Elementary" }
 * ```
 */
export function tokenizePII(
  text: string,
  entities: KnownEntities,
  options: {
    /** Also detect and redact unknown PII (emails, phones, etc.) */
    redactUnknownPII?: boolean;
    /** Convert zip codes to broad regions instead of redacting */
    convertZipToRegion?: boolean;
  } = {}
): TokenizationResult {
  if (!text) {
    return { sanitized: text, tokens: new Map(), wasTokenized: false, tokenCount: 0 };
  }

  const { redactUnknownPII = true, convertZipToRegion = true } = options;
  const tokens = new Map<string, string>();
  let sanitized = text;
  let tokenCount = 0;

  // Helper to replace entity with token (case-insensitive)
  const replaceEntity = (entity: string | undefined, token: string): void => {
    if (!entity || entity.length < 2) return;

    // Create case-insensitive regex with word boundaries for better matching
    const regex = new RegExp(`\\b${escapeRegex(entity)}\\b`, 'gi');

    if (regex.test(sanitized)) {
      sanitized = sanitized.replace(regex, token);
      tokens.set(token, entity);
      tokenCount++;
    }
  };

  // Tokenize child name(s)
  if (entities.childName) {
    replaceEntity(entities.childName, '[CHILD]');
  }

  if (entities.childNames && entities.childNames.length > 0) {
    entities.childNames.forEach((name, index) => {
      const token = index === 0 ? '[CHILD]' : `[CHILD_${index + 1}]`;
      replaceEntity(name, token);
    });
  }

  // Tokenize parent name
  if (entities.parentName) {
    replaceEntity(entities.parentName, '[PARENT]');
  }

  // Tokenize sibling names
  if (entities.siblingNames && entities.siblingNames.length > 0) {
    entities.siblingNames.forEach((name, index) => {
      const token = index === 0 ? '[SIBLING]' : `[SIBLING_${index + 1}]`;
      replaceEntity(name, token);
    });
  }

  // Tokenize school name
  if (entities.schoolName) {
    replaceEntity(entities.schoolName, '[SCHOOL]');
  }

  // Handle zip code - convert to region or tokenize
  if (entities.zipCode) {
    if (convertZipToRegion) {
      const region = zipToRegion(entities.zipCode);
      const zipRegex = new RegExp(`\\b${escapeRegex(entities.zipCode)}\\b`, 'gi');
      if (zipRegex.test(sanitized)) {
        sanitized = sanitized.replace(zipRegex, region);
        tokens.set('[REGION]', entities.zipCode);
        tokenCount++;
      }
    } else {
      replaceEntity(entities.zipCode, '[ZIP]');
    }
  }

  // Tokenize city (convert to [REGION])
  if (entities.city) {
    replaceEntity(entities.city, '[REGION]');
  }

  // Tokenize full address
  if (entities.address) {
    replaceEntity(entities.address, '[ADDRESS]');
  }

  // Fallback: detect and redact any remaining unknown PII
  if (redactUnknownPII) {
    sanitized = redactPII(sanitized);
  }

  return {
    sanitized,
    tokens,
    wasTokenized: tokenCount > 0,
    tokenCount
  };
}

/**
 * Detokenize text by replacing tokens with original values
 *
 * @param text Text with tokens
 * @param tokens Token map from tokenizePII
 * @returns Text with tokens replaced by original values
 *
 * @example
 * ```typescript
 * const tokens = new Map([["[CHILD]", "Emma"], ["[SCHOOL]", "Lincoln Elementary"]]);
 * const text = "Tell [CHILD] about the science fair at [SCHOOL]";
 * const result = detokenizePII(text, tokens);
 * // result: "Tell Emma about the science fair at Lincoln Elementary"
 * ```
 */
export function detokenizePII(text: string, tokens: Map<string, string>): string {
  if (!text || tokens.size === 0) return text;

  let result = text;

  for (const [token, value] of tokens) {
    // Replace all occurrences of the token
    result = result.split(token).join(value);
  }

  return result;
}

/**
 * Serialize token map for storage/transmission
 */
export function serializeTokens(tokens: Map<string, string>): string {
  return JSON.stringify(Array.from(tokens.entries()));
}

/**
 * Deserialize token map from storage/transmission
 */
export function deserializeTokens(serialized: string): Map<string, string> {
  try {
    const entries = JSON.parse(serialized) as [string, string][];
    return new Map(entries);
  } catch {
    return new Map();
  }
}

