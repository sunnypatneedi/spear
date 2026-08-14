/**
 * Unicode normalization and sanitization utilities for SPEAR
 * 
 * Handles NFKC normalization, Bidi character stripping, and zero-width character removal
 * to prevent obfuscation attacks via Unicode exploits.
 */

/**
 * Bidi override characters that can be used for text direction manipulation
 * U+202A-U+202E: LRE, RLE, PDF, LRO, RLO
 * U+2066-U+2069: LRI, RLI, FSI, PDI
 */
const BIDI_CHARS = /[\u202A-\u202E\u2066-\u2069]/g;

/**
 * Zero-width characters that can hide malicious content
 * U+200B: Zero Width Space
 * U+200C: Zero Width Non-Joiner
 * U+200D: Zero Width Joiner
 * U+FEFF: Zero Width No-Break Space (BOM)
 */
const ZERO_WIDTH_CHARS = /[\u200B-\u200D\uFEFF]/g;

/**
 * Normalize text using NFKC (Normalization Form KC)
 * 
 * NFKC applies compatibility decomposition followed by canonical composition.
 * This helps detect attacks that use visually similar Unicode characters.
 * 
 * @param text Input text to normalize
 * @returns Normalized text
 */
export function normalize(text: string): string {
  if (!text) return text;
  return text.normalize('NFKC');
}

/**
 * Strip bidirectional text control characters
 * 
 * These characters can be used to hide malicious content by changing
 * text direction or creating misleading visual representations.
 * 
 * @param text Input text
 * @returns Text with Bidi characters removed
 */
export function stripBidi(text: string): string {
  if (!text) return text;
  return text.replace(BIDI_CHARS, '');
}

/**
 * Remove zero-width characters
 * 
 * Zero-width characters are invisible and can be used to hide content
 * or bypass pattern matching.
 * 
 * @param text Input text
 * @returns Text with zero-width characters removed
 */
export function stripZeroWidth(text: string): string {
  if (!text) return text;
  return text.replace(ZERO_WIDTH_CHARS, '');
}

/**
 * Decode HTML entities so encoded attacks cannot bypass regex gates.
 *
 * Handles numeric (`&#115;`, `&#x73;`) and a small named-entity set.
 * Must run *before* NFKC so `&#115;ystem` becomes `system` for pattern matching.
 *
 * @param text Input text
 */
export function decodeHtmlEntities(text: string): string {
  if (!text) return text;

  const fromCode = (n: number): string => {
    if (!Number.isFinite(n) || n < 0 || n > 0x10ffff) return '';
    try {
      return String.fromCodePoint(n);
    } catch {
      return '';
    }
  };

  let result = text.replace(/&#x([0-9a-fA-F]{1,6});/g, (_m, hex: string) =>
    fromCode(parseInt(hex, 16))
  );
  result = result.replace(/&#(\d{1,7});/g, (_m, dec: string) =>
    fromCode(parseInt(dec, 10))
  );
  result = result.replace(/&lt;/g, '<');
  result = result.replace(/&gt;/g, '>');
  result = result.replace(/&quot;/g, '"');
  result = result.replace(/&apos;/g, "'");
  result = result.replace(/&nbsp;/g, ' ');
  result = result.replace(/&amp;/g, '&');
  return result;
}

/**
 * Apply all sanitization steps: HTML-entity decode, NFKC, Bidi strip, zero-width removal
 *
 * This is the recommended function to use for all user input processing.
 *
 * @param text Input text
 * @returns Fully sanitized text
 *
 * @example
 * ```typescript
 * const userInput = "Hello\u202EWorld"; // Contains Bidi override
 * const clean = sanitize(userInput);   // "HelloWorld"
 * ```
 */
export function sanitize(text: string): string {
  if (!text) return text;

  // 1. Decode HTML entities (otherwise `&#115;ystem` bypasses every regex)
  // 2. NFKC normalization to handle compatibility characters
  // 3. Strip Bidi control characters
  // 4. Remove zero-width characters
  let result = decodeHtmlEntities(text);
  result = normalize(result);
  result = stripBidi(result);
  result = stripZeroWidth(result);

  return result;
}

/**
 * Check if text contains any suspicious Unicode characters
 *
 * @param text Input text
 * @returns True if suspicious characters detected
 */
export function hasSuspiciousUnicode(text: string): boolean {
  if (!text) return false;
  // IMPORTANT: Do NOT use BIDI_CHARS or ZERO_WIDTH_CHARS here.
  // Those module-level regexes carry the /g flag (required for .replace()).
  // Calling .test() on a /g regex advances lastIndex, so alternating calls
  // on matching text return true, false, true, false... — a silent bypass.
  // Use fresh inline literals (no /g) so every call starts from index 0.
  return /[\u202A-\u202E\u2066-\u2069]/.test(text) ||
         /[\u200B-\u200D\uFEFF]/.test(text);
}

