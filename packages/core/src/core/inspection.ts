import { sanitize } from './unicode.js';

// Confusable Latin lookalikes, applied only to tokens that also contain Latin.
// Do not transliterate ordinary Cyrillic/Greek words or rewrite user messages.
const LOOKALIKES: Record<string, string> = {
  а: 'a', А: 'A', е: 'e', Е: 'E', о: 'o', О: 'O', р: 'p', Р: 'P',
  с: 'c', С: 'C', у: 'y', У: 'Y', х: 'x', Х: 'X', і: 'i', І: 'I',
  ј: 'j', Ј: 'J', ѕ: 's', Ѕ: 'S', ο: 'o', Ο: 'O', ρ: 'p', Ρ: 'P',
  ν: 'v', ʏ: 'y',
};

/** Build bounded inspection views without changing the text delivered to the app. */
export function inspectionViews(content: string): string[] {
  if (content.length > 100_000) throw new Error('Input exceeds inspection limit');
  const views = new Set<string>([content]);
  const escaped = content.replace(/\\u([0-9a-f]{4})/gi, (_, hex: string) =>
    String.fromCharCode(parseInt(hex, 16)));
  const clean = sanitize(escaped);
  const folded = clean.replace(/[\p{L}\p{N}]+/gu, token => {
    if (!/[a-z]/i.test(token)) return token;
    return [...token].map(char => LOOKALIKES[char] ?? char).join('')
      .replace(/[01345]/g, char => ({ '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's' })[char] ?? char);
  });
  views.add(folded);
  views.add(folded.replace(/(?:\b[a-z]\s+){2,}[a-z]\b/gi, match => match.replace(/\s/g, ''))
    .replace(/<\/?([a-z]+)>/gi, ' $1 ').replace(/\s+/g, ' '));
  if (/[\u202A-\u202E\u2066-\u2069]/.test(escaped)) {
    views.add([...folded].reverse().join(''));
  }
  if (/\brot13\b/i.test(clean)) {
    views.add(folded.replace(/[a-z]/gi, char => String.fromCharCode(
      char.charCodeAt(0) + (char.toLowerCase() <= 'm' ? 13 : -13))));
  }
  if (/\bbase64\b/i.test(clean)) {
    // One decoding layer, bounded token size and count; never execute decoded text.
    const tokens = clean.match(/\b[A-Za-z0-9+/]{16,4096}={0,2}/g) ?? [];
    if (tokens.length > 16) throw new Error('Too many encoded input segments');
    for (const token of tokens) {
      try {
        const decoded = new TextDecoder('utf-8', { fatal: true }).decode(
          Uint8Array.from(atob(token), char => char.charCodeAt(0)));
        views.add(sanitize(decoded));
      } catch { /* Non-Base64 words and non-UTF8 data remain in the original view. */ }
    }
  }
  return [...views];
}
