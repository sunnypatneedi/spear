/**
 * Local (in-process) similarity for system-prompt exfiltration.
 *
 * Tier 1: TF-IDF cosine + 4-gram Jaccard. Zero extra dependencies.
 * Catches same-language paraphrases; the Python sidecar remains opt-in
 * for cross-lingual cases when `similarity.local_first` is true.
 */

/**
 * Tokenize into lowercase alphanumeric words.
 */
export function tokenizeWords(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter(t => t.length > 0);
}

/**
 * Character n-grams (default 4) over a normalized string.
 */
export function charNgrams(text: string, n = 4): string[] {
  const normalized = text.toLowerCase().replace(/\s+/g, ' ').trim();
  if (normalized.length < n) return normalized ? [normalized] : [];
  const grams: string[] = [];
  for (let i = 0; i <= normalized.length - n; i++) {
    grams.push(normalized.slice(i, i + n));
  }
  return grams;
}

function termFrequency(tokens: string[]): Map<string, number> {
  const tf = new Map<string, number>();
  for (const t of tokens) {
    tf.set(t, (tf.get(t) ?? 0) + 1);
  }
  return tf;
}

function cosine(a: Map<string, number>, b: Map<string, number>): number {
  let dot = 0;
  let magA = 0;
  let magB = 0;
  for (const [, v] of a) magA += v * v;
  for (const [, v] of b) magB += v * v;
  if (magA === 0 || magB === 0) return 0;
  for (const [k, va] of a) {
    const vb = b.get(k);
    if (vb) dot += va * vb;
  }
  return dot / (Math.sqrt(magA) * Math.sqrt(magB));
}

/**
 * TF-IDF-ish cosine: IDF is approximated as 1 / (1 + df) over the two docs.
 *
 * @param a First text
 * @param b Second text
 */
export function tfidfCosine(a: string, b: string): number {
  const ta = tokenizeWords(a);
  const tb = tokenizeWords(b);
  const fa = termFrequency(ta);
  const fb = termFrequency(tb);
  const vocab = new Set([...fa.keys(), ...fb.keys()]);
  const wa = new Map<string, number>();
  const wb = new Map<string, number>();
  for (const term of vocab) {
    const df = (fa.has(term) ? 1 : 0) + (fb.has(term) ? 1 : 0);
    const idf = Math.log(1 + 2 / df);
    wa.set(term, (fa.get(term) ?? 0) * idf);
    wb.set(term, (fb.get(term) ?? 0) * idf);
  }
  return cosine(wa, wb);
}

/**
 * Jaccard overlap of character n-grams.
 *
 * @param a First text
 * @param b Second text
 * @param n Gram length
 */
export function ngramJaccard(a: string, b: string, n = 4): number {
  const ga = new Set(charNgrams(a, n));
  const gb = new Set(charNgrams(b, n));
  if (ga.size === 0 || gb.size === 0) return 0;
  let inter = 0;
  for (const g of ga) {
    if (gb.has(g)) inter++;
  }
  return inter / (ga.size + gb.size - inter);
}

/**
 * Combined local similarity in [0, 1]. Takes the max of TF-IDF cosine
 * and 4-gram Jaccard so either signal is enough to trip the gate.
 *
 * @param output LLM output
 * @param reference System prompt (or other sensitive reference)
 */
export function localSimilarity(output: string, reference: string): number {
  if (!output || !reference) return 0;
  const cosineScore = tfidfCosine(output, reference);
  const jaccard = ngramJaccard(output, reference, 4);
  return Math.max(cosineScore, jaccard);
}
