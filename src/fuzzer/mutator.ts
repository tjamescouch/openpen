/**
 * Payload mutation strategies - encoding, case variation, null bytes
 */

export type MutationStrategy = 'url-encode' | 'double-encode' | 'unicode' | 'case-swap' | 'null-byte' | 'concat';

/**
 * Apply a set of mutations to a payload, returning all variants
 */
export function mutatePayload(payload: string, strategies?: MutationStrategy[]): string[] {
  const strats = strategies || ['url-encode', 'double-encode', 'case-swap', 'null-byte'];
  const results: string[] = [payload]; // always include original

  for (const s of strats) {
    const mutated = applyMutation(payload, s);
    if (mutated !== payload) {
      results.push(mutated);
    }
  }

  return results;
}

function applyMutation(payload: string, strategy: MutationStrategy): string {
  switch (strategy) {
    case 'url-encode':
      return urlEncode(payload);
    case 'double-encode':
      return urlEncode(urlEncode(payload));
    case 'unicode':
      return unicodeEscape(payload);
    case 'case-swap':
      return caseSwap(payload);
    case 'null-byte':
      return payload + '%00';
    case 'concat':
      return concatSplit(payload);
  }
}

function urlEncode(s: string): string {
  return encodeURIComponent(s);
}

function unicodeEscape(s: string): string {
  return s.replace(/[<>'"/\\]/g, ch => {
    const code = ch.charCodeAt(0);
    return `\\u${code.toString(16).padStart(4, '0')}`;
  });
}

function caseSwap(s: string): string {
  return s.replace(/[a-zA-Z]/g, ch => {
    return ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase();
  });
}

function concatSplit(s: string): string {
  // Split strings at midpoint with concat operator
  if (s.length < 4) return s;
  const mid = Math.floor(s.length / 2);
  return s.slice(0, mid) + "'+'" + s.slice(mid);
}
