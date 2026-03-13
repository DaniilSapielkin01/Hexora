// Weighted similarity: prefix 40% + suffix 40% + levenshtein 20%
// Mirrors attacker strategy: same first/last chars, different middle.

export function normalizeAddress(address: string): string {
  return address.toLowerCase();
}

export function calculateSimilarity(a: string, b: string): number {
  const na = normalizeAddress(a);
  const nb = normalizeAddress(b);
  if (na === nb) return 100;
  const bodyA = na.startsWith("0x") ? na.slice(2) : na;
  const bodyB = nb.startsWith("0x") ? nb.slice(2) : nb;
  return Math.round(
    prefixSimilarity(bodyA, bodyB, 6) * 0.4 +
      suffixSimilarity(bodyA, bodyB, 6) * 0.4 +
      levenshteinSimilarity(bodyA, bodyB) * 0.2
  );
}

function prefixSimilarity(a: string, b: string, len: number): number {
  const pa = a.slice(0, len);
  const pb = b.slice(0, len);
  let m = 0;
  for (let i = 0; i < Math.min(pa.length, pb.length); i++) {
    const ca = pa[i];
    const cb = pb[i];
    if (ca !== undefined && cb !== undefined && ca === cb) m++;
  }
  return (m / len) * 100;
}

function suffixSimilarity(a: string, b: string, len: number): number {
  const sa = a.slice(-len);
  const sb = b.slice(-len);
  let m = 0;
  for (let i = 0; i < Math.min(sa.length, sb.length); i++) {
    const ca = sa[i];
    const cb = sb[i];
    if (ca !== undefined && cb !== undefined && ca === cb) m++;
  }
  return (m / len) * 100;
}

function levenshteinSimilarity(a: string, b: string): number {
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 100;
  return Math.round((1 - levenshteinDistance(a, b) / maxLen) * 100);
}

function levenshteinDistance(a: string, b: string): number {
  const n = b.length;
  const dp: number[] = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0] ?? 0;
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const temp = dp[j] ?? 0;
      const ai = a[i - 1];
      const bj = b[j - 1];
      dp[j] =
        ai !== undefined && bj !== undefined && ai === bj
          ? prev
          : 1 + Math.min(prev, dp[j] ?? 0, dp[j - 1] ?? 0);
      prev = temp;
    }
  }
  return dp[n] ?? 0;
}

export interface SimilarityMatch {
  address: string;
  similarityScore: number;
  prefixMatch: boolean;
  suffixMatch: boolean;
}

export function findMostSimilar(
  input: string,
  known: string[],
  threshold: number = 85
): SimilarityMatch | null {
  const ni = normalizeAddress(input);
  let best: SimilarityMatch | null = null;

  for (const addr of known) {
    if (normalizeAddress(addr) === ni) continue;
    const score = calculateSimilarity(input, addr);
    if (score >= threshold && (!best || score > best.similarityScore)) {
      const bi = ni.startsWith("0x") ? ni.slice(2) : ni;
      const ba = normalizeAddress(addr).startsWith("0x")
        ? normalizeAddress(addr).slice(2)
        : normalizeAddress(addr);
      best = {
        address: addr,
        similarityScore: score,
        prefixMatch: bi.slice(0, 4) === ba.slice(0, 4),
        suffixMatch: bi.slice(-4) === ba.slice(-4),
      };
    }
  }
  return best;
}
