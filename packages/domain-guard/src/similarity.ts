// Domain-specific similarity using Levenshtein distance

function levenshtein(a: string, b: string): number {
  const m = a.length
  const n = b.length
  // Use flat array for performance and to avoid index-signature issues
  const dp = new Array<number>((m + 1) * (n + 1)).fill(0)
  const idx = (i: number, j: number) => i * (n + 1) + j

  for (let i = 0; i <= m; i++) dp[idx(i, 0)] = i
  for (let j = 0; j <= n; j++) dp[idx(0, j)] = j

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[idx(i, j)] = dp[idx(i - 1, j - 1)] ?? 0
      } else {
        dp[idx(i, j)] = 1 + Math.min(
          dp[idx(i - 1, j - 1)] ?? 0,
          dp[idx(i - 1, j)] ?? 0,
          dp[idx(i, j - 1)] ?? 0
        )
      }
    }
  }
  return dp[idx(m, n)] ?? 0
}

// Calculate similarity score 0–100 between two domain strings
export function domainSimilarity(a: string, b: string): number {
  if (a === b) return 100
  const maxLen = Math.max(a.length, b.length)
  if (maxLen === 0) return 100
  const dist = levenshtein(a, b)
  return Math.round((1 - dist / maxLen) * 100)
}

// Find most similar legit domain above threshold
export function findMostSimilarLegit(
  input: string,
  legitDomains: readonly string[],
  threshold: number
): { domain: string; score: number } | null {
  let best: { domain: string; score: number } | null = null

  for (const legit of legitDomains) {
    const score = domainSimilarity(input, legit)
    if (score >= threshold && score < 100) {
      if (!best || score > best.score) {
        best = { domain: legit, score }
      }
    }
  }

  return best
}
