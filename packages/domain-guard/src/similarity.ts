// Domain-specific similarity using Levenshtein distance

// Cap input length: O(m*n) memory + CPU. 256 covers every realistic domain
// while preventing pathological inputs from allocating megabytes.
const MAX_LEN = 256

function levenshtein(a: string, b: string): number {
  if (a.length > MAX_LEN) a = a.slice(0, MAX_LEN)
  if (b.length > MAX_LEN) b = b.slice(0, MAX_LEN)
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

// Calculate similarity score 0–100 between two domain strings.
// Weighted: SLD dominates (0.9), TLD is a tiebreaker (0.1).
// Attackers typically clone the SLD ("uniswap") and only swap the TLD
// ("uniswap.com" vs "uniswap.org") — a flat string distance would score
// those around 70%, missing the obvious squat.
export function domainSimilarity(a: string, b: string): number {
  if (a === b) return 100
  if (!a || !b) return 0
  const [sldA, tldA] = splitSldTld(a)
  const [sldB, tldB] = splitSldTld(b)
  const sldSim = rawSimilarity(sldA, sldB)
  const tldSim = rawSimilarity(tldA, tldB)
  return Math.round(sldSim * 0.9 + tldSim * 0.1)
}

function splitSldTld(d: string): [string, string] {
  const parts = d.split(".")
  if (parts.length < 2) return [parts[0] ?? "", ""]
  return [parts[parts.length - 2] ?? "", parts[parts.length - 1] ?? ""]
}

function rawSimilarity(a: string, b: string): number {
  if (a === b) return 100
  const maxLen = Math.max(a.length, b.length)
  if (maxLen === 0) return 100
  return (1 - levenshtein(a, b) / maxLen) * 100
}

// Find most similar legit domain above threshold.
// Ties broken by shorter domain — prefers the registered form
// ("uniswap.org") over a subdomain entry ("app.uniswap.org") with the
// same similarity score.
export function findMostSimilarLegit(
  input: string,
  legitDomains: readonly string[],
  threshold: number
): { domain: string; score: number } | null {
  let best: { domain: string; score: number } | null = null

  for (const legit of legitDomains) {
    const score = domainSimilarity(input, legit)
    if (score < threshold || score >= 100) continue
    if (!best) {
      best = { domain: legit, score }
      continue
    }
    if (score > best.score) {
      best = { domain: legit, score }
    } else if (score === best.score && legit.length < best.domain.length) {
      best = { domain: legit, score }
    }
  }

  return best
}
