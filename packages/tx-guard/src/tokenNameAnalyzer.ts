// Fake token / suspicious token name detector
// Scammers send tokens with names like:
//   "Visit scam.com to claim $1000"
//   "$ 5000 USDT - claim at evil.xyz"
//   "CONGRATULATIONS! Go to scam.io"
//
// These are fake airdrop tokens designed to lure users to phishing sites
// The token itself is worthless — the scam is the website visit

// URL pattern — domain in token name/symbol
const URL_PATTERN = /https?:\/\/|www\.|[a-z0-9-]{3,}\.(com|io|xyz|net|org|vip|top|la|gg|app|finance)/i

// Action words common in scam token names
const SCAM_ACTION_WORDS = [
  "claim", "visit", "go to", "congratulations", "winner",
  "reward", "airdrop", "bonus", "free", "gift", "earn",
  "connect wallet", "verify", "activate",
]

// Suspicious patterns in token names
const SUSPICIOUS_PATTERNS = [
  /\$\s*\d+/,           // "$1000", "$ 5000"
  /\d+\s*(usdt|eth|bnb|usdc)/i,  // "1000 USDT"
  /[A-Z0-9-]{3,}\.(com|io|xyz|net|org)/i,  // "SCAM.IO"
]

export interface TokenNameRisk {
  detected:   boolean
  confidence: number
  warning:    string | null
  signals:    string[]
}

export function analyzeTokenName(name: string, symbol: string): TokenNameRisk {
  const combined = `${name} ${symbol}`.toLowerCase()
  const signals: string[] = []
  let score = 0

  // ── 1. URL in name ─────────────────────────────────────────────────────────
  if (URL_PATTERN.test(name) || URL_PATTERN.test(symbol)) {
    score += 40
    signals.push("URL found in token name/symbol")
  }

  // ── 2. Action words ────────────────────────────────────────────────────────
  for (const word of SCAM_ACTION_WORDS) {
    if (combined.includes(word)) {
      score += 20
      signals.push(`scam action word: "${word}"`)
      break
    }
  }

  // ── 3. Suspicious patterns ─────────────────────────────────────────────────
  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (pattern.test(name) || pattern.test(symbol)) {
      score += 15
      signals.push(`suspicious pattern in name`)
      break
    }
  }

  // ── 4. Very long token name (real tokens are short) ───────────────────────
  if (name.length > 40) {
    score += 10
    signals.push(`unusually long token name: ${name.length} chars`)
  }

  // ── 5. Token symbol contains special chars ────────────────────────────────
  if (/[^A-Z0-9]/.test(symbol) && symbol.length > 0) {
    score += 8
    signals.push("suspicious characters in token symbol")
  }

  const detected = score >= 35

  return {
    detected,
    confidence: Math.min(score + 10, 95),
    warning: detected
      ? `Suspicious token name detected: "${name}". This appears to be a fake airdrop token designed to lure you to a phishing site. Do not visit any URLs.`
      : null,
    signals,
  }
}

// Check if incoming transaction is a fake token airdrop
// Used when analyzing incoming transactions (value = 0, unknown token)
export function isFakeAirdrop(
  tokenName:   string,
  tokenSymbol: string,
  fromAddress: string,
  value:       bigint
): boolean {
  if (value > 0n) return false  // if token has value, not a fake airdrop
  const risk = analyzeTokenName(tokenName, tokenSymbol)
  return risk.detected
}
