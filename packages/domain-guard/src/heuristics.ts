// Heuristic scoring — catches phishing domains that don't appear in any list
// and aren't typosquats of known domains.
// Each signal adds points. Final score maps to a risk level.

// ── Suspicious TLDs ──────────────────────────────────────────────────────────
// Free or extremely cheap TLDs heavily abused by phishing campaigns
export const SUSPICIOUS_TLDS = new Set([
  // Free TLDs
  "tk", "ml", "ga", "cf", "gq",
  // Ultra-cheap, favorite for crypto scams
  "top", "vip", "la", "icu", "xyz", "click", "surf",
  "buzz", "rest", "cam", "cyou", "fun",
  // Crypto-bait TLDs
  "finance", "exchange", "trade", "investments",
])

// Legitimate Web3 projects that use some of these TLDs
// Prevents false positives on known safe sites
const LEGIT_EXCEPTIONS = new Set([
  "curve.fi",
  "1inch.io",
  "gmx.io",
  "dydx.exchange",
  "velodrome.finance",
  "stargate.finance",
  "hop.exchange",
])

// ── Suspicious keywords in domain name ───────────────────────────────────────
// Words that almost never appear in legit Web3 domains
// but are very common in phishing / scam sites

// High-risk words — strong signal of scam (15–20 pts each)
const HIGH_RISK_KEYWORDS = [
  "airdrop", "claim", "voucher", "bonus",
  "reward", "giveaway", "free-nft", "freemint",
  "nft-drop", "token-sale", "presale-claim",
  "connect-wallet", "verify-wallet", "wallet-verify",
  "secure-login", "login-secure",
]

// Medium-risk words — weak signal alone, strong in combination (8–12 pts each)
const MEDIUM_RISK_KEYWORDS = [
  "nft", "mint", "drop", "stake", "defi",
  "swap", "bridge", "yield", "farm", "earn",
  "official", "secure", "login", "verify", "connect",
  "wallet", "support", "help", "portal",
  // Crypto token names used as bait
  "shib", "pepe", "doge", "floki", "bonk",
  "usdt", "usdc", "usd", "wbtc", "weth",
]

// ── NFT spam domain patterns ──────────────────────────────────────────────────
// Domains like SHIBAR.la, SHIBOS.vip, NFTWOOD.top
// Pattern: short crypto-sounding name + suspicious TLD
// These don't typosquat anything — they're pure bait domains

// Crypto-adjacent suffixes/prefixes used in bait domain names
const CRYPTO_BAIT_PATTERNS = [
  // Known crypto token prefixes: SHIB*, DOGE*, PEPE*, BTC*, ETH*, XRP*, SOL*
  /^(nft|shib|doge|pepe|floki|bonk|ape|punk|moon|safe|btc|eth|xrp|sol|bnb|avax|matic)[a-z]{0,8}\./i,
  // Crypto suffix patterns: *swap, *fi, *dao, *pad, *nft, *art, *coin
  /^[a-z]{3,8}(nft|coin|swap|fi|dao|pad|drop|art|inu|verse|chain)\./i,
  // High-risk action words anywhere in domain
  /\b(voucher|bonus|airdrop|claim|reward|gift|mint|drop)\b/i,
  // Short random-looking word (4-6 chars) + suspicious TLD — XRPAR.top, SHIBOS.vip
  // No vowels or very few = likely random/generated name
  /^[bcdfghjklmnpqrstvwxyz]{4,7}\./i,
]

// Words that indicate crypto bait even without known token name
const CRYPTO_BAIT_WORDS = new Set([
  "inu", "verse", "fi", "dao", "pad", "labs", "protocol",
  "finance", "network", "chain", "token", "coin",
])

// ── Scoring ───────────────────────────────────────────────────────────────────

export interface HeuristicResult {
  score:        number        // 0–100 accumulated risk score
  signals:      string[]      // human-readable list of triggered signals
  tldSuspicious: boolean
  hasHighRiskKeyword: boolean
  hasMediumRiskKeyword: boolean
  isCryptoBaitPattern: boolean
}

export function runHeuristics(domain: string, registeredDomain: string): HeuristicResult {
  const signals: string[] = []
  let score = 0

  // Skip if domain is a known legit exception
  if (LEGIT_EXCEPTIONS.has(domain) || LEGIT_EXCEPTIONS.has(registeredDomain)) {
    return { score: 0, signals: [], tldSuspicious: false,
      hasHighRiskKeyword: false, hasMediumRiskKeyword: false, isCryptoBaitPattern: false }
  }

  const parts   = domain.split(".")
  const tld     = parts[parts.length - 1] ?? ""
  const sld     = parts[parts.length - 2] ?? ""   // second-level domain
  const fullStr = domain.toLowerCase()

  // ── 1. Suspicious TLD ──────────────────────────────────────────────────────
  const tldSuspicious = SUSPICIOUS_TLDS.has(tld)
  if (tldSuspicious) {
    score += 15
    signals.push(`suspicious TLD: .${tld}`)
  }

  // ── 2. High-risk keywords ─────────────────────────────────────────────────
  let hasHighRiskKeyword = false
  for (const kw of HIGH_RISK_KEYWORDS) {
    if (fullStr.includes(kw)) {
      hasHighRiskKeyword = true
      score += 20
      signals.push(`high-risk keyword: "${kw}"`)
      break // one match is enough for max score
    }
  }

  // ── 3. Medium-risk keywords ───────────────────────────────────────────────
  let hasMediumRiskKeyword = false
  let mediumMatches = 0
  for (const kw of MEDIUM_RISK_KEYWORDS) {
    if (fullStr.includes(kw)) {
      hasMediumRiskKeyword = true
      mediumMatches++
    }
  }
  if (mediumMatches > 0) {
    const pts = Math.min(mediumMatches * 10, 25) // cap at 25
    score += pts
    signals.push(`medium-risk keywords (${mediumMatches}): +${pts}pts`)
  }

  // ── 4. NFT/crypto bait domain pattern ─────────────────────────────────────
  // SHIBAR.la, NFTWOOD.top, SHIBOS.vip, XRPAR.top
  let isCryptoBaitPattern = false
  for (const pattern of CRYPTO_BAIT_PATTERNS) {
    if (pattern.test(domain) || pattern.test(sld)) {
      isCryptoBaitPattern = true
      score += 18
      signals.push(`crypto bait domain pattern: "${sld}"`)
      break
    }
  }

  // Short SLD + suspicious TLD + contains crypto bait word → extra signal
  if (!isCryptoBaitPattern && tldSuspicious && sld.length <= 8) {
    for (const word of CRYPTO_BAIT_WORDS) {
      if (sld.includes(word)) {
        isCryptoBaitPattern = true
        score += 14
        signals.push(`crypto bait word in short domain: "${word}"`)
        break
      }
    }
  }

  // ── 5. Combo amplifier ────────────────────────────────────────────────────
  // If multiple medium signals fire together — they amplify each other
  const activeSignals = [tldSuspicious, hasHighRiskKeyword, hasMediumRiskKeyword, isCryptoBaitPattern]
    .filter(Boolean).length

  if (activeSignals >= 3) {
    score += 15
    signals.push(`combo amplifier: ${activeSignals} signals active`)
  } else if (activeSignals === 2) {
    score += 8
    signals.push(`combo amplifier: ${activeSignals} signals active`)
  }

  // ── 6. Domain length suspicion ────────────────────────────────────────────
  if (sld.length > 24) {
    score += 8
    signals.push(`unusually long domain: ${sld.length} chars`)
  }

  // ── 7. Multiple hyphens (keyword stuffing) ────────────────────────────────
  const hyphens = (sld.match(/-/g) ?? []).length
  if (hyphens >= 2) {
    score += 10
    signals.push(`multiple hyphens: ${hyphens}`)
  }

  return {
    score: Math.min(score, 100),
    signals,
    tldSuspicious,
    hasHighRiskKeyword,
    hasMediumRiskKeyword,
    isCryptoBaitPattern,
  }
}

// Map heuristic score to reason string
export function heuristicReason(result: HeuristicResult): string {
  if (result.isCryptoBaitPattern || result.hasHighRiskKeyword) return "nft_spam_domain"
  if (result.tldSuspicious && result.hasMediumRiskKeyword)     return "suspicious_tld_combo"
  return "suspicious_domain"
}
