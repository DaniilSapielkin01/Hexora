// Normalize any URL or bare domain into a clean lowercase domain string
// Examples:
//   "https://app.uniswap.org/swap?foo=1" → "app.uniswap.org"
//   "UNISWAP.ORG"                        → "uniswap.org"
//   "uniswap.org/"                       → "uniswap.org"

export function normalizeDomain(input: string): string {
  let s = input.trim().toLowerCase()

  // Add scheme if missing so URL constructor works
  if (!s.startsWith("http://") && !s.startsWith("https://")) {
    s = "https://" + s
  }

  try {
    const url = new URL(s)
    // Remove trailing dot (FQDN style)
    return url.hostname.replace(/\.$/, "")
  } catch {
    // Fallback: strip scheme and path manually
    return s
      .replace(/^https?:\/\//, "")
      .replace(/\/.*$/, "")
      .replace(/\.$/, "")
  }
}

// Extract registered domain (eTLD+1) from full hostname
// Handles common multi-part TLDs: .co.uk, .com.br, .org.au etc.
// For a full PSL implementation use tldts — this covers 99% of Web3 domains
const MULTI_PART_TLDS = new Set([
  "co.uk", "co.jp", "co.in", "co.nz", "co.za", "co.kr",
  "com.br", "com.au", "com.ar", "com.mx", "com.tr",
  "org.uk", "org.au", "net.au", "gov.uk",
])

export function getRegisteredDomain(hostname: string): string {
  const parts = hostname.split(".")
  if (parts.length <= 2) return hostname
  // Check if last two parts form a known multi-part TLD
  const lastTwo = parts.slice(-2).join(".")
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".")
  }
  return parts.slice(-2).join(".")
}

// Count subdomain depth — "app.uniswap.org" → 1, "a.b.uniswap.org" → 2
export function getSubdomainDepth(hostname: string): number {
  const parts = hostname.split(".")
  return Math.max(0, parts.length - 2)
}

// Detect if domain contains homoglyph (lookalike unicode) characters
// Common attack: replace Latin chars with Cyrillic/Greek lookalikes
const LATIN_LOOKALIKES: Record<string, string> = {
  "а": "a",  // Cyrillic а → Latin a
  "е": "e",  // Cyrillic е → Latin e
  "о": "o",  // Cyrillic о → Latin o
  "р": "p",  // Cyrillic р → Latin p
  "с": "c",  // Cyrillic с → Latin c
  "х": "x",  // Cyrillic х → Latin x
  "ν": "v",  // Greek nu → Latin v
  "ω": "w",  // Greek omega → Latin w
  "ɑ": "a",  // Latin alpha → Latin a
  "ƅ": "b",  // Latin b lookalike
  "ı": "i",  // Dotless i → Latin i
  "ⅼ": "l",  // Roman numeral l → Latin l
}

export function hasHomoglyph(domain: string): boolean {
  return Object.keys(LATIN_LOOKALIKES).some((char) => domain.includes(char))
}

// Replace homoglyphs with their Latin equivalents for comparison
export function normalizeHomoglyphs(domain: string): string {
  let result = domain
  for (const [lookalike, latin] of Object.entries(LATIN_LOOKALIKES)) {
    result = result.split(lookalike).join(latin)
  }
  return result
}

// Leet-speak / numeric substitutions used in typosquatting
// e.g. "un1swap.org", "0pensea.io", "3therscan.io"
const LEET_SUBSTITUTIONS: Record<string, string> = {
  "0": "o", "1": "l", "3": "e",
  "4": "a", "5": "s", "7": "t",
  "@": "a", "$": "s",
}

export function hasLeetSubstitution(domain: string): boolean {
  // SLD = label immediately before the TLD, not the leftmost label.
  // For "app.un1swap.org" we want "un1swap", not "app".
  const parts = domain.split(".")
  const sld = parts.length >= 2 ? parts[parts.length - 2] ?? "" : parts[0] ?? ""
  return Object.keys(LEET_SUBSTITUTIONS).some((char) => sld.includes(char))
}

// Normalize leet chars for comparison against legit domains
export function normalizeLeet(domain: string): string {
  let result = domain
  for (const [leet, latin] of Object.entries(LEET_SUBSTITUTIONS)) {
    result = result.split(leet).join(latin)
  }
  return result
}

// Detect IDN (Internationalized Domain Name) — punycode encoded
export function isIDN(domain: string): boolean {
  return domain.includes("xn--") || /[^\x00-\x7F]/.test(domain)
}
