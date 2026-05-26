# @hexora/domain-guard

Detect **phishing domains** before users connect their wallet.

[![npm version](https://img.shields.io/npm/v/@hexora/domain-guard?color=6efaee&labelColor=060809)](https://www.npmjs.com/package/@hexora/domain-guard)
[![license](https://img.shields.io/npm/l/@hexora/domain-guard?color=6efaee&labelColor=060809)](https://github.com/DaniilSapielkin01/Hexora/blob/main/LICENSE)

---

## The problem

Phishing sites impersonate legitimate Web3 protocols to steal wallet connections and signatures. A single typo or an invisible character change is enough to redirect funds.

| Domain | Attack type | Target |
|---|---|---|
| `uniswap.com` | blacklisted | uniswap.org |
| `uniswаp.org` | homoglyph | Cyrillic 'а' instead of 'a' |
| `un1swap.org` | leet | numeric substitution |
| `app.uniswap.evil.com` | subdomain | subdomain hijacking |
| `NFTWOOD.top` | nft spam | crypto bait + suspicious TLD |

---

## Install

```bash
npm install @hexora/domain-guard
# or install everything
npm install hexora
```

---

## Usage

```ts
import { checkDomain } from "@hexora/domain-guard"

// Basic — offline, instant, no API keys
const result = await checkDomain({
  domain: window.location.hostname,
})

if (result.scam) {
  console.warn(result.reason)      // "blacklisted_domain"
  console.warn(result.riskLevel)   // "critical"
  console.warn(result.matchedLegit) // "uniswap.org"
}
```

### Check on page load

```tsx
useEffect(() => {
  checkDomain({ domain: window.location.hostname }).then((r) => {
    if (r.scam) showPhishingBanner(r)
  })
}, [])
```

### With domain age check

```ts
const result = await checkDomain({
  domain:   "suspicious-new-dapp.io",
  checkAge: true, // uses RDAP — requires network
})
// domains registered < 30 days ago with crypto keywords → flagged
```

### Custom lists

```ts
const result = await checkDomain({
  domain:          "myapp.io",
  customWhitelist: ["myapp.io", "staging.myapp.io"],
  customBlacklist: ["evil-myapp.io"],
})
```

---

## API

### `checkDomain(params): Promise<CheckDomainResult>`

#### Parameters

| Param | Type | Required | Default | Description |
|---|---|---|---|---|
| `domain` | `string` | ✓ | — | URL or bare domain (e.g. `uniswap.org` or `https://app.uniswap.org`) |
| `typosquatThreshold` | `number` | — | `82` | Min similarity score to flag (0–100) |
| `customWhitelist` | `string[]` | — | `[]` | Additional safe domains |
| `customBlacklist` | `string[]` | — | `[]` | Additional blocked domains |
| `checkAge` | `boolean` | — | `false` | Enable RDAP domain age check |

#### Result

```ts
{
  scam:        boolean
  reason:      "blacklisted_domain" | "typosquat" | "homoglyph" | "subdomain_hijack" |
               "idn_suspicious" | "nft_spam_domain" | "suspicious_domain" |
               "suspicious_tld_combo" | "new_domain" | null
  riskLevel:   "none" | "low" | "medium" | "high" | "critical"
  confidence:  number   // 0–100
  matchedLegit: string | null  // closest legitimate domain found
  details: {
    hasHomoglyph:     boolean
    heuristicSignals: string[]
    domainAge: {
      checked:   boolean
      ageInDays: number | null
      registrar: string | null
    }
  }
  error: { code: string; message: string } | null
}
```

---

## Detection layers

All 9 layers run on every check. No external API calls required by default.

| # | Layer | How it works |
|---|---|---|
| 1 | **Blacklist** | Exact match against 35+ confirmed phishing domains |
| 2 | **Whitelist** | 120+ safe Web3 domains bypass all further checks |
| 3 | **Homoglyph** | Detects Cyrillic, Greek, and Unicode lookalike characters |
| 4 | **Leet substitution** | Catches `0`, `1`, `3` replacing `o`, `l`, `e` |
| 5 | **IDN / Punycode** | Detects encoded international domain attacks |
| 6 | **Subdomain hijack** | Parses domain hierarchy to find real registered domain |
| 7 | **Typosquatting** | SLD-weighted similarity (0.9 SLD + 0.1 TLD) against 120+ legit domains — catches `uniswap.com` vs `uniswap.org` that a flat Levenshtein misses |
| 8 | **NFT spam heuristics** | Crypto bait keywords + suspicious TLD combos |
| 9 | **Domain age (RDAP)** | Optional — flags domains < 30 days old |

---

## Coverage

- **9** detection layers
- **120+** whitelisted legitimate Web3 domains
- **35+** blacklisted confirmed phishing domains
- **8,000+** typosquat variants covered automatically
- **22** suspicious TLDs tracked
- **0** required API keys

---

## Platform support

React · Next.js · Vue · Svelte · Angular · React Native · Browser Extensions · Node.js · Vanilla JS

---

## License

MIT · [GitHub](https://github.com/DaniilSapielkin01/Hexora)
