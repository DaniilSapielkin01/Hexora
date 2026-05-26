# hexora

**Web3 Security SDK** — detect address poisoning attacks, phishing domains, and malicious transactions before users lose funds.

[![npm version](https://img.shields.io/npm/v/hexora?color=6efaee&labelColor=060809)](https://www.npmjs.com/package/hexora)
[![npm downloads](https://img.shields.io/npm/dm/hexora?color=6efaee&labelColor=060809)](https://www.npmjs.com/package/hexora)
[![license](https://img.shields.io/npm/l/hexora?color=6efaee&labelColor=060809)](https://github.com/DaniilSapielkin01/Hexora/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-blue?labelColor=060809)](https://www.typescriptlang.org/)

---

## What is Hexora?

Hexora is an open-source security SDK for wallets and dApps. It gives developers a simple API to protect users from the three most common Web3 attack vectors:

📚 Hexora Documentation: https://hexora-docs.vercel.app/

| Package | Protects against | Size |
|---|---|---|
| `@hexora/address-guard` | Address poisoning, native + ERC-20 dust attacks, zero-value transfers | ~3.8 kB |
| `@hexora/domain-guard` | Phishing domains, SLD-weighted typosquat, homoglyph, IDN, subdomain hijack | ~4.5 kB |
| `@hexora/tx-guard` | Malicious approvals, permit drains, delegation abuse, ERC-4337 v0.6/v0.7 | ~14.6 kB |

This package (`hexora`) is the **unified entry point** — it re-exports all three packages so you can install once and use everything.

---

## Install

```bash
npm install hexora
# or individual packages
npm install @hexora/address-guard
npm install @hexora/domain-guard
npm install @hexora/tx-guard
```

---

## Quick Start

Three lines of protection covering the full attack surface:

```ts
import { checkAddress, checkDomain, checkTx } from "hexora"

// 1. When user pastes a recipient address
const addrResult = await checkAddress({
  userAddress:  connectedWallet,
  inputAddress: pastedAddress,
  provider:     window.ethereum,
})
if (addrResult.scam) blockTransaction(addrResult)

// 2. On page load — check the current site
const domainResult = await checkDomain({
  domain: window.location.hostname,
})
if (domainResult.scam) showPhishingWarning(domainResult)

// 3. Before showing "Sign" button
const txResult = await checkTx({
  tx:       pendingTransaction,
  provider: window.ethereum,
})
if (txResult.scam) blockSigning(txResult)
```

---

## @hexora/address-guard

Detects **address poisoning attacks** — a technique where attackers create wallet addresses with the same first and last characters as a legitimate address, then inject them into the victim's transaction history via zero-value transfers.

**Real attack — BNB Chain:**
```
Legit: 0xEF70ef [Af74A3caAbF254E786F834133864] BC80E6
Fake:  0xe7d409 [75DD0396Fc81A39b0ED1f2b7aCE1] BC80E6
                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ different middle, same ends
```

### Detection algorithms

- **Similarity scoring** — weighted prefix (40%) + suffix (40%) + Levenshtein distance (20%)
- **Zero-value transfer detection** — identifies $0 ERC-20 transfers used to poison history
- **Batch poisoning** — detects methodId `0xe19c2253` batch contracts (40 victims in one tx)
- **TransferFrom spoofing** — catches contracts that move tokens without user interaction
- **Dust attack detection** — micro-transactions below economic threshold
- **New suspicious address** — flags addresses with no legitimate history

### Usage

```ts
import { checkAddress } from "hexora"
// or: import { checkAddress } from "@hexora/address-guard"

const result = await checkAddress({
  userAddress:  "0xYourWallet",
  inputAddress: "0xAddressToVerify",
  provider:     window.ethereum,
})

console.log(result.scam)           // true
console.log(result.reason)         // "zero_value_transfer"
console.log(result.riskLevel)      // "critical"
console.log(result.confidence)     // 96
console.log(result.similarityScore) // 87
console.log(result.matchedAddress) // "0xLegitAddress..."
```

### Parameters

| Param | Type | Required | Description |
|---|---|---|---|
| `userAddress` | `string` | ✓ | Connected wallet address |
| `inputAddress` | `string` | ✓ | Address to verify |
| `provider` | `EIP1193Provider` | ✓ | MetaMask, WalletConnect, or any EIP-1193 provider |
| `historyLimit` | `number` | — | Transactions to scan (default: 20, max: 50) |
| `similarityThreshold` | `number` | — | Min score to flag (default: 85, range: 0–100) |
| `apiKeys.etherscan` | `string` | — | Etherscan API key for higher rate limits |
| `apiKeys.bscscan` | `string` | — | BscScan API key |

### Result shape

```ts
interface CheckResult {
  scam:            boolean
  reason:          ScamReason | null   // "address_poisoning" | "zero_value_transfer" | ...
  riskLevel:       RiskLevel           // "none" | "low" | "medium" | "high" | "critical"
  confidence:      number              // 0–100
  similarityScore: number              // 0–100
  matchedAddress:  string | null       // closest legit address found
  details: {
    historyScanned: number
    chain:          string
  }
  error: CheckError | null
}
```

### Supported chains

| Chain | Status |
|---|---|
| Ethereum | ✅ Live |
| BNB Chain | ✅ Live |
| Polygon | ✅ Live |
| Avalanche | ✅ Live |
| Arbitrum | ✅ Live |
| Optimism | ✅ Live |
| Solana | 🔜 Soon |

---

## @hexora/domain-guard

Detects **phishing domains** targeting Web3 users — typosquatting, homoglyph attacks, subdomain hijacking, NFT spam domains, and newly registered suspicious sites.

### Detection layers (9 total)

1. **Blacklist** — 35+ confirmed phishing domains (exact match, instant)
2. **Whitelist** — 120+ legitimate Web3 domains (safe bypass)
3. **Homoglyph** — Cyrillic/Greek/Unicode lookalike chars (`uniswаp.org` uses Cyrillic 'а')
4. **Leet substitution** — numeric replacements (`un1swap.org`, `0pensea.io`)
5. **IDN / Punycode** — internationalized domain name encoding attacks
6. **Subdomain hijack** — `app.uniswap.evil.com` pattern detection
7. **Typosquatting** — Levenshtein distance against 120+ legit domains (threshold: 82%)
8. **NFT spam heuristics** — crypto bait keywords + suspicious TLD combos (`SHIBAR.la`, `NFTWOOD.top`)
9. **Domain age (RDAP)** — optional online check; domains < 30 days old flagged as suspicious

### Usage

```ts
import { checkDomain } from "hexora"
// or: import { checkDomain } from "@hexora/domain-guard"

// Basic — offline, instant
const result = await checkDomain({
  domain: "uniswap.com",
})

// With domain age check (requires network)
const result = await checkDomain({
  domain:   "app.uniswap.org",
  checkAge: true,
})

// Custom lists
const result = await checkDomain({
  domain:          "myprotocol.io",
  customWhitelist: ["myprotocol.io"],
  customBlacklist: ["evil-clone.io"],
})

console.log(result.scam)        // true
console.log(result.reason)      // "blacklisted_domain"
console.log(result.riskLevel)   // "critical"
console.log(result.matchedLegit) // "uniswap.org"
console.log(result.confidence)  // 100
```

### Parameters

| Param | Type | Required | Description |
|---|---|---|---|
| `domain` | `string` | ✓ | URL or bare domain to check |
| `typosquatThreshold` | `number` | — | Min similarity to flag (default: 82) |
| `customWhitelist` | `string[]` | — | Additional safe domains |
| `customBlacklist` | `string[]` | — | Additional blocked domains |
| `checkAge` | `boolean` | — | Enable RDAP domain age check (default: false) |

### Coverage metrics

- **9** detection layers
- **120+** whitelisted legitimate Web3 domains
- **35+** blacklisted confirmed phishing domains
- **8,000+** typosquat variants covered
- **0** required API keys

---

## @hexora/tx-guard

Detects **malicious transactions and signatures** before the user signs. Analyzes calldata structure, EIP-712 typed data, contract age, proxy upgrades, and more. No blacklist, no ML — pure pattern-based detection that works offline.

In 2024, wallet drainers stole **$494 million** from 332,000 victims. Angel Drainer, Inferno Drainer, and Pink Drainer together account for 93.9% of stolen funds — tx-guard detects the patterns all three rely on.

### Detection patterns (13 total)

| Pattern | Risk | Description |
|---|---|---|
| Unlimited Approval | 🔴 Critical | `approve(spender, 2^256-1)` to unknown address — grants permanent full token access |
| Delegation Abuse | 🔴 Critical | `updateDelegate` / `approveDelegation` — Venus $27M exploit exact pattern |
| EIP-2612 Permit | 🔴 Critical | Offline gasless signature granting token allowance — #1 drainer vector |
| setApprovalForAll | 🔴 Critical | One signature = all NFTs in collection transferred |
| Permit2 Drain | 🔴 Critical | Blanket multi-token approval via Uniswap Permit2 to unknown spender |
| Ice Phishing | 🟠 High | `transferFrom(victim→attacker)` using forgotten old allowance |
| Proxy Recently Upgraded | 🟠 High | EIP-1967 implementation changed < 7 days ago |
| Suspicious Multicall | 🟠 High | `approve + transferFrom` bundled in one atomic multicall |
| Seaport Order Spoof | 🟠 High | Fake OpenSea order routes assets to attacker (Inferno pattern) |
| Fake Token Airdrop | 🟠 High | Token name contains URL or scam call-to-action |
| New Contract + ETH | 🟠 High | Contract < 30 days old requesting ETH value |
| ERC-4337 Suspicious | 🟡 Medium | `handleOps` on non-EntryPoint contract |
| Composite Scoring | 🟠 High | Multiple weak signals combined into one verdict |

### The Venus Protocol exploit

In 2025, an attacker used a fake Zoom interface to trick a Venus Protocol user into signing one transaction: `updateDelegate(attacker_address, true)`. This granted the attacker full borrowing rights on the victim's position. $27 million was drained.

tx-guard detects this exact pattern:

```ts
const result = await checkTx({
  tx: {
    to:   "0xfd36e2c2a6789db23113685031d7f16329158384", // Venus Comptroller
    from: "0xVictimAddress",
    data: "0xe8eda9df000000000000000000000000attacker...0001",
  },
})

// result.scam      → true
// result.reason    → "ice_phishing"
// result.riskLevel → "critical"
// result.warning   → "DELEGATION ATTACK DETECTED. This transaction grants..."
```

### Usage

```ts
import { checkTx } from "hexora"
// or: import { checkTx } from "@hexora/tx-guard"

// Basic
const result = await checkTx({
  tx:       pendingTransaction,
  provider: window.ethereum,
})

// With EIP-712 typed data (permit, Seaport orders)
const result = await checkTx({
  tx,
  typedData: eip712Payload,
  provider:  window.ethereum,
})

// With deep simulation (requires Alchemy/Infura key)
const result = await checkTx({
  tx,
  provider: window.ethereum,
  rpcUrl:   "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY",
})

// Fake token airdrop detection
const result = await checkTx({
  tx,
  tokenName:   incomingToken.name,
  tokenSymbol: incomingToken.symbol,
})

if (result.scam) {
  alert(result.warning)  // human-readable explanation
  // result.reason    → "unlimited_approval"
  // result.riskLevel → "critical"
  // result.confidence → 92
}
```

### Parameters

| Param | Type | Required | Description |
|---|---|---|---|
| `tx` | `RawTransaction` | ✓ | Transaction object `{ to, from, data?, value?, chainId? }` |
| `provider` | `EIP1193Provider` | — | Wallet provider — enables contract age + simulation |
| `typedData` | `TypedDataPayload` | — | EIP-712 signature payload to analyze |
| `tokenName` | `string` | — | Token name for fake airdrop detection |
| `tokenSymbol` | `string` | — | Token symbol for fake airdrop detection |
| `rpcUrl` | `string` | — | Premium RPC for `debug_traceCall` simulation (Alchemy/Infura) |

---

## Framework support

Works in any JavaScript environment — no assumptions about your stack.

| Environment | Support |
|---|---|
| React | ✅ |
| Next.js | ✅ (client components) |
| Vue 3 | ✅ |
| Svelte | ✅ |
| Angular | ✅ |
| React Native | ✅ (with WalletConnect provider) |
| Node.js | ✅ (custom EIP-1193 adapter) |
| Browser Extension | ✅ (Chrome, Firefox, Edge) |
| Vanilla JS | ✅ |

---

## Philosophy

**SDK-first. Zero UI. Zero opinions.**

Hexora is infrastructure, not a product. Every function returns a structured result object — you decide what to show the user, whether to block the transaction, and how to present the warning. We own the security logic. You own the UX.

**Privacy first.** All detection runs locally by default. No transaction data, addresses, or domains are sent to external servers. The only optional network calls are domain age checks (RDAP) and deep transaction simulation (your own Alchemy/Infura key).

**Open source.** MIT license. Auditable, forkable, composable.

---

## Links

- [GitHub](https://github.com/DaniilSapielkin01/Hexora)
- [npm — hexora](https://www.npmjs.com/package/hexora)
- [npm — @hexora/address-guard](https://www.npmjs.com/package/@hexora/address-guard)
- [npm — @hexora/domain-guard](https://www.npmjs.com/package/@hexora/domain-guard)
- [npm — @hexora/tx-guard](https://www.npmjs.com/package/@hexora/tx-guard)

---

MIT License · © Hexora Contributors
