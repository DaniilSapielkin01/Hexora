#!/usr/bin/env npx tsx
// Script to update KNOWN_PHISHING_DOMAINS from MetaMask eth-phishing-detect
// Run: npx tsx scripts/update-blacklist.ts
//
// Source: https://github.com/MetaMask/eth-phishing-detect (MIT License)
// We take top N most recently added domains — not the full 200K list
// because the full list would bloat the bundle significantly
//
// Strategy: take domains that contain keywords matching our whitelist
// This gives maximum signal with minimum size

import { writeFileSync } from "fs"
import { join } from "path"

const METAMASK_CONFIG_URL =
  "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json"

// How many domains to include from MetaMask blacklist
const TAKE = 500

// Keywords that make a domain relevant to Web3 — only include domains
// that contain at least one of these (filters out unrelated scams)
const RELEVANCE_KEYWORDS = [
  "uniswap", "metamask", "opensea", "aave", "compound", "curve",
  "sushi", "pancake", "1inch", "ethereum", "ether", "eth", "defi",
  "nft", "wallet", "ledger", "trezor", "phantom", "solana", "arbitrum",
  "optimism", "polygon", "binance", "coinbase", "lido", "blur",
  "raydium", "yearn", "convex", "balancer", "dydx", "gmx",
]

interface MetaMaskConfig {
  blacklist: string[]
  whitelist: string[]
  fuzzylist: string[]
}

async function fetchMetaMaskBlacklist(): Promise<string[]> {
  console.log("Fetching MetaMask eth-phishing-detect config...")
  const res  = await fetch(METAMASK_CONFIG_URL)
  if (!res.ok) throw new Error(`Failed to fetch: ${res.status}`)
  const data = await res.json() as MetaMaskConfig
  return data.blacklist ?? []
}

function filterRelevant(domains: string[]): string[] {
  return domains.filter((domain) =>
    RELEVANCE_KEYWORDS.some((kw) => domain.toLowerCase().includes(kw))
  )
}

function generateTypeScriptArray(
  ourDomains: string[],
  metamaskDomains: string[]
): string {
  // Merge — our curated list first, MetaMask additions after
  const merged = [
    ...ourDomains,
    "// ── From MetaMask eth-phishing-detect (MIT) ──",
    ...metamaskDomains.map((d) => `  "${d}",`),
  ]

  const count = ourDomains.length + metamaskDomains.length

  return `// Auto-generated — do not edit manually
// Run: npx tsx scripts/update-blacklist.ts
// Sources: Hexora curated list + MetaMask eth-phishing-detect (MIT License)
// Total: ${count} confirmed phishing domains

export const KNOWN_PHISHING_DOMAINS: readonly string[] = [
${merged.join("\n")}
]
`
}

// Our curated list — kept separately so script doesn't overwrite them
const OUR_DOMAINS = [
  // Uniswap fakes
  '  "app-uniswap.org",',
  '  "app-uniswap.io",',
  '  "uniswap.com",',
  '  "uniswap-app.com",',
  '  "uniswap-exchange.com",',
  '  "uniswaap.org",',
  '  "uniswapdex.io",',
  // OpenSea fakes
  '  "openseas.io",',
  '  "open-sea.io",',
  '  "opensea.com",',
  // MetaMask fakes
  '  "metamask-login.com",',
  '  "metamask-wallet.com",',
  '  "metmask.io",',
  '  "meta-mask.io",',
  // Etherscan fakes
  '  "etherscan-login.com",',
  '  "etherscan.com",',
  // MEW fakes
  '  "myetherwallet.com.co",',
  '  "myetherwllet.com",',
  // PancakeSwap fakes
  '  "pancakeswap.org",',
  '  "pancakeswap.com",',
  // Aave fakes
  '  "defi-aave.com",',
  '  "aave-app.com",',
  // Trust Wallet fakes
  '  "trustwalet.com",',
  '  "trust-wallet.com",',
  // Lido fakes
  '  "lido-stake.com",',
  '  "staking-lido.com",',
  // Generic
  '  "wallet-connect-secure.com",',
  '  "defi-rewards-claim.com",',
  '  "nft-airdrop-claim.io",',
  "  // ── From MetaMask eth-phishing-detect (MIT) ──",
]

async function main() {
  try {
    const allBlacklist  = await fetchMetaMaskBlacklist()
    console.log(`Fetched ${allBlacklist.length} domains from MetaMask`)

    const relevant = filterRelevant(allBlacklist)
    console.log(`Filtered to ${relevant.length} Web3-relevant domains`)

    const top = relevant.slice(0, TAKE)
    console.log(`Taking top ${top.length} domains`)

    const lines = top.map((d) => `  "${d}",`)
    const total = OUR_DOMAINS.filter((l) => l.trim().startsWith('"')).length + top.length

    const output = `// Auto-generated — do not edit manually
// Run: npx tsx scripts/update-blacklist.ts
// Sources: Hexora curated list + MetaMask eth-phishing-detect (MIT License)
// Total: ${total} confirmed phishing domains

export const KNOWN_PHISHING_DOMAINS: readonly string[] = [
${OUR_DOMAINS.join("\n")}
${lines.join("\n")}
]
`

    const outPath = join(
      import.meta.dirname ?? process.cwd(),
      "../packages/domain-guard/src/generatedBlacklist.ts"
    )

    writeFileSync(outPath, output, "utf-8")
    console.log(`✅ Written ${total} domains to generatedBlacklist.ts`)
    console.log(`   Our curated: ${OUR_DOMAINS.filter(l => l.trim().startsWith('"')).length}`)
    console.log(`   From MetaMask: ${top.length}`)

  } catch (err) {
    console.error("❌ Failed:", err)
    process.exit(1)
  }
}

main()
