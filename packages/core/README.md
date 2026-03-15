# @hexora/core

Shared types, provider detection, and utilities for the Hexora Web3 Security SDK.

[![npm version](https://img.shields.io/npm/v/@hexora/core?color=6efaee&labelColor=060809)](https://www.npmjs.com/package/@hexora/core)
[![license](https://img.shields.io/npm/l/@hexora/core?color=6efaee&labelColor=060809)](https://github.com/DaniilSapielkin01/Hexora/blob/main/LICENSE)
[![bundle size](https://img.shields.io/bundlephobia/minzip/@hexora/core?color=6efaee&labelColor=060809)](https://bundlephobia.com/package/@hexora/core)

---

## What is this?

`@hexora/core` is the shared foundation for all Hexora packages. It provides:

- **TypeScript types** — `RiskLevel`, `ChainId`, `ScamReason`, `CheckError`, `EIP1193Provider`
- **Provider detection** — auto-detects MetaMask, WalletConnect, Phantom, and any EIP-1193 provider
- **Similarity algorithms** — Levenshtein distance and weighted prefix/suffix scoring
- **Transaction history fetching** — adapters for Etherscan, BscScan, Polygonscan, and more
- **In-memory caching** — deduplicates API calls across multiple checks

You rarely need to install this directly — it is a peer dependency of `@hexora/address-guard`, `@hexora/domain-guard`, and `@hexora/tx-guard` and gets installed automatically.

---

## Install

```bash
# Usually installed automatically as a peer dependency.
# Install manually only if you need the types directly.
npm install @hexora/core
```

---

## Exported types

```ts
import type {
  ChainId,
  RiskLevel,
  ScamReason,
  CheckError,
  EIP1193Provider,
  HistoryProvider,
  RawProvider,
} from "@hexora/core"
```

### `ChainId`

```ts
type ChainId =
  | "ethereum"
  | "bnb"
  | "polygon"
  | "avalanche"
  | "arbitrum"
  | "optimism"
  | "solana"
  | "bitcoin"
  | "tron"
```

### `RiskLevel`

```ts
type RiskLevel = "none" | "low" | "medium" | "high" | "critical"
```

### `ScamReason`

```ts
type ScamReason =
  | "address_poisoning"
  | "zero_value_transfer"
  | "batch_poisoning"
  | "transferfrom_spoofing"
  | "dust_attack"
  | "new_suspicious_address"
```

### `CheckError`

```ts
interface CheckError {
  code:    "provider_error" | "network_error" | "rate_limit" | "unknown"
  message: string
}
```

### `EIP1193Provider`

Standard EIP-1193 wallet provider interface:

```ts
interface EIP1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>
}
```

### `HistoryProvider`

Custom transaction history source — implement this to use Alchemy, Moralis, or your own indexer instead of public block explorers:

```ts
interface HistoryProvider {
  getHistory(address: string, chainId: ChainId): Promise<HistoryTransaction[]>
}

interface HistoryTransaction {
  from:  string
  to:    string
  value: string
  hash:  string
}
```

Usage with `@hexora/address-guard`:

```ts
import { checkAddress } from "@hexora/address-guard"
import type { HistoryProvider } from "@hexora/core"

const myProvider: HistoryProvider = {
  async getHistory(address, chainId) {
    const data = await myIndexer.getTransactions(address, chainId)
    return data.map(tx => ({ from: tx.from, to: tx.to, value: tx.value, hash: tx.hash }))
  }
}

const result = await checkAddress({
  userAddress:     "0x...",
  inputAddress:    "0x...",
  provider:        window.ethereum,
  historyProvider: myProvider,
})
```

### `RawProvider`

Union type that accepts MetaMask, WalletConnect, Phantom, or any compatible provider:

```ts
type RawProvider = EIP1193Provider | PhantomProvider | Record<string, unknown>
```

---

## Bundle size

2.2 kB minified + brotlied. Zero external dependencies.

---

## License

MIT · [GitHub](https://github.com/DaniilSapielkin01/Hexora)
