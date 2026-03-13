# HEXORA

**Web3 Security SDK** — detects address poisoning attacks before users lose funds.

[![npm](https://img.shields.io/npm/v/hexora)](https://www.npmjs.com/package/hexora)
[![size](https://img.shields.io/bundlephobia/minzip/hexora)](https://bundlephobia.com/package/hexora)
[![license](https://img.shields.io/npm/l/hexora)](./LICENSE)

---

## The Problem

Address poisoning attacks cost millions every year. An attacker creates a wallet with the same first and last characters as a legitimate address, sends a tiny transaction to the victim, and waits for them to copy the wrong address from their history.

**MetaMask, Trust Wallet, Ledger Live** — none of them detect this. HEXORA fills that gap at the SDK level.

```
Legit:  0xEF70efAf74A3caAbF254E786F834133864BC80E6
Fake:   0xe7d40975DD0396Fc81A39b0ED1f2b7aCE1BC80E6
                  ^^^^^ different middle ^^^^^
```

These are real addresses from a live attack on BNB Chain. The victim `0x7265BD...075a91` had `0xEF70ef...BC80E6` in their history — the attacker deployed `0xe7d409...BC80E6` with matching first and last 4 chars and sent a [zero-value transfer](https://bscscan.com/tx/0x67e2b135f1255fa45db213d2da8231331c5b3c681031553b17e543bc7292acc8) to poison the history.

---

### Real case

https://x.com/incrypted/status/2029865814342398139

---

## Install

```bash
npm install hexora
# or
pnpm add hexora
```

---

## Quick Start

```ts
import { checkAddress } from "hexora";

const result = await checkAddress({
  userAddress: "0x...", // connected wallet
  inputAddress: "0x...", // address the user is about to send to
  provider: window.ethereum,
});

if (result.scam) {
  console.warn(result.reason); // "batch_poisoning"
  console.warn(result.riskLevel); // "critical"
}
```

---

## How It Works

Every `checkAddress()` call runs through a multi-layer pipeline:

```
1. Provider Detection    — auto-detects MetaMask / WalletConnect / Phantom / any EIP-1193
2. Chain Resolution      — reads chainId from provider, no manual chain param needed
3. History Fetch         — fetches last N transactions for both addresses in parallel
4. Similarity Check      — weighted prefix/suffix/Levenshtein comparison
5. Poison Detection      — zero-value transfers, batch poisoning, transferFrom spoofing, dust
6. Input Addr Analysis   — checks if inputAddress itself is a known attacker wallet
7. Risk Scoring          — combines all signals into a final structured result
```

---

## Response

```ts
{
  scam:            true,
  reason:          "zero_value_transfer",
  riskLevel:       "critical",
  similarityScore: 87,
  confidence:      96,
  matchedAddress:  "0xEF70efAf74A3caAbF254E786F834133864BC80E6",
  details: {
    chain:          "bnb",
    userAddress:    "0x7265BDC334276e496d284D2Dcc2918aA59075a91",
    inputAddress:   "0xe7d40975DD0396Fc81A39b0ED1f2b7aCE1BC80E6",
    historyScanned: 20,
    poisonTxFound:  true,
    zeroValueFound: true,
    dustFound:      false,
  },
  error: null
}
```

### `riskLevel` values

| Value      | Meaning                                   |
| ---------- | ----------------------------------------- |
| `none`     | No signals detected — address looks clean |
| `low`      | Weak signal — worth monitoring            |
| `medium`   | Suspicious — consider warning the user    |
| `high`     | Strong signal — warn the user             |
| `critical` | Confirmed attack pattern — block the tx   |

### `reason` values

| Value                    | Description                                                  |
| ------------------------ | ------------------------------------------------------------ |
| `address_poisoning`      | Similar address found in user's transaction history          |
| `zero_value_transfer`    | Incoming ERC-20 transfer with value = 0                      |
| `batch_poisoning`        | Attacker contract poisoned history in a single batch tx      |
| `transferfrom_spoofing`  | Contract forced a zero-value transferFrom using your address |
| `dust_attack`            | Micro-transaction received from unknown address              |
| `new_suspicious_address` | Young address with outgoing-only activity                    |

---

## API Reference

### `checkAddress(params)`

```ts
import { checkAddress } from "hexora"

const result = await checkAddress(params: CheckAddressParams): Promise<CheckResult>
```

#### `CheckAddressParams`

| Field                 | Type              | Required | Default               | Description                            |
| --------------------- | ----------------- | -------- | --------------------- | -------------------------------------- |
| `userAddress`         | `string`          | ✅       | —                     | The connected wallet address           |
| `inputAddress`        | `string`          | ✅       | —                     | The address the user wants to send to  |
| `provider`            | `RawProvider`     | ✅       | —                     | EIP-1193 or Phantom provider           |
| `historyLimit`        | `number`          | ❌       | `20`                  | Transactions to scan (max 50)          |
| `similarityThreshold` | `number`          | ❌       | `85`                  | Minimum score to flag (0–100)          |
| `dustThreshold`       | `bigint`          | ❌       | `10_000_000_000_000n` | Wei threshold for dust detection       |
| `historyProvider`     | `HistoryProvider` | ❌       | —                     | Custom transaction history source      |
| `apiKeys.etherscan`   | `string`          | ❌       | —                     | Etherscan API key (higher rate limits) |
| `apiKeys.bscscan`     | `string`          | ❌       | —                     | BscScan API key                        |
| `apiKeys.polygonscan` | `string`          | ❌       | —                     | Polygonscan API key                    |

---

## Supported Chains

| Chain     | Status | Auto-detected from provider |
| --------- | ------ | --------------------------- |
| Ethereum  | ✅     | `chainId: 0x1`              |
| BNB Chain | ✅     | `chainId: 0x38`             |
| Polygon   | ✅     | `chainId: 0x89`             |
| Avalanche | ✅     | `chainId: 0xa86a`           |
| Arbitrum  | ✅     | `chainId: 0xa4b1`           |
| Optimism  | ✅     | `chainId: 0xa`              |
| Solana    | 🔜     | Phantom provider            |
| Bitcoin   | 🔜     | Coming soon                 |
| Tron      | 🔜     | Coming soon                 |

Chain is resolved **automatically** from the provider — you never pass `chain` manually.

---

## Supported Wallets & Providers

HEXORA auto-detects the provider type. Any wallet that implements **EIP-1193** works out of the box:

| Wallet              | Works |
| ------------------- | ----- |
| MetaMask            | ✅    |
| WalletConnect       | ✅    |
| Coinbase Wallet     | ✅    |
| Trust Wallet (EVM)  | ✅    |
| Rainbow             | ✅    |
| Rabby               | ✅    |
| Ledger Live         | ✅    |
| Phantom (Solana)    | ✅    |
| Any EIP-1193 wallet | ✅    |

---

## Usage Examples

### React

```tsx
import { checkAddress } from "hexora";

const handleSend = async () => {
  const result = await checkAddress({
    userAddress: account,
    inputAddress: pastedAddress,
    provider: window.ethereum,
  });

  if (result.scam) {
    alert(`⚠️ ${result.reason} — risk: ${result.riskLevel}`);
    return;
  }

  // proceed with transaction
};
```

### Next.js

Works in client components only — `window.ethereum` is not available server-side.

```tsx
"use client";
import { checkAddress } from "hexora";

export function SendForm() {
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const result = await checkAddress({
      userAddress: userWallet,
      inputAddress: recipientInput,
      provider: window.ethereum,
    });
    if (result.scam) setWarning(result.reason);
  };
}
```

### Vue 3

```ts
import { checkAddress } from "hexora";

async function onSend() {
  const result = await checkAddress({
    userAddress: wallet.address,
    inputAddress: form.recipient,
    provider: window.ethereum,
  });

  if (result.scam) {
    warningMessage.value = result.reason;
    return;
  }
}
```

### Svelte

```ts
import { checkAddress } from "hexora";

async function handleSend() {
  const result = await checkAddress({
    userAddress: $wallet.address,
    inputAddress: recipientInput,
    provider: window.ethereum,
  });

  if (result.scam) {
    warning = result.reason;
  }
}
```

### Angular

```ts
import { Injectable } from "@angular/core";
import { checkAddress } from "hexora";

@Injectable({ providedIn: "root" })
export class HexoraService {
  async check(userAddress: string, inputAddress: string) {
    return checkAddress({
      userAddress,
      inputAddress,
      provider: (window as any).ethereum,
    });
  }
}
```

### React Native

> Requires a WalletConnect or custom EIP-1193 compatible provider — `window.ethereum` is not available in React Native.

```tsx
import { checkAddress } from "hexora";
import { useWalletConnectModal } from "@walletconnect/modal-react-native";

export function SendScreen() {
  const { provider } = useWalletConnectModal();

  const handleSend = async () => {
    const result = await checkAddress({
      userAddress: connectedAddress,
      inputAddress: recipientAddress,
      provider: provider, // WalletConnect EIP-1193 provider
    });

    if (result.scam) {
      Alert.alert("⚠️ Warning", `Suspicious address: ${result.reason}`);
      return;
    }
  };
}
```

### Node.js / Backend

Useful for pre-validating addresses in a backend before broadcasting transactions.

```ts
import { checkAddress } from "hexora";
import type { EIP1193Provider } from "hexora";

// Node.js has no window.ethereum — use your own RPC provider adapter
class NodeProvider implements EIP1193Provider {
  async request({ method }: { method: string }): Promise<unknown> {
    if (method === "eth_chainId") return "0x1";
    throw new Error(`Unsupported method: ${method}`);
  }
}

const result = await checkAddress({
  userAddress: "0x7265BDC334276e496d284D2Dcc2918aA59075a91",
  inputAddress: "0xe7d40975DD0396Fc81A39b0ED1f2b7aCE1BC80E6",
  provider: new NodeProvider(),
  apiKeys: { etherscan: process.env.ETHERSCAN_API_KEY },
});
```

### Browser Extension (Chrome / Firefox)

```ts
import { checkAddress } from "hexora";

chrome.runtime.onMessage.addListener(async (msg, _sender, sendResponse) => {
  if (msg.type === "CHECK_ADDRESS") {
    const result = await checkAddress({
      userAddress: msg.userAddress,
      inputAddress: msg.inputAddress,
      provider: window.ethereum,
    });
    sendResponse(result);
  }
  return true; // keep channel open for async response
});
```

### With API Keys (higher rate limits)

```ts
const result = await checkAddress({
  userAddress: account,
  inputAddress: pastedAddress,
  provider: window.ethereum,
  apiKeys: {
    etherscan: "YOUR_ETHERSCAN_KEY",
    bscscan: "YOUR_BSCSCAN_KEY",
  },
});
```

### Custom History Provider

Implement `HistoryProvider` to plug in your own data source (Alchemy, Moralis, your own indexer):

```ts
import { checkAddress } from "hexora";
import type { HistoryProvider, NormalizedTransaction, ChainId } from "hexora";

class AlchemyProvider implements HistoryProvider {
  async getTransactions(
    address: string,
    chain: ChainId,
    limit: number
  ): Promise<NormalizedTransaction[]> {
    // fetch from Alchemy / Moralis / your indexer
    return [];
  }
}

const result = await checkAddress({
  userAddress: account,
  inputAddress: pastedAddress,
  provider: window.ethereum,
  historyProvider: new AlchemyProvider(),
});
```

---

## Platform Support

| Platform           | Status | Notes                                     |
| ------------------ | ------ | ----------------------------------------- |
| React              | ✅     | Full support                              |
| Next.js            | ✅     | Client components only                    |
| Vue 3              | ✅     | Full support                              |
| Svelte / SvelteKit | ✅     | Full support                              |
| Angular            | ✅     | Full support                              |
| React Native       | ✅     | Requires WalletConnect or custom provider |
| Node.js            | ✅     | Custom EIP-1193 adapter required          |
| Browser Extension  | ✅     | Chrome, Firefox, Edge                     |
| Vanilla JS         | ✅     | Full support                              |

---

## Coming Soon

Native SDK support is planned for mobile platforms — no JS bridge required:

| Platform         | Status | Notes                                  |
| ---------------- | ------ | -------------------------------------- |
| Swift / iOS      | 🔜     | Native Swift SDK                       |
| Kotlin / Android | 🔜     | Native Kotlin SDK                      |
| Flutter          | 🔜     | Dart package                           |
| Rust             | 🔜     | For CLI tools and backend integrations |
| Python           | 🔜     | For backend / analytics use cases      |

> Want to contribute a native SDK? Open an issue or reach out.

---

## Error Handling

HEXORA never throws. All errors are returned in `result.error`:

```ts
const result = await checkAddress({ ... })

if (result.error) {
  console.error(result.error.code)    // "network_unavailable"
  console.error(result.error.message) // human-readable message
}
```

### Error codes

| Code                   | Description                         |
| ---------------------- | ----------------------------------- |
| `invalid_address`      | Address format is invalid for chain |
| `unknown_provider`     | Provider type could not be detected |
| `unsupported_chain`    | Chain is not supported yet          |
| `network_unavailable`  | Could not connect to provider       |
| `history_fetch_failed` | Transaction history fetch failed    |
| `rate_limited`         | API rate limit hit                  |
| `unknown`              | Unexpected error                    |

---

## Packages

This is a monorepo. You can install the full SDK or individual packages:

| Package                 | Description                  | Size        |
| ----------------------- | ---------------------------- | ----------- |
| `hexora`                | Full SDK — all modules       | ~3.5 kB     |
| `@hexora/address-guard` | Address poisoning detection  | ~3.5 kB     |
| `@hexora/core`          | Shared utilities and types   | ~2.2 kB     |
| `@hexora/domain-guard`  | Domain phishing detection 🔜 | coming soon |

---

## Architecture

```
hexora/
├── packages/
│   ├── core/           — shared: types, provider detection, similarity, cache
│   ├── address-guard/  — address poisoning detection logic
│   ├── domain-guard/   — domain phishing detection (coming soon)
│   └── hexora/         — single entry point re-exporting all modules
```

Each package is independent. `@hexora/core` is shared — never duplicate logic across modules.

---

## Privacy

- All analysis runs **locally** — no data is sent to HEXORA servers
- Transaction history is fetched directly from public block explorer APIs
- In-memory cache only (5 min TTL) — cleared when the page unloads
- No `localStorage`, no cookies, no tracking

---

## License

MIT — free for personal and commercial use.
