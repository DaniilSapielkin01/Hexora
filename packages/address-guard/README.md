# @hexora/address-guard

Detect **address poisoning attacks** before users lose funds.

[![npm version](https://img.shields.io/npm/v/@hexora/address-guard?color=6efaee&labelColor=060809)](https://www.npmjs.com/package/@hexora/address-guard)
[![license](https://img.shields.io/npm/l/@hexora/address-guard?color=6efaee&labelColor=060809)](https://github.com/DaniilSapielkin01/Hexora/blob/main/LICENSE)
[![bundle size](https://img.shields.io/bundlephobia/minzip/@hexora/address-guard?color=6efaee&labelColor=060809)](https://bundlephobia.com/package/@hexora/address-guard)

---

## The problem

Address poisoning is a social engineering attack where the attacker:

1. Creates a wallet address with the **same first and last characters** as a legitimate address the victim has used
2. Sends a **zero-value transaction** from that fake address to poison the victim's history
3. Waits for the victim to copy the wrong address from their history and send real funds

```
Legit: 0xEF70ef [Af74A3caAbF254E786F834133864] BC80E6
Fake:  0xe7d409 [75DD0396Fc81A39b0ED1f2b7aCE1] BC80E6
```

Most wallets display these addresses identically in truncated form. Users can't tell the difference by eye.

Hexora detects both **native (ETH)** and **ERC-20 token** dust patterns — attackers almost always use cheap token transfers because native dust is unprofitable on gas.

---

## Install

```bash
npm install @hexora/address-guard
# or install everything
npm install hexora
```

---

## Usage

```ts
import { checkAddress } from "@hexora/address-guard"

const result = await checkAddress({
  userAddress:  "0xYourConnectedWallet",
  inputAddress: "0xAddressUserPasted",
  provider:     window.ethereum,
})

if (result.scam) {
  console.warn(result.reason)     // "zero_value_transfer"
  console.warn(result.riskLevel)  // "critical"
  console.warn(result.confidence) // 96
}
```

### React example

```tsx
const handleRecipientChange = async (address: string) => {
  if (address.length !== 42) return

  const result = await checkAddress({
    userAddress:  connectedWallet,
    inputAddress: address,
    provider:     window.ethereum,
  })

  if (result.scam) {
    setWarning(`⚠️ Suspicious address: ${result.reason} (${result.confidence}% confidence)`)
  }
}
```

### React Native (WalletConnect)

```tsx
import { useWalletConnectModal } from "@walletconnect/modal-react-native"
import { checkAddress } from "@hexora/address-guard"

const { provider } = useWalletConnectModal()

const result = await checkAddress({
  userAddress:  connectedAddress,
  inputAddress: recipientAddress,
  provider,
})
```

---

## API

### `checkAddress(params): Promise<CheckResult>`

#### Parameters

| Param | Type | Required | Default | Description |
|---|---|---|---|---|
| `userAddress` | `string` | ✓ | — | Connected wallet address |
| `inputAddress` | `string` | ✓ | — | Address to verify |
| `provider` | `RawProvider` | ✓ | — | EIP-1193 or Phantom provider |
| `historyLimit` | `number` | — | `20` | Transactions to scan (max 50) |
| `similarityThreshold` | `number` | — | `85` | Min score to flag (0–100) |
| `historyProvider` | `HistoryProvider` | — | — | Custom tx history source |
| `apiKeys.etherscan` | `string` | — | — | Etherscan API key |
| `apiKeys.bscscan` | `string` | — | — | BscScan API key |

#### Result

```ts
{
  scam:            boolean
  reason:          "address_poisoning" | "zero_value_transfer" | "batch_poisoning" |
                   "transferfrom_spoofing" | "dust_attack" | "new_suspicious_address" | null
  riskLevel:       "none" | "low" | "medium" | "high" | "critical"
  confidence:      number   // 0–100
  similarityScore: number   // 0–100
  matchedAddress:  string | null
  details: {
    historyScanned: number
    chain:          string
  }
  error:           { code: string; message: string } | null
}
```

---

## How it works

Every `checkAddress()` call runs through a 7-layer pipeline:

```
1. Provider detection   — auto-detects MetaMask, WalletConnect, Phantom
2. Chain resolution     — reads chainId from provider automatically
3. History fetch        — last N txs from block explorers, Promise.allSettled
                          so a single failed lookup doesn't lose the rest
4. Similarity check     — weighted prefix (40%) + suffix (40%) + Levenshtein (20%);
                          contract addresses (DEX routers, tokens) filtered out
                          to avoid false positives
5. Poison detection     — zero-value, batch, transferFrom, native + ERC-20 dust
6. Input analysis       — checks if the address itself is a known attacker wallet
7. Risk scoring         — combines all signals; multi-signal amplifier boosts
                          confidence when several weak signals fire together
```

---

## Supported chains

Ethereum · BNB Chain · Polygon · Avalanche · Arbitrum · Optimism

---

## Platform support

React · Next.js · Vue · Svelte · Angular · React Native · Browser Extensions · Node.js · Vanilla JS

---

## License

MIT · [GitHub](https://github.com/DaniilSapielkin01/Hexora)
