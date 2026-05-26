# @hexora/tx-guard

Detect **malicious transactions and signatures** before users sign them.

[![npm version](https://img.shields.io/npm/v/@hexora/tx-guard?color=6efaee&labelColor=060809)](https://www.npmjs.com/package/@hexora/tx-guard)
[![license](https://img.shields.io/npm/l/@hexora/tx-guard?color=6efaee&labelColor=060809)](https://github.com/DaniilSapielkin01/Hexora/blob/main/LICENSE)

---

## The problem

In 2024, wallet drainers stole **$494 million** from 332,000 victims — a 67% increase year over year. Angel Drainer, Inferno Drainer, and Pink Drainer together account for 93.9% of stolen funds.

They all exploit the same weakness: **users don't understand what they're signing.**

A `setApprovalForAll` looks identical to a legitimate NFT listing. An EIP-2612 permit looks like a harmless "Sign this message" popup. A `updateDelegate` looks like a routine protocol interaction. tx-guard reads the calldata and tells users exactly what will happen.

---

## Install

```bash
npm install @hexora/tx-guard
# or install everything
npm install hexora
```

---

## Usage

```ts
import { checkTx } from "@hexora/tx-guard"

// Before showing the "Sign" button
const result = await checkTx({
  tx:       pendingTransaction,
  provider: window.ethereum,
})

if (result.scam) {
  alert(result.warning)
  return // block signing
}
```

### EIP-712 typed data (permit, Seaport orders)

```ts
const result = await checkTx({
  tx,
  typedData: eip712SignatureRequest,
  provider:  window.ethereum,
})
// Detects: permit_drain, seaport_order_spoof, permit2_drain
```

### Deep simulation with Alchemy/Infura

```ts
// Uses debug_traceCall — sees every storage write and internal call
// Works without rpcUrl too — falls back to basic eth_call simulation
const result = await checkTx({
  tx,
  provider: window.ethereum,
  rpcUrl:   "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY",
})
```

### Fake token airdrop detection

```ts
const result = await checkTx({
  tx,
  tokenName:   incomingToken.name,
  tokenSymbol: incomingToken.symbol,
})
// "Visit scam.xyz to claim $1000 USDT" → fake_token_airdrop
```

---

## Detection patterns (13 total)

### Critical

**Unlimited Approval** — `approve(spender, 2^256-1)` to an unknown address grants permanent full access to your tokens. Drainers request this first, then drain at any time without another signature from you.

**Delegation Abuse** — `updateDelegate` and `approveDelegation` give another address the right to borrow and withdraw on your behalf in lending protocols (Venus, Aave, Compound). This was the exact mechanism used in the **Venus Protocol $27M exploit** — one signed transaction handed over full control.

**EIP-2612 Permit** — A gasless off-chain signature that grants token allowance without broadcasting a transaction. Inferno and Angel Drainer use this as their primary attack vector because the "Sign Message" popup feels safe compared to a transaction.

**setApprovalForAll** — One approval grants access to every NFT you own in an entire collection. Attackers spoof OpenSea and Blur listing pages to make users sign this instead of a legitimate sale.

**Permit2 Drain** — Uniswap's Permit2 contract allows a single signature to authorize spending across many tokens. Drainers spoof these requests to get blanket access — one signature drains USDC, WETH, and any other approved token simultaneously.

### High

**Ice Phishing** — A malicious contract calls `transferFrom(victim, attacker)` using an old allowance you granted months ago and forgot about. Named "ice phishing" because the approval is frozen in your history until the attacker decides to act.

**Proxy Recently Upgraded** — Upgradeable proxy contracts can change their implementation (logic) at any time. If the implementation address changed less than 7 days ago, the new code may contain malicious logic added right before the attack.

**Suspicious Multicall** — A single transaction that bundles `approve` + `transferFrom` atomically. The user sees one confirmation but two operations execute — the approval and the drain happen in the same block with no time to react.

**Seaport Order Spoof** — Attackers forge Seaport marketplace orders where the `consideration` field routes assets to their address instead of the seller. Inferno Drainer specializes in this — victims think they're listing an NFT but actually send ETH to the attacker.

**Fake Token Airdrop** — Tokens with names like "Visit scam.xyz to claim $1000 USDT" are sent to wallets as a lure. The token itself is worthless — the scam is the website visit, which then requests a wallet signature.

**New Contract + ETH** — Legitimate protocols are battle-tested for months before handling real funds. A contract deployed less than 30 days ago requesting ETH is a strong indicator of a one-time attack contract.

### Medium

**ERC-4337 AA Suspicious** — In Account Abstraction, user operations flow Bundler → EntryPoint → your wallet. If `handleOps` is called on an address that isn't the official ERC-4337 EntryPoint, someone is routing your transaction through custom logic to conceal the real operation. Both v0.6 (selector `0x1fad948c`) and v0.7 (`0x765e827f`, packed format) EntryPoints are decoded via viem.

**Composite Scoring** — Multiple weak signals that wouldn't trigger a flag individually are combined into a single risk verdict. A new contract + multicall + medium-confidence detection together cross the threshold.

---

## API

### `checkTx(params): Promise<CheckTxResult>`

#### Parameters

| Param | Type | Required | Description |
|---|---|---|---|
| `tx` | `RawTransaction` | ✓ | `{ to, from, data?, value?, chainId? }` |
| `provider` | `EIP1193Provider` | — | Enables contract age check + simulation |
| `typedData` | `TypedDataPayload` | — | EIP-712 payload to analyze |
| `tokenName` | `string` | — | Token name for fake airdrop detection |
| `tokenSymbol` | `string` | — | Token symbol for fake airdrop detection |
| `rpcUrl` | `string` | — | Alchemy/Infura URL for deep `debug_traceCall` simulation |

#### Result

```ts
{
  scam:       boolean
  reason:     TxScamReason | null
  riskLevel:  "none" | "low" | "medium" | "high" | "critical"
  confidence: number   // 0–100
  warning:    string | null  // human-readable explanation for UI
  details: {
    methodId:          string | null
    methodName:        string | null
    spender:           string | null
    amount:            bigint | null
    isUnlimitedAmount: boolean
    contractAge:       number | null   // days since deployment
    isProxy:           boolean
    proxyImplAge:      number | null   // days since last upgrade
    simulationResult:  SimulationResult | null
  }
  error: { code: string; message: string } | null
}
```

#### TxScamReason values

```ts
type TxScamReason =
  | "unlimited_approval"
  | "permit_drain"
  | "set_approval_for_all"
  | "ice_phishing"
  | "new_contract"
  | "eth_value_mismatch"
  | "suspicious_multicall"
  | "seaport_order_spoof"
  | "permit2_drain"
  | "proxy_recently_upgraded"
  | "simulation_loss"
  | "fake_token_airdrop"
  | "delegation_abuse"
```

---

## Coverage

- **13** attack patterns
- **$494M** stolen in 2024 — the attacks we detect
- **93.9%** of top drainer families covered (Angel, Inferno, Pink)
- **0** external API calls required for detection
- All EVM chains supported

## Dependencies

Uses [`viem`](https://viem.sh) for ABI decoding (keccak256, `decodeFunctionData`, `decodeAbiParameters`). If you already have viem in your dApp this is free via dedup; otherwise viem is tree-shaken to ~6 kB inside this package.

## Additional exports

```ts
import { isHandleOpsCalldata, extractUserOps, analyzeUserOperation } from "@hexora/tx-guard"

// Quick check before deeper analysis
if (isHandleOpsCalldata(tx.data)) {
  const ops = extractUserOps(tx.data)  // v0.6 + v0.7 supported
  for (const op of ops) analyzeUserOperation(op)
}
```

---

## Platform support

React · Next.js · Vue · Svelte · Angular · React Native · Browser Extensions · Node.js · Vanilla JS

---

## License

MIT · [GitHub](https://github.com/DaniilSapielkin01/Hexora)
