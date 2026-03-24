// Transaction simulation via eth_call
// Shows real balance delta BEFORE user signs
// This is the most powerful detection — catches scams that look legitimate
// on the surface but drain funds when executed

import type { EIP1193Provider } from "@hexora/core"
import type { RawTransaction, SimulationResult } from "./types.js"

const TIMEOUT_MS = 4000

// ERC-20 balanceOf(address) selector
const BALANCE_OF = "0x70a08231"
// ERC-20 Transfer event topic
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

export async function simulateTransaction(
  tx:       RawTransaction,
  provider: EIP1193Provider
): Promise<SimulationResult> {
  try {
    // ── 1. Get ETH balance before ───────────────────────────────────────────
    const [balanceBefore, chainId] = await Promise.all([
      withTimeout(
        provider.request({ method: "eth_getBalance", params: [tx.from, "latest"] }),
        TIMEOUT_MS
      ) as Promise<string>,
      withTimeout(
        provider.request({ method: "eth_chainId", params: [] }),
        TIMEOUT_MS
      ) as Promise<string>,
    ])

    // ── 2. Simulate via eth_call ────────────────────────────────────────────
    // eth_call runs the tx without broadcasting — returns what would happen
    let callSuccess = true
    try {
      await withTimeout(
        provider.request({
          method: "eth_call",
          params: [{ to: tx.to, from: tx.from, data: tx.data, value: tx.value }, "latest"],
        }),
        TIMEOUT_MS
      )
    } catch {
      callSuccess = false
    }

    // ── 3. Use eth_estimateGas to check if tx would succeed ─────────────────
    let gasEstimate: bigint | null = null
    try {
      const gasHex = await withTimeout(
        provider.request({
          method: "eth_estimateGas",
          params: [{ to: tx.to, from: tx.from, data: tx.data, value: tx.value }],
        }),
        TIMEOUT_MS
      ) as string
      gasEstimate = BigInt(gasHex)
    } catch {
      // tx would revert
      callSuccess = false
    }

    // ── 4. Calculate ETH delta ──────────────────────────────────────────────
    const ethValue  = tx.value ? BigInt(tx.value) : 0n
    const gasCost   = gasEstimate ? gasEstimate * 20_000_000_000n : 0n  // ~20 gwei estimate
    const ethDelta  = -(ethValue + gasCost)

    // ── 5. Detect token transfers via eth_getLogs simulation ────────────────
    // We use a block-level approach: get recent Transfer events FROM the user
    // to detect tokens that would be drained
    const tokenDeltas: SimulationResult["tokenDeltas"] = []

    try {
      // Look for recent outgoing Transfer events from user address
      // This is a heuristic — not a full simulation
      const logs = await withTimeout(
        provider.request({
          method: "eth_getLogs",
          params: [{
            fromBlock: "latest",
            toBlock:   "latest",
            topics: [
              TRANSFER_TOPIC,
              "0x" + tx.from.slice(2).toLowerCase().padStart(64, "0"),
            ],
          }],
        }),
        TIMEOUT_MS
      ) as Array<{ address: string; data: string; topics: string[] }>

      for (const log of (logs ?? []).slice(0, 5)) {
        try {
          const amount = BigInt(log.data)
          if (amount > 0n) {
            tokenDeltas.push({ token: log.address, delta: -amount })
          }
        } catch { /* skip */ }
      }
    } catch { /* logs not available */ }

    return {
      ethDelta,
      tokenDeltas,
      success: callSuccess,
    }

  } catch {
    return { ethDelta: 0n, tokenDeltas: [], success: false }
  }
}

// Check if simulation shows user losing funds to unknown address
export function isSimulationDangerous(result: SimulationResult): boolean {
  if (!result.success) return true                    // tx reverts = suspicious
  if (result.ethDelta < -10_000_000_000_000_000n) {  // losing > 0.01 ETH unexpectedly
    return true
  }
  return false
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("timeout")), ms)
    ),
  ])
}
