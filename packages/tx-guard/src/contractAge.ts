// Check contract deployment age via RPC
// Uses eth_getTransactionByHash on the contract creation tx
// Requires provider — gracefully returns null if unavailable

import type { EIP1193Provider } from "@hexora/core"

const TIMEOUT_MS = 3000

export async function getContractAge(
  address: string,
  provider: EIP1193Provider
): Promise<number | null> {
  try {
    // eth_getCode — check if it's actually a contract
    const code = await withTimeout(
      provider.request({ method: "eth_getCode", params: [address, "latest"] }),
      TIMEOUT_MS
    ) as string

    if (!code || code === "0x") return null  // EOA, not a contract

    // Get contract creation tx via eth_getTransactionReceipt doesn't give us
    // creation info directly — we use a trick: get the first block the contract
    // appears in by checking the nonce of the creator
    // Simplified: get current block timestamp and compare with block where
    // the contract was first seen — using eth_getStorageAt trick
    // For a clean implementation without external APIs, we check
    // transaction count at block 0 vs now for the contract address

    // Get current block number
    const blockHex = await withTimeout(
      provider.request({ method: "eth_blockNumber", params: [] }),
      TIMEOUT_MS
    ) as string

    const currentBlock = parseInt(blockHex, 16)

    // Binary search for the deployment block
    const deployBlock = await findDeploymentBlock(address, provider, currentBlock)
    if (deployBlock === null) return null

    // Get block timestamp
    const block = await withTimeout(
      provider.request({
        method: "eth_getBlockByNumber",
        params: ["0x" + deployBlock.toString(16), false],
      }),
      TIMEOUT_MS
    ) as { timestamp: string } | null

    if (!block?.timestamp) return null

    const deployTimestamp = parseInt(block.timestamp, 16) * 1000
    const ageInDays = Math.floor((Date.now() - deployTimestamp) / (1000 * 60 * 60 * 24))

    return ageInDays
  } catch {
    return null
  }
}

// Binary search for the block where contract was first deployed
// Uses eth_getCode at specific blocks — contract won't exist before deployment
async function findDeploymentBlock(
  address: string,
  provider: EIP1193Provider,
  currentBlock: number,
  maxIterations = 20
): Promise<number | null> {
  try {
    let low  = Math.max(0, currentBlock - 2_000_000)  // look back ~1 year max
    let high = currentBlock

    for (let i = 0; i < maxIterations; i++) {
      if (high - low <= 1) return high

      const mid  = Math.floor((low + high) / 2)
      const code = await withTimeout(
        provider.request({
          method: "eth_getCode",
          params: [address, "0x" + mid.toString(16)],
        }),
        TIMEOUT_MS
      ) as string

      if (code && code !== "0x") {
        high = mid  // contract exists here, look earlier
      } else {
        low = mid   // contract doesn't exist here, look later
      }
    }

    return high
  } catch {
    return null
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("timeout")), ms)
    ),
  ])
}
