// Proxy contract implementation change detector
// Many drainer contracts use upgradeable proxies and change implementation
// right before the attack — old implementation was benign, new one drains
//
// EIP-1967 storage slots for proxy implementation:
// https://eips.ethereum.org/EIPS/eip-1967

import type { EIP1193Provider } from "@hexora/core"

const TIMEOUT_MS = 3000

// EIP-1967 implementation slot
// keccak256("eip1967.proxy.implementation") - 1
const EIP1967_IMPL_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

// EIP-1967 beacon slot
const EIP1967_BEACON_SLOT =
  "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

// OpenZeppelin transparent proxy admin slot
const OZ_ADMIN_SLOT =
  "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"

export interface ProxyCheckResult {
  isProxy:              boolean
  implementation:       string | null
  implementationAge:    number | null   // days since impl was set (approx)
  recentlyUpgraded:     boolean         // implementation changed < 7 days ago
  available:            boolean
}

export async function checkProxyImplementation(
  address:  string,
  provider: EIP1193Provider
): Promise<ProxyCheckResult> {
  const notAvailable: ProxyCheckResult = {
    isProxy: false, implementation: null,
    implementationAge: null, recentlyUpgraded: false, available: false,
  }

  try {
    // Try EIP-1967 implementation slot first
    const implSlot = await readStorageSlot(address, EIP1967_IMPL_SLOT, provider)

    if (!implSlot || implSlot === "0x" + "0".repeat(64)) {
      // Not an EIP-1967 proxy — not suspicious
      return { ...notAvailable, available: true }
    }

    // Extract address from storage slot (last 20 bytes)
    const implAddress = "0x" + implSlot.slice(-40)

    if (implAddress === "0x" + "0".repeat(40)) {
      return { ...notAvailable, available: true }
    }

    // Get implementation contract age
    const implAge = await getContractDeployAge(implAddress, provider)

    const recentlyUpgraded = implAge !== null && implAge < 7

    return {
      isProxy:           true,
      implementation:    implAddress,
      implementationAge: implAge,
      recentlyUpgraded,
      available:         true,
    }
  } catch {
    return notAvailable
  }
}

// Get approximate age of contract in days using binary search on eth_getCode
async function getContractDeployAge(
  address:  string,
  provider: EIP1193Provider
): Promise<number | null> {
  try {
    const blockHex = await withTimeout(
      provider.request({ method: "eth_blockNumber", params: [] }),
      TIMEOUT_MS
    ) as string

    const currentBlock = parseInt(blockHex, 16)

    // Quick check: was it deployed in the last 30 days? (~216,000 blocks on Ethereum)
    const lookbackBlocks = 216_000
    const checkBlock     = Math.max(0, currentBlock - lookbackBlocks)

    const codeAtCheckBlock = await withTimeout(
      provider.request({
        method: "eth_getCode",
        params: [address, "0x" + checkBlock.toString(16)],
      }),
      TIMEOUT_MS
    ) as string

    if (codeAtCheckBlock && codeAtCheckBlock !== "0x") {
      // Contract existed 30 days ago — old, not suspicious
      return 30
    }

    // Contract was deployed in last 30 days — binary search for exact block
    let low  = checkBlock
    let high = currentBlock

    for (let i = 0; i < 15; i++) {
      if (high - low <= 1) break
      const mid  = Math.floor((low + high) / 2)
      const code = await withTimeout(
        provider.request({
          method: "eth_getCode",
          params: [address, "0x" + mid.toString(16)],
        }),
        TIMEOUT_MS
      ) as string

      if (code && code !== "0x") high = mid
      else low = mid
    }

    // Get timestamp of deployment block
    const block = await withTimeout(
      provider.request({
        method: "eth_getBlockByNumber",
        params: ["0x" + high.toString(16), false],
      }),
      TIMEOUT_MS
    ) as { timestamp: string } | null

    if (!block?.timestamp) return null

    const deployTime = parseInt(block.timestamp, 16) * 1000
    return Math.floor((Date.now() - deployTime) / (1000 * 60 * 60 * 24))

  } catch {
    return null
  }
}

async function readStorageSlot(
  address:  string,
  slot:     string,
  provider: EIP1193Provider
): Promise<string | null> {
  try {
    const result = await withTimeout(
      provider.request({ method: "eth_getStorageAt", params: [address, slot, "latest"] }),
      TIMEOUT_MS
    ) as string
    return result
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
