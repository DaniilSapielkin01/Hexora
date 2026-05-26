// Dynamic ABI decoding via Etherscan API
// Fetches verified ABI for contract and decodes calldata
// Falls back to methodId lookup if API unavailable
//
// Why this matters: if attacker renames a dangerous function,
// our hardcoded methodIds won't catch it.
// With ABI decoding we read the actual function signature from Etherscan.

import type { EIP1193Provider } from "@hexora/core"
import { HTTP_TIMEOUT_MS, logEvent } from "@hexora/core"

// Etherscan-compatible API endpoints per chain
const EXPLORER_APIS: Record<string, string> = {
  "0x1":    "https://api.etherscan.io/api",
  "0x38":   "https://api.bscscan.com/api",
  "0x89":   "https://api.polygonscan.com/api",
  "0xa":    "https://api-optimistic.etherscan.io/api",
  "0xa4b1": "https://api.arbiscan.io/api",
  "0x2105": "https://api.basescan.org/api",
}

export interface DecodedFunction {
  name:      string
  signature: string
  inputs:    Array<{ name: string; type: string; value: string }>
}

// Cache to avoid repeated API calls for same contract.
// Bounded LRU: Map preserves insertion order, so deleting the oldest key on
// overflow gives us O(1) LRU semantics without an extra data structure.
const ABI_CACHE_MAX = 500
const abiCache = new Map<string, DecodedFunction | null>()

function cacheSet(key: string, value: DecodedFunction | null): void {
  if (abiCache.has(key)) abiCache.delete(key)
  abiCache.set(key, value)
  if (abiCache.size > ABI_CACHE_MAX) {
    const oldest = abiCache.keys().next().value
    if (oldest !== undefined) abiCache.delete(oldest)
  }
}

function cacheGet(key: string): DecodedFunction | null | undefined {
  if (!abiCache.has(key)) return undefined
  const v = abiCache.get(key)
  // Touch on access — move to most-recently-used end.
  abiCache.delete(key)
  abiCache.set(key, v ?? null)
  return v
}

// keccak256 implementation must be injected by the caller. We avoid bundling a
// crypto lib here so consumers can pick their own (ethers, js-sha3, viem, etc.)
// without us forcing a transitive dep on the published npm package.
// Without it, ABI matching is disabled and the function returns null after fetch.
export type Keccak256Fn = (input: string) => string

export async function decodeCalldata(
  contractAddress: string,
  calldata:        string,
  chainId:         string,
  apiKey?:         string,
  keccak256?:      Keccak256Fn
): Promise<DecodedFunction | null> {
  if (!calldata || calldata === "0x" || calldata.length < 10) return null
  if (!keccak256) return null

  const cacheKey = `${chainId}:${contractAddress.toLowerCase()}`
  const cached = cacheGet(cacheKey)
  if (cached !== undefined) {
    return cached ? decodeWithAbi(cached.signature, calldata) : null
  }

  const apiBase = EXPLORER_APIS[chainId]
  if (!apiBase) {
    cacheSet(cacheKey, null)
    return null
  }

  try {
    const url = new URL(apiBase)
    url.searchParams.set("module",  "contract")
    url.searchParams.set("action",  "getabi")
    url.searchParams.set("address", contractAddress)
    if (apiKey) url.searchParams.set("apikey", apiKey)

    const controller = new AbortController()
    const timeout    = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS)

    const res  = await fetch(url.toString(), { signal: controller.signal })
    clearTimeout(timeout)

    if (!res.ok) {
      logEvent("warn", "abiDecoder", "explorer http error",
        { chainId, status: res.status })
      cacheSet(cacheKey, null); return null
    }

    const data = await res.json() as { status: string; result: string }
    if (data.status !== "1") {
      // Common: contract not verified — expected, log at debug.
      logEvent("debug", "abiDecoder", "abi not available",
        { chainId, contract: contractAddress, result: data.result })
      cacheSet(cacheKey, null); return null
    }

    // Parse ABI and find matching function
    const abi      = JSON.parse(data.result) as Array<{ type: string; name: string; inputs: Array<{ name: string; type: string }> }>
    const methodId = calldata.slice(0, 10).toLowerCase()

    for (const item of abi) {
      if (item.type !== "function") continue
      const sig  = `${item.name}(${item.inputs.map(i => i.type).join(",")})`
      const hash = methodIdFromSig(sig, keccak256)

      if (hash === methodId) {
        const decoded: DecodedFunction = {
          name:      item.name,
          signature: sig,
          inputs:    decodeParams(calldata.slice(10), item.inputs),
        }
        cacheSet(cacheKey, decoded)
        return decoded
      }
    }

    cacheSet(cacheKey, null)
    return null
  } catch (err) {
    logEvent("warn", "abiDecoder", "fetch failed",
      { chainId, contract: contractAddress,
        error: err instanceof Error ? err.message : String(err) })
    cacheSet(cacheKey, null)
    return null
  }
}

// Detect dangerous function names even if methodId is unknown
// This catches renamed versions of delegation/approval functions
const DANGEROUS_FUNCTION_PATTERNS = [
  /delegate/i,
  /operator/i,
  /approval/i,
  /allowance/i,
  /borrow.*behalf/i,
  /withdraw.*behalf/i,
  /transfer.*from/i,
]

export function isDangerousFunctionName(name: string): boolean {
  return DANGEROUS_FUNCTION_PATTERNS.some(p => p.test(name))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function decodeWithAbi(signature: string, calldata: string): DecodedFunction {
  const name   = signature.split("(")[0] ?? signature
  return { name, signature, inputs: [] }
}

function decodeParams(
  params: string,
  inputs: Array<{ name: string; type: string }>
): Array<{ name: string; type: string; value: string }> {
  const result = []
  for (let i = 0; i < inputs.length; i++) {
    const input  = inputs[i]
    if (!input) continue
    const offset = i * 64
    const slice  = params.slice(offset, offset + 64)
    let value    = slice

    if (input.type === "address") {
      value = "0x" + slice.slice(24)
    } else if (input.type === "bool") {
      value = slice.endsWith("1") ? "true" : "false"
    } else if (input.type.startsWith("uint")) {
      try { value = BigInt("0x" + slice).toString() } catch { /* keep hex */ }
    }

    result.push({ name: input.name, type: input.type, value })
  }
  return result
}

// Compute 4-byte function selector from canonical signature using the
// caller-provided keccak256. Expected output: "0x" + 8 hex chars, lowercased.
function methodIdFromSig(sig: string, keccak256?: Keccak256Fn): string {
  if (!keccak256) return ""
  const h = keccak256(sig).toLowerCase()
  const hex = h.startsWith("0x") ? h : `0x${h}`
  return hex.slice(0, 10)
}
