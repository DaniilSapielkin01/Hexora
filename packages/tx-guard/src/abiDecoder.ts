// Dynamic ABI decoding via Etherscan API
// Fetches verified ABI for contract and decodes calldata
// Falls back to methodId lookup if API unavailable
//
// Why this matters: if attacker renames a dangerous function,
// our hardcoded methodIds won't catch it.
// With ABI decoding we read the actual function signature from Etherscan.

import type { EIP1193Provider } from "@hexora/core"
import { HTTP_TIMEOUT_MS, logEvent } from "@hexora/core"
import { keccak256, toBytes, decodeAbiParameters, type AbiParameter } from "viem"

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

// Caller may pass a custom keccak256 (e.g. a faster native binding); by
// default we use viem's. Signature: takes the canonical function signature
// string ("approve(address,uint256)") and returns the 0x-prefixed 32-byte
// hash; we slice the first 4 bytes for the selector.
export type Keccak256Fn = (input: string) => string

const defaultKeccak: Keccak256Fn = (s) => keccak256(toBytes(s))

export async function decodeCalldata(
  contractAddress: string,
  calldata:        string,
  chainId:         string,
  apiKey?:         string,
  customKeccak?:   Keccak256Fn
): Promise<DecodedFunction | null> {
  if (!calldata || calldata === "0x" || calldata.length < 10) return null
  const hashFn = customKeccak ?? defaultKeccak

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
      const hash = methodIdFromSig(sig, hashFn)

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

// Decode params via viem — handles full ABI spec (dynamic types, tuples,
// arrays). Previously we did fixed-32-byte-slot extraction which was wrong
// for `bool` (uint→endsWith heuristic) and broken for any dynamic type.
function decodeParams(
  params: string,
  inputs: Array<{ name: string; type: string }>
): Array<{ name: string; type: string; value: string }> {
  if (inputs.length === 0) return []
  try {
    const abiParams = inputs.map(i => ({ name: i.name, type: i.type } as AbiParameter))
    const data = `0x${params}` as `0x${string}`
    const values = decodeAbiParameters(abiParams, data)
    return inputs.map((input, i) => ({
      name:  input.name,
      type:  input.type,
      value: stringifyAbiValue(values[i]),
    }))
  } catch {
    // Malformed calldata — return inputs with empty values rather than
    // throwing, so downstream detectors keep working on the function name.
    return inputs.map(input => ({ name: input.name, type: input.type, value: "" }))
  }
}

function stringifyAbiValue(v: unknown): string {
  if (v === null || v === undefined) return ""
  if (typeof v === "bigint") return v.toString()
  if (typeof v === "string") return v
  if (typeof v === "boolean") return v ? "true" : "false"
  try { return JSON.stringify(v, (_, x) => typeof x === "bigint" ? x.toString() : x) }
  catch { return String(v) }
}

// Compute 4-byte function selector from canonical signature.
function methodIdFromSig(sig: string, hashFn: Keccak256Fn): string {
  const h = hashFn(sig).toLowerCase()
  const hex = h.startsWith("0x") ? h : `0x${h}`
  return hex.slice(0, 10)
}
