// ERC-4337 Account Abstraction UserOperation detector
// AA transactions have different structure than regular transactions
// Drainers are increasingly using AA to obfuscate their attacks
//
// In AA: user signs UserOperation → Bundler sends handleOps() → EntryPoint executes
// The "real" transaction is handleOps() which contains the user's intent inside

import { AA_METHOD_IDS } from "./knownProtocols.js"
import type { RawTransaction } from "./types.js"

// ERC-4337 EntryPoint addresses (official deployments)
const ENTRY_POINTS = new Set([
  "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789",  // EntryPoint v0.6
  "0x0576a174d229e3cfa37253523e645a78a0c91b57",  // EntryPoint v0.6 (alt)
  "0x4337084d9e255ff0702461cf8895ce9e3b5ff108",  // EntryPoint v0.7
])

export interface AADetectionResult {
  isAA:           boolean
  isEntryPoint:   boolean
  methodName:     string | null
  innerCallCount: number   // how many ops bundled inside
  warning:        string | null
}

export function detectAATransaction(tx: RawTransaction): AADetectionResult {
  const clean: AADetectionResult = {
    isAA: false, isEntryPoint: false,
    methodName: null, innerCallCount: 0, warning: null,
  }

  const data = tx.data ?? "0x"
  if (!data || data === "0x" || data.length < 10) return clean

  const hex      = data.startsWith("0x") ? data.slice(2) : data
  const methodId = "0x" + hex.slice(0, 8).toLowerCase()
  const toAddr   = tx.to?.toLowerCase() ?? ""

  const methodName = AA_METHOD_IDS.get(methodId)
  const isEntryPoint = ENTRY_POINTS.has(toAddr)

  // handleOps — bundler submitting user operations
  if (methodId === "0x1fad948c" || methodId === "0x765e827f") {
    return {
      isAA:           true,
      isEntryPoint,
      methodName:     methodName ?? "handleOps",
      innerCallCount: estimateOpCount(hex),
      warning: isEntryPoint
        ? null  // Legitimate EntryPoint call
        : `This transaction calls handleOps on an unknown contract. This may be an Account Abstraction exploit. Verify the EntryPoint address.`,
    }
  }

  // Safe/AA execute — single operation execution
  if (methodId === "0xb61d27f6") {
    return {
      isAA:           true,
      isEntryPoint:   false,
      methodName:     "execute",
      innerCallCount: 1,
      warning:        null,  // execute is normal for Safe wallets
    }
  }

  // multiSend — Safe batch operation
  if (methodId === "0x8d80ff0a") {
    const opCount = estimateMultiSendCount(hex)
    return {
      isAA:           true,
      isEntryPoint:   false,
      methodName:     "multiSend",
      innerCallCount: opCount,
      warning: opCount > 3
        ? `This multiSend bundles ${opCount} operations. Review all operations carefully — drainers hide malicious calls in batch transactions.`
        : null,
    }
  }

  return clean
}

// Rough estimate of operations count in handleOps calldata
function estimateOpCount(hex: string): number {
  // Each UserOperation is at minimum 32 bytes of header
  // This is a rough heuristic — proper decoding needs ABI
  const paramsLen = hex.length - 8
  return Math.max(1, Math.floor(paramsLen / 640))
}

// Estimate number of operations in multiSend
function estimateMultiSendCount(hex: string): number {
  // multiSend packs operations: 1 byte op type + 20 bytes to + 32 bytes value + 32 bytes dataLen + data
  // Minimum 85 bytes per operation = 170 hex chars
  const paramsLen = hex.length - 8
  return Math.max(1, Math.floor(paramsLen / 170))
}
