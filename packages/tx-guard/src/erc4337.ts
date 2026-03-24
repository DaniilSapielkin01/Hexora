// ERC-4337 Account Abstraction UserOperation analysis
// AA transactions have a different structure than regular transactions
// Drainers are increasingly using AA to hide malicious intent
//
// UserOperation structure:
// { sender, nonce, initCode, callData, callGasLimit, ... paymasterAndData, signature }

import { parseCalldata } from "./calldataParser.js"
import { isDelegationMethod } from "./knownProtocols.js"
import { KNOWN_DRAINER_METHOD_IDS } from "./methodIds.js"

// ERC-4337 EntryPoint addresses
export const ENTRY_POINTS = new Set([
  "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789",  // EntryPoint v0.6
  "0x0000000071727de22e5e9d8baf0edac6f37da032",  // EntryPoint v0.7
])

export interface UserOperation {
  sender:               string
  nonce:                string
  initCode?:            string
  callData:             string
  callGasLimit?:        string
  verificationGasLimit?: string
  preVerificationGas?:  string
  maxFeePerGas?:        string
  maxPriorityFeePerGas?: string
  paymasterAndData?:    string
  signature?:           string
}

export interface UserOpRisk {
  detected:   boolean
  reason:     string | null
  confidence: number
  warning:    string | null
  signals:    string[]
}

export function analyzeUserOperation(userOp: UserOperation): UserOpRisk {
  const signals: string[] = []
  let maxConfidence = 0
  let topReason: string | null = null
  let topWarning: string | null = null

  // ── 1. New account deployment (initCode not empty) ────────────────────────
  // Drainers deploy fresh contracts for each victim
  if (userOp.initCode && userOp.initCode !== "0x") {
    signals.push("deploys_new_contract")
    // initCode first 20 bytes = factory address
    const factory = "0x" + userOp.initCode.slice(2, 42)
    signals.push(`factory: ${factory}`)
  }

  // ── 2. Analyze callData ───────────────────────────────────────────────────
  if (userOp.callData && userOp.callData !== "0x") {
    const parsed = parseCalldata(userOp.callData)

    if (parsed.methodId) {
      // Check for known drainer methods
      if (KNOWN_DRAINER_METHOD_IDS.has(parsed.methodId)) {
        signals.push("drainer_method_in_calldata")
        maxConfidence = Math.max(maxConfidence, 88)
        topReason  = "ice_phishing"
        topWarning = `UserOperation contains known drainer method (${parsed.methodId})`
      }

      // Check for delegation methods
      const delegation = isDelegationMethod(parsed.methodId)
      if (delegation) {
        signals.push("delegation_in_userop")
        maxConfidence = Math.max(maxConfidence, 82)
        topReason  = "delegation_abuse"
        topWarning = `UserOperation grants delegation via ${delegation} — this can allow draining your funds`
      }

      // Unlimited approval in AA transaction
      if (parsed.amount !== null && parsed.amount === 2n ** 256n - 1n) {
        signals.push("unlimited_approval_in_userop")
        maxConfidence = Math.max(maxConfidence, 85)
        topReason  = "unlimited_approval"
        topWarning = `UserOperation contains unlimited token approval to ${parsed.spender}`
      }
    }
  }

  // ── 3. Suspicious paymasterAndData ───────────────────────────────────────
  // Paymaster paying gas = someone else is funding this tx = suspicious
  if (userOp.paymasterAndData && userOp.paymasterAndData !== "0x") {
    signals.push("sponsored_transaction")
    // Not necessarily malicious but worth noting
  }

  // ── 4. Multiple signals in one UserOp ────────────────────────────────────
  if (signals.length >= 3) {
    maxConfidence = Math.min(maxConfidence + 15, 97)
  }

  const detected = maxConfidence >= 50

  return {
    detected,
    reason:     topReason,
    confidence: maxConfidence,
    warning:    topWarning,
    signals,
  }
}

// Check if a transaction is targeting an EntryPoint (AA transaction)
export function isAATransaction(toAddress: string): boolean {
  return ENTRY_POINTS.has(toAddress.toLowerCase())
}

// Extract UserOperation from callData of EntryPoint transaction
// EntryPoint.handleOps(UserOperation[],address) = 0x1fad948c
export function extractUserOp(callData: string): UserOperation | null {
  if (!callData || callData.length < 10) return null
  const methodId = callData.slice(0, 10)
  if (methodId !== "0x1fad948c") return null

  try {
    // Simplified extraction — gets the callData field from first UserOp
    // Full ABI decoding would need a proper library
    const params = callData.slice(10)
    // UserOp callData starts at a known offset in the ABI encoding
    // This is a simplified heuristic
    return {
      sender:   "0x" + params.slice(24, 64),
      nonce:    "0x" + params.slice(64, 128),
      callData: "0x" + params.slice(128, 256),
    }
  } catch {
    return null
  }
}
