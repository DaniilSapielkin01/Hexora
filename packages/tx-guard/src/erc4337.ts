// ERC-4337 Account Abstraction UserOperation analysis
// AA transactions have a different structure than regular transactions
// Drainers are increasingly using AA to hide malicious intent
//
// UserOperation structure:
// { sender, nonce, initCode, callData, callGasLimit, ... paymasterAndData, signature }

import { decodeFunctionData, parseAbi } from "viem"
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

// EntryPoint selectors.
const HANDLE_OPS_V06_SELECTOR = "0x1fad948c"   // v0.6
const HANDLE_OPS_V07_SELECTOR = "0x765e827f"   // v0.7 (packed)

// Detect whether the given callData is an EntryPoint.handleOps call (any version).
export function isHandleOpsCalldata(callData: string): boolean {
  if (!callData || callData.length < 10) return false
  const sel = callData.slice(0, 10).toLowerCase()
  return sel === HANDLE_OPS_V06_SELECTOR || sel === HANDLE_OPS_V07_SELECTOR
}

// v0.6 — UserOperation tuple has 11 fields.
const HANDLE_OPS_V06_ABI = parseAbi([
  "function handleOps((address sender, uint256 nonce, bytes initCode, bytes callData, uint256 callGasLimit, uint256 verificationGasLimit, uint256 preVerificationGas, uint256 maxFeePerGas, uint256 maxPriorityFeePerGas, bytes paymasterAndData, bytes signature)[] ops, address beneficiary)",
])

// v0.7 — fields packed into bytes32 (accountGasLimits, gasFees) for cheaper
// calldata. We decode into the same v0.6-shaped UserOperation by unpacking.
const HANDLE_OPS_V07_ABI = parseAbi([
  "function handleOps((address sender, uint256 nonce, bytes initCode, bytes callData, bytes32 accountGasLimits, uint256 preVerificationGas, bytes32 gasFees, bytes paymasterAndData, bytes signature)[] ops, address beneficiary)",
])

// Extract UserOperations from EntryPoint.handleOps calldata.
// Returns [] if the calldata isn't handleOps or fails to decode. Uses viem
// so we don't maintain a hand-rolled dynamic ABI decoder (previous version
// returned garbage from fixed-offset slicing).
export function extractUserOps(callData: string): UserOperation[] {
  if (!isHandleOpsCalldata(callData)) return []
  const data = callData as `0x${string}`
  const sel  = callData.slice(0, 10).toLowerCase()
  try {
    if (sel === HANDLE_OPS_V06_SELECTOR) {
      const { args } = decodeFunctionData({ abi: HANDLE_OPS_V06_ABI, data })
      return (args[0] as ReadonlyArray<V06Op>).map(toUserOp_V06)
    }
    const { args } = decodeFunctionData({ abi: HANDLE_OPS_V07_ABI, data })
    return (args[0] as ReadonlyArray<V07Op>).map(toUserOp_V07)
  } catch {
    return []
  }
}

type V06Op = {
  sender: string; nonce: bigint;
  initCode: string; callData: string;
  callGasLimit: bigint; verificationGasLimit: bigint;
  preVerificationGas: bigint; maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  paymasterAndData: string; signature: string;
}

type V07Op = {
  sender: string; nonce: bigint;
  initCode: string; callData: string;
  accountGasLimits: string;
  preVerificationGas: bigint;
  gasFees: string;
  paymasterAndData: string; signature: string;
}

function toUserOp_V06(op: V06Op): UserOperation {
  return {
    sender:               op.sender,
    nonce:                "0x" + op.nonce.toString(16),
    initCode:             op.initCode,
    callData:             op.callData,
    callGasLimit:         "0x" + op.callGasLimit.toString(16),
    verificationGasLimit: "0x" + op.verificationGasLimit.toString(16),
    preVerificationGas:   "0x" + op.preVerificationGas.toString(16),
    maxFeePerGas:         "0x" + op.maxFeePerGas.toString(16),
    maxPriorityFeePerGas: "0x" + op.maxPriorityFeePerGas.toString(16),
    paymasterAndData:     op.paymasterAndData,
    signature:            op.signature,
  }
}

// Unpack v0.7 bytes32 fields: high 16 bytes + low 16 bytes per field.
function toUserOp_V07(op: V07Op): UserOperation {
  const [verificationGasLimit, callGasLimit]    = splitBytes32(op.accountGasLimits)
  const [maxPriorityFeePerGas, maxFeePerGas]    = splitBytes32(op.gasFees)
  return {
    sender:               op.sender,
    nonce:                "0x" + op.nonce.toString(16),
    initCode:             op.initCode,
    callData:             op.callData,
    callGasLimit:         "0x" + callGasLimit.toString(16),
    verificationGasLimit: "0x" + verificationGasLimit.toString(16),
    preVerificationGas:   "0x" + op.preVerificationGas.toString(16),
    maxFeePerGas:         "0x" + maxFeePerGas.toString(16),
    maxPriorityFeePerGas: "0x" + maxPriorityFeePerGas.toString(16),
    paymasterAndData:     op.paymasterAndData,
    signature:            op.signature,
  }
}

function splitBytes32(hex: string): [bigint, bigint] {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex
  const high  = clean.slice(0, 32)   // first 16 bytes
  const low   = clean.slice(32, 64)  // last 16 bytes
  return [BigInt("0x" + (high || "0")), BigInt("0x" + (low || "0"))]
}

// Back-compat shim — returns the first UserOp from a handleOps bundle.
export function extractUserOp(callData: string): UserOperation | null {
  const ops = extractUserOps(callData)
  return ops[0] ?? null
}
