import {
  METHOD_APPROVE, METHOD_PERMIT, METHOD_SET_APPROVAL_FOR_ALL,
  METHOD_TRANSFER_FROM, METHOD_PERMIT2_APPROVE, METHOD_PERMIT2_PERMIT,
  METHOD_MULTICALL, METHOD_MULTICALL_DEADLINE,
  KNOWN_DRAINER_METHOD_IDS, KNOWN_ROUTERS,
} from "./methodIds.js"
import { parseCalldata, MAX_UINT256 }  from "./calldataParser.js"
import { analyzeTypedData }            from "./typedDataAnalyzer.js"
import { detectDelegation }            from "./delegationDetector.js"
import { detectAATransaction }         from "./aaDetector.js"
import { runCompositeScoring }         from "./compositeScoring.js"
import type { RawTransaction, TypedDataPayload, TxScamReason, TxCheckDetails } from "./types.js"

export interface DetectionResult {
  detected:   boolean
  reason:     TxScamReason | null
  confidence: number
  warning:    string | null
  details:    TxCheckDetails
}

export function detectTransaction(
  tx:           RawTransaction,
  typedData?:   TypedDataPayload,
  contractAge?: number | null,
  isProxy?:     boolean,
  proxyImplAge?: number | null,
): DetectionResult {
  const data    = tx.data ?? "0x"
  const parsed  = parseCalldata(data)
  const value   = tx.value ? BigInt(tx.value) : 0n
  const toAddr  = tx.to?.toLowerCase() ?? ""

  const details: TxCheckDetails = {
    methodId:          parsed.methodId,
    methodName:        parsed.methodName,
    spender:           parsed.spender ?? parsed.operator,
    amount:            parsed.amount,
    isUnlimitedAmount: parsed.amount === MAX_UINT256,
    contractAge:       contractAge ?? null,
    isProxy:           isProxy ?? false,
    proxyImplAge:      proxyImplAge ?? null,
    simulationResult:  null,
  }

  const hasMulticall = parsed.methodId === METHOD_MULTICALL ||
                       parsed.methodId === METHOD_MULTICALL_DEADLINE

  // ── 0. Typed data signature check ────────────────────────────────────────
  if (typedData) {
    const tdResult = analyzeTypedData(typedData)
    if (tdResult.detected) {
      return {
        detected: true, reason: tdResult.reason as TxScamReason,
        confidence: tdResult.confidence, warning: tdResult.warning,
        details: { ...details, spender: tdResult.spender, amount: tdResult.amount },
      }
    }
  }

  // ── 1. Delegation attack (Venus/Aave/Compound pattern) ────────────────────
  const delegation = detectDelegation(tx)
  if (delegation.detected) {
    return {
      detected: true, reason: "ice_phishing",
      confidence: delegation.confidence,
      warning: delegation.warning,
      details: { ...details, spender: delegation.delegate },
    }
  }

  // ── 2. ERC-4337 AA suspicious patterns ───────────────────────────────────
  const aaResult = detectAATransaction(tx)
  if (aaResult.warning) {
    return {
      detected: true, reason: "suspicious_multicall",
      confidence: 78, warning: aaResult.warning,
      details,
    }
  }

  // ── 3. Known drainer method IDs ───────────────────────────────────────────
  if (parsed.methodId && KNOWN_DRAINER_METHOD_IDS.has(parsed.methodId)) {
    return {
      detected: true, reason: "ice_phishing", confidence: 88,
      warning: `This transaction uses a method associated with known drainer contracts (${parsed.methodId}).`,
      details,
    }
  }

  // ── 4. Unlimited ERC-20 approve ───────────────────────────────────────────
  if (parsed.methodId === METHOD_APPROVE || parsed.methodId === METHOD_PERMIT) {
    const spender = parsed.spender?.toLowerCase() ?? ""
    if (KNOWN_ROUTERS.has(spender)) {
      return { detected: false, reason: null, confidence: 0, warning: null, details }
    }
    if (details.isUnlimitedAmount) {
      return {
        detected: true, reason: "unlimited_approval", confidence: 92,
        warning: `UNLIMITED approval to unknown address ${parsed.spender}. Only approve known DEX routers.`,
        details,
      }
    }
    return {
      detected: true, reason: "unlimited_approval", confidence: 55,
      warning: `Token approval to unverified address ${parsed.spender}.`,
      details,
    }
  }

  // ── 5. setApprovalForAll ──────────────────────────────────────────────────
  if (parsed.methodId === METHOD_SET_APPROVAL_FOR_ALL && parsed.approved === true) {
    const operator = parsed.operator?.toLowerCase() ?? ""
    if (KNOWN_ROUTERS.has(operator)) {
      return { detected: false, reason: null, confidence: 0, warning: null, details }
    }
    return {
      detected: true, reason: "set_approval_for_all", confidence: 95,
      warning: `setApprovalForAll grants access to ALL your NFTs to ${parsed.operator}. Only approve known marketplaces.`,
      details,
    }
  }

  // ── 6. Permit2 ────────────────────────────────────────────────────────────
  if (parsed.methodId === METHOD_PERMIT2_APPROVE || parsed.methodId === METHOD_PERMIT2_PERMIT) {
    const spender = parsed.spender?.toLowerCase() ?? ""
    if (KNOWN_ROUTERS.has(spender)) {
      return { detected: false, reason: null, confidence: 0, warning: null, details }
    }
    return {
      detected: true, reason: "permit2_drain", confidence: 88,
      warning: `Permit2 approval to unknown address ${parsed.spender}.`,
      details,
    }
  }

  // ── 7. transferFrom ice phishing ─────────────────────────────────────────
  if (parsed.methodId === METHOD_TRANSFER_FROM) {
    const fromAddr = parsed.from?.toLowerCase() ?? ""
    const toAddrTx = parsed.to?.toLowerCase() ?? ""
    if (fromAddr === tx.from?.toLowerCase() && !KNOWN_ROUTERS.has(toAddrTx)) {
      return {
        detected: true, reason: "ice_phishing", confidence: 85,
        warning: `This contract moves your tokens to ${parsed.to}. Classic ice phishing pattern.`,
        details,
      }
    }
  }

  // ── 8. Suspicious multicall ───────────────────────────────────────────────
  if (hasMulticall) {
    if (data.includes(METHOD_APPROVE.slice(2)) && data.includes(METHOD_TRANSFER_FROM.slice(2))) {
      return {
        detected: true, reason: "suspicious_multicall", confidence: 82,
        warning: "This multicall bundles an approval with a token transfer — classic drainer pattern.",
        details,
      }
    }
  }

  // ── 9. New contract + ETH ─────────────────────────────────────────────────
  if (contractAge !== null && contractAge !== undefined) {
    if (contractAge < 7 && value > 0n) {
      return {
        detected: true, reason: "new_contract", confidence: 78,
        warning: `Contract deployed ${contractAge} days ago is requesting ETH.`,
        details,
      }
    }
    if (contractAge < 30 && value > 0n) {
      return {
        detected: true, reason: "new_contract", confidence: 60,
        warning: `Contract deployed only ${contractAge} days ago.`,
        details,
      }
    }
  }

  // ── 10. Composite scoring — combine weak signals ──────────────────────────
  const baseResult: DetectionResult = {
    detected: false, reason: null, confidence: 0, warning: null, details,
  }

  const composite = runCompositeScoring(
    { ...baseResult, details: { ...details, simulationResult: null } },
    delegation,
    contractAge ?? null,
    value,
    hasMulticall,
    isProxy ?? false,
    proxyImplAge ?? null,
  )

  if (composite.fired) {
    return {
      detected: true, reason: composite.reason,
      confidence: composite.confidence,
      warning: composite.warning,
      details,
    }
  }

  return { detected: false, reason: null, confidence: 0, warning: null, details }
}
