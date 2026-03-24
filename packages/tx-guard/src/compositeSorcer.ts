// Composite scoring — multiple weak signals = one strong verdict
// Solves the problem where each detector fires independently
// and misses patterns that only become clear in combination
//
// Example: new contract + medium heuristic + suspicious multicall
//          = none of them critical alone, but together = critical

import type { TxScamReason } from "./types.js"
import type { DetectionResult } from "./detector.js"
import type { DelegationRisk }  from "./delegationDetector.js"

export interface CompositeSignal {
  reason:     string
  weight:     number    // 0–100 contribution to total score
  fired:      boolean
}

export interface CompositeResult {
  totalScore:  number           // 0–100
  fired:       boolean          // score >= threshold
  reason:      TxScamReason | null
  confidence:  number
  signals:     CompositeSignal[]
  warning:     string | null
}

const COMPOSITE_THRESHOLD = 60   // score needed to flag as scam

export function runCompositeScoring(
  baseDetection: DetectionResult,
  delegation:    DelegationRisk,
  contractAge:   number | null,
  ethValue:      bigint,
  hasMulticall:  boolean,
  isProxy:       boolean,
  proxyImplAge:  number | null,
): CompositeResult {

  const signals: CompositeSignal[] = []
  let totalScore = 0

  // ── Already detected by primary detector ─────────────────────────────────
  if (baseDetection.detected && baseDetection.confidence >= 80) {
    return {
      totalScore:  baseDetection.confidence,
      fired:       true,
      reason:      baseDetection.reason,
      confidence:  baseDetection.confidence,
      signals:     [{ reason: baseDetection.reason ?? "detected", weight: baseDetection.confidence, fired: true }],
      warning:     baseDetection.warning,
    }
  }

  // ── Accumulate weak signals ────────────────────────────────────────────────

  // Delegation to unknown address (medium confidence alone)
  if (delegation.detected && delegation.confidence < 80) {
    const w = 35
    totalScore += w
    signals.push({ reason: "delegation_to_unknown", weight: w, fired: true })
  }

  // New contract receiving ETH
  if (contractAge !== null && contractAge < 30 && ethValue > 0n) {
    const w = contractAge < 7 ? 30 : 20
    totalScore += w
    signals.push({ reason: `new_contract_${contractAge}d_with_eth`, weight: w, fired: true })
  }

  // Proxy recently upgraded
  if (isProxy && proxyImplAge !== null && proxyImplAge < 14) {
    const w = proxyImplAge < 7 ? 25 : 15
    totalScore += w
    signals.push({ reason: `proxy_upgraded_${proxyImplAge}d_ago`, weight: w, fired: true })
  }

  // Multicall present (weak signal alone, amplifies others)
  if (hasMulticall) {
    const w = 15
    totalScore += w
    signals.push({ reason: "multicall_present", weight: w, fired: true })
  }

  // Base detection fired at medium confidence
  if (baseDetection.detected && baseDetection.confidence >= 50) {
    const w = baseDetection.confidence * 0.5
    totalScore += w
    signals.push({ reason: baseDetection.reason ?? "medium_detection", weight: w, fired: true })
  }

  const fired = totalScore >= COMPOSITE_THRESHOLD

  if (!fired) {
    return { totalScore, fired: false, reason: null, confidence: 0, signals, warning: null }
  }

  // Determine dominant reason
  const dominantReason = resolveDominantReason(signals, baseDetection, delegation)
  const confidence     = Math.min(Math.round(totalScore), 95)

  return {
    totalScore,
    fired,
    reason:    dominantReason,
    confidence,
    signals,
    warning: buildCompositeWarning(signals, confidence),
  }
}

function resolveDominantReason(
  signals:    CompositeSignal[],
  base:       DetectionResult,
  delegation: DelegationRisk,
): TxScamReason {
  if (delegation.detected) return "ice_phishing"
  if (base.reason)         return base.reason
  if (signals.some(s => s.reason.includes("proxy"))) return "proxy_recently_upgraded"
  if (signals.some(s => s.reason.includes("new_contract"))) return "new_contract"
  return "suspicious_multicall"
}

function buildCompositeWarning(signals: CompositeSignal[], confidence: number): string {
  const fired = signals.filter(s => s.fired)
  return [
    `⚠️ Multiple suspicious signals detected (confidence: ${confidence}%)`,
    ``,
    `Signals:`,
    ...fired.map(s => `  • ${s.reason} (+${Math.round(s.weight)}pts)`),
    ``,
    `No single signal is conclusive but the combination indicates high risk.`,
    `Verify this transaction carefully before signing.`,
  ].join("\n")
}
