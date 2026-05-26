import type { ChainId, ScamReason, RiskLevel, CheckError } from "@hexora/core";
import type { CheckResult, CheckDetails } from "./types.js";

export interface ScorerInput {
  chain: ChainId;
  userAddress: string;
  inputAddress: string;
  historyScanned: number;
  similarityScore: number;
  matchedAddress: string | null;
  zeroValueFound: boolean;
  batchPoisonFound: boolean;
  dustFound: boolean;
  transferFromFound: boolean;
  inputAddrDetection: {
    detected: boolean;
    reason: ScamReason | null;
    confidence: number;
  };
}

export function buildResult(input: ScorerInput): CheckResult {
  const signals: { reason: ScamReason; weight: number }[] = [];

  if (input.batchPoisonFound)
    signals.push({ reason: "batch_poisoning", weight: 100 });
  if (input.transferFromFound)
    signals.push({ reason: "transferfrom_spoofing", weight: 95 });
  if (input.zeroValueFound)
    signals.push({ reason: "zero_value_transfer", weight: 90 });
  if (
    input.inputAddrDetection.detected &&
    input.inputAddrDetection.reason !== null
  )
    signals.push({
      reason: input.inputAddrDetection.reason,
      weight: input.inputAddrDetection.confidence,
    });
  // Trust the upstream similarity match: findMostSimilar already filtered by
  // the caller-supplied threshold (default 85, but can be lowered). Re-gating
  // on a hardcoded 85 here would silently discard valid lowered-threshold
  // matches.
  if (input.matchedAddress !== null && input.similarityScore > 0)
    signals.push({
      reason: "address_poisoning",
      weight: input.similarityScore,
    });
  if (input.dustFound) signals.push({ reason: "dust_attack", weight: 70 });

  signals.sort((a, b) => b.weight - a.weight);
  const top = signals[0];
  const riskScore = top?.weight ?? 0;

  // Multi-signal amplifier: each additional signal beyond the top one adds
  // 7 points to confidence (capped at 100). This rewards composite evidence
  // — three independent medium signals are stronger than one isolated one
  // and the previous +3-per-signal under-rewarded that.
  const extra = Math.max(0, signals.length - 1);
  const confidence = Math.min(100, riskScore + extra * 7);

  // Scam flag: any single >=70, OR a combination of >=2 signals where the
  // strongest is at least 50. Catches drip-attack patterns where no single
  // signal is conclusive but the pile is unambiguous.
  const scam =
    top !== undefined &&
    (riskScore >= 70 || (signals.length >= 2 && riskScore >= 50));

  const details: CheckDetails = {
    chain: input.chain,
    userAddress: input.userAddress,
    inputAddress: input.inputAddress,
    historyScanned: input.historyScanned,
    poisonTxFound: input.batchPoisonFound || input.transferFromFound,
    zeroValueFound: input.zeroValueFound,
    dustFound: input.dustFound,
  };

  return {
    scam,
    reason: top?.reason ?? null,
    riskLevel: toRiskLevel(riskScore, signals.length),
    similarityScore: input.similarityScore,
    confidence,
    matchedAddress: input.matchedAddress,
    details,
    error: null,
  };
}

function toRiskLevel(score: number, count: number): RiskLevel {
  if (score === 0) return "none";
  if (score < 50) return "low";
  if (score < 70) return "medium";
  if (score >= 90 || (score >= 80 && count >= 2)) return "critical";
  return "high";
}

export function buildErrorResult(
  code: string,
  message: string,
  chain: ChainId = "ethereum"
): CheckResult {
  return {
    scam: false,
    reason: null,
    riskLevel: "none",
    similarityScore: 0,
    confidence: 0,
    matchedAddress: null,
    details: {
      chain,
      userAddress: "",
      inputAddress: "",
      historyScanned: 0,
      poisonTxFound: false,
      zeroValueFound: false,
      dustFound: false,
    },
    error: { code: code as CheckError["code"], message },
  };
}
