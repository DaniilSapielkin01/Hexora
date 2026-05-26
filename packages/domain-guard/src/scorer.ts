import type { RiskLevel } from "@hexora/core"
import type { DetectionResult } from "./detector.js"
import type { CheckDomainResult } from "./types.js"

export function buildDomainResult(
  domain: string,
  detection: DetectionResult
): Omit<CheckDomainResult, "error"> {
  return {
    scam:            detection.detected,
    reason:          detection.reason,
    riskLevel:       getRiskLevel(detection),
    confidence:      detection.confidence,
    domain,
    matchedLegit:    detection.matchedLegit,
    similarityScore: detection.similarityScore,
    details: {
      ...detection.details,
      domainAge: {
        checked: false, ageInDays: null,
        isVeryNew: false, isNew: false, isRecent: false, registrar: null,
      },
    },
  }
}

function getRiskLevel(detection: DetectionResult): RiskLevel {
  if (!detection.detected) {
    if (detection.details.heuristicScore >= 20) return "low"
    return "none"
  }
  switch (detection.reason) {
    case "blacklisted_domain": return "critical"
    case "homoglyph":          return "critical"
    case "subdomain_hijack":   return "high"
    case "idn_suspicious":     return "high"
    case "new_domain":         return "medium"
    case "nft_spam_domain":
      return detection.confidence >= 70 ? "high" : "medium"
    case "suspicious_domain":
    case "suspicious_tld_combo":
      return detection.confidence >= 55 ? "high" : "medium"
    case "typosquat":
      if (detection.confidence >= 90) return "critical"
      if (detection.confidence >= 75) return "high"
      return "medium"
    default: return "medium"
  }
}
