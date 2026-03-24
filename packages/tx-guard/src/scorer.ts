import type { RiskLevel } from "@hexora/core"
import type { TxScamReason } from "./types.js"

export function getRiskLevel(reason: TxScamReason | null, confidence: number): RiskLevel {
  if (!reason) return "none"
  switch (reason) {
    case "set_approval_for_all":    return "critical"
    case "permit_drain":            return confidence >= 85 ? "critical" : "high"
    case "permit2_drain":           return "critical"
    case "ice_phishing":            return "critical"
    case "delegation_abuse":        return "critical"
    case "unlimited_approval":      return confidence >= 85 ? "critical" : "high"
    case "seaport_order_spoof":     return "high"
    case "suspicious_multicall":    return "high"
    case "proxy_recently_upgraded": return "high"
    case "simulation_loss":         return "high"
    case "fake_token_airdrop":      return "high"
    case "new_contract":            return confidence >= 75 ? "high" : "medium"
    case "eth_value_mismatch":      return "high"
    default:                        return "medium"
  }
}
