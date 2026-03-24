// Composite scoring — multiple weak signals together = strong signal
// Solves the problem where each individual check passes but combination is dangerous
//
// Example: approve(unknown) + new contract + ETH value = very suspicious
// Each alone: medium risk. Together: critical.

export interface SignalWeight {
  name:       string
  points:     number
  reason:     string
}

export interface CompositeScore {
  total:      number       // 0–100
  signals:    SignalWeight[]
  riskLevel:  "none" | "low" | "medium" | "high" | "critical"
  dominant:   string | null  // most impactful signal
}

// Signal weights — points added to composite score
const SIGNAL_WEIGHTS = {
  // Transaction patterns
  unlimited_approve_unknown:    45,
  approve_unknown:              25,
  delegation_method:            40,
  delegation_known_protocol:    20,
  set_approval_for_all_unknown: 50,
  permit_unknown:               40,
  permit2_unknown:              40,
  multicall_approve_transfer:   35,
  drainer_method_id:            50,

  // Contract signals
  contract_age_very_new:        25,   // < 7 days
  contract_age_new:             15,   // < 30 days
  contract_age_recent:          8,    // < 90 days
  proxy_recently_upgraded:      30,
  proxy_unknown_impl:           20,

  // Value signals
  eth_value_sent:               10,
  high_eth_value:               20,   // > 1 ETH

  // Context signals
  typed_data_unknown_spender:   35,
  seaport_unknown_recipient:    30,
  token_name_suspicious:        25,

  // Simulation
  simulation_failed:            30,
  simulation_balance_loss:      35,
}

export function buildCompositeScore(activeSignals: Array<keyof typeof SIGNAL_WEIGHTS>): CompositeScore {
  const signals: SignalWeight[] = []
  let total = 0

  for (const signal of activeSignals) {
    const points = SIGNAL_WEIGHTS[signal] ?? 0
    if (points > 0) {
      signals.push({ name: signal, points, reason: signalReason(signal) })
      total += points
    }
  }

  // Combo amplifier — 3+ signals = +15 bonus
  if (signals.length >= 3) {
    total += 15
    signals.push({ name: "combo_amplifier", points: 15, reason: "Multiple risk signals detected simultaneously" })
  } else if (signals.length === 2) {
    total += 8
    signals.push({ name: "combo_amplifier", points: 8, reason: "Two risk signals detected together" })
  }

  total = Math.min(total, 100)

  // Sort by impact
  signals.sort((a, b) => b.points - a.points)
  const dominant = signals[0]?.name ?? null

  return {
    total,
    signals,
    riskLevel: scoreToRisk(total),
    dominant,
  }
}

function scoreToRisk(score: number): CompositeScore["riskLevel"] {
  if (score >= 70) return "critical"
  if (score >= 50) return "high"
  if (score >= 30) return "medium"
  if (score >= 15) return "low"
  return "none"
}

function signalReason(signal: string): string {
  const reasons: Record<string, string> = {
    unlimited_approve_unknown:    "Unlimited approval to unknown address",
    approve_unknown:              "Token approval to unverified address",
    delegation_method:            "Delegation method grants third-party fund access",
    delegation_known_protocol:    "Delegation on known protocol — verify the address",
    set_approval_for_all_unknown: "SetApprovalForAll to unknown operator",
    permit_unknown:               "Permit signature to unknown spender",
    permit2_unknown:              "Permit2 approval to unknown address",
    multicall_approve_transfer:   "Multicall bundles approval with transfer",
    drainer_method_id:            "Known drainer contract method signature",
    contract_age_very_new:        "Contract deployed less than 7 days ago",
    contract_age_new:             "Contract deployed less than 30 days ago",
    contract_age_recent:          "Contract deployed less than 90 days ago",
    proxy_recently_upgraded:      "Proxy implementation changed recently",
    proxy_unknown_impl:           "Proxy implementation is unknown",
    eth_value_sent:               "ETH is being sent in this transaction",
    high_eth_value:               "Large ETH amount being sent",
    typed_data_unknown_spender:   "Typed data signature for unknown spender",
    seaport_unknown_recipient:    "Seaport order with unknown recipient",
    token_name_suspicious:        "Token name contains suspicious content",
    simulation_failed:            "Transaction would revert",
    simulation_balance_loss:      "Simulation shows unexpected balance loss",
  }
  return reasons[signal] ?? signal
}
