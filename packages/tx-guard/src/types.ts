import type { RiskLevel, CheckError, EIP1193Provider } from "@hexora/core"

export interface RawTransaction {
  to:       string
  from:     string
  data?:    string
  value?:   string
  chainId?: string
}

export interface TypedDataPayload {
  domain:      Record<string, unknown>
  types:       Record<string, unknown>
  message:     Record<string, unknown>
  primaryType: string
}

export interface CheckTxParams {
  tx:           RawTransaction
  provider?:    EIP1193Provider
  typedData?:   TypedDataPayload
  tokenName?:   string
  tokenSymbol?: string
  // Optional: premium RPC for deep simulation via debug_traceCall
  // Supports Alchemy, Infura, QuickNode
  // Without this, basic eth_call simulation is used
  // Example: "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
  rpcUrl?:      string
}

export type TxScamReason =
  | "unlimited_approval"
  | "permit_drain"
  | "set_approval_for_all"
  | "ice_phishing"
  | "new_contract"
  | "eth_value_mismatch"
  | "suspicious_multicall"
  | "seaport_order_spoof"
  | "permit2_drain"
  | "proxy_recently_upgraded"
  | "simulation_loss"
  | "fake_token_airdrop"
  | "delegation_abuse"          // Venus/Aave/Compound delegate exploit

export interface TxCheckDetails {
  methodId:          string | null
  methodName:        string | null
  spender:           string | null
  amount:            bigint | null
  isUnlimitedAmount: boolean
  contractAge:       number | null
  isProxy:           boolean
  proxyImplAge:      number | null
  simulationResult:  SimulationResult | null
  // Optional — populated by checkTx when provider available
  domainAge?: {
    checked:   boolean
    ageInDays: number | null
    isVeryNew: boolean
    isNew:     boolean
    isRecent:  boolean
    registrar: string | null
  }
}

export interface SimulationResult {
  ethDelta:    bigint
  tokenDeltas: Array<{ token: string; delta: bigint; symbol?: string }>
  success:     boolean
}

export interface CheckTxResult {
  scam:       boolean
  reason:     TxScamReason | null
  riskLevel:  RiskLevel
  confidence: number
  warning:    string | null
  details:    TxCheckDetails
  error:      CheckError | null
}
