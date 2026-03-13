import type {
  ChainId,
  RiskLevel,
  ScamReason,
  CheckError,
  HistoryProvider,
  RawProvider,
} from "@hexora/core";

export interface CheckAddressParams {
  userAddress: string;
  inputAddress: string;
  provider: RawProvider;
  historyProvider?: HistoryProvider;
  historyLimit?: number; // default: 20, max: 50
  similarityThreshold?: number; // default: 85
  dustThreshold?: bigint;
  apiKeys?: {
    etherscan?: string;
    bscscan?: string;
    polygonscan?: string;
  };
}

export interface CheckDetails {
  chain: ChainId;
  userAddress: string;
  inputAddress: string;
  historyScanned: number;
  poisonTxFound: boolean;
  zeroValueFound: boolean;
  dustFound: boolean;
}

export interface CheckResult {
  scam: boolean;
  reason: ScamReason | null;
  riskLevel: RiskLevel;
  similarityScore: number;
  confidence: number;
  matchedAddress: string | null;
  details: CheckDetails;
  error: CheckError | null;
}
