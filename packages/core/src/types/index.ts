// Supported blockchain networks
export type ChainId =
  | "ethereum"
  | "bnb"
  | "polygon"
  | "avalanche"
  | "arbitrum"
  | "optimism"
  | "solana"
  | "bitcoin"
  | "tron";

// EVM numeric chain ID → ChainId mapping
export const EVM_CHAIN_MAP: Record<string, ChainId> = {
  "0x1": "ethereum",
  "0x38": "bnb",
  "0x89": "polygon",
  "0xa86a": "avalanche",
  "0xa4b1": "arbitrum",
  "0xa": "optimism",
};

export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";

export type ScamReason =
  | "address_poisoning"
  | "zero_value_transfer"
  | "batch_poisoning"
  | "transferfrom_spoofing"
  | "dust_attack"
  | "new_suspicious_address"
  | "known_phishing"
  | "malicious_domain"
  | "phishing_domain"
  | "typosquat_domain";

export interface NormalizedTransaction {
  hash: string;
  from: string;
  to: string;
  value: bigint;
  tokenValue?: bigint;
  timestamp: number;
  blockNumber: number;
  isIncoming: boolean;
  contractAddress?: string | undefined;
  methodId?: string | undefined;
  isZeroValue: boolean;
  isBatchPoison: boolean;
}

export interface CheckError {
  code: ErrorCode;
  message: string;
}

export type ErrorCode =
  | "network_unavailable"
  | "history_fetch_failed"
  | "unsupported_chain"
  | "invalid_address"
  | "unknown_provider"
  | "rate_limited"
  | "unknown";

// EIP-1193 standard — MetaMask, WalletConnect, Coinbase, Trust, Rainbow, Rabby, etc.
export interface EIP1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  on?(event: string, handler: (...args: unknown[]) => void): void;
  removeListener?(event: string, handler: (...args: unknown[]) => void): void;
}

// Phantom (Solana)
export interface PhantomProvider {
  isPhantom: boolean;
  publicKey?: { toString(): string };
  connect(): Promise<{ publicKey: { toString(): string } }>;
  request?(args: { method: string; params?: unknown }): Promise<unknown>;
}

export type RawProvider =
  | EIP1193Provider
  | PhantomProvider
  | Record<string, unknown>;

// Internal unified provider — every chain adapter implements this
export interface HexoraProvider {
  chainId(): Promise<ChainId>;
  rawChainId(): Promise<string>;
  isEVM(): boolean;
  getProviderType(): ProviderType;
}

export type ProviderType = "eip1193" | "phantom" | "unknown";

// Custom history provider — implement to use your own data source
export interface HistoryProvider {
  getTransactions(
    address: string,
    chain: ChainId,
    limit: number
  ): Promise<NormalizedTransaction[]>;
}
