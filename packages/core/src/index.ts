export type {
  ChainId,
  RiskLevel,
  ScamReason,
  ErrorCode,
  NormalizedTransaction,
  CheckError,
  EIP1193Provider,
  PhantomProvider,
  RawProvider,
  HexoraProvider,
  ProviderType,
  HistoryProvider,
} from "./types/index.js";

export { EVM_CHAIN_MAP } from "./types/index.js";
export { detectProvider } from "./providers/detector.js";
export { txCache } from "./cache.js";
export { validateAddress } from "./validator.js";
export { calculateSimilarity, findMostSimilar } from "./similarity.js";
export { DefaultHistoryProvider } from "./history/fetcher.js";
