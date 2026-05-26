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
export { setLogger, logEvent } from "./logger.js";
export type { Logger, LogEvent, LogLevel } from "./logger.js";
export {
  HTTP_TIMEOUT_MS,
  HTTP_RETRIES,
  HTTP_RETRY_DELAY_MS,
  HISTORY_FETCH_TIMEOUT_MS,
} from "./constants.js";
