// address-guard
export { checkAddress, DEFAULT_DUST_THRESHOLD } from "@hexora/address-guard";
export type {
  CheckAddressParams,
  CheckResult,
  CheckDetails,
} from "@hexora/address-guard";

// shared types from core
export type {
  ChainId,
  RiskLevel,
  ScamReason,
  CheckError,
  NormalizedTransaction,
  HistoryProvider,
  EIP1193Provider,
  PhantomProvider,
  RawProvider,
  Logger,
  LogEvent,
  LogLevel,
} from "@hexora/core";

// Opt-in observability — see @hexora/core/logger
export { setLogger } from "@hexora/core";
