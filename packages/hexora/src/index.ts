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
} from "@hexora/core";
