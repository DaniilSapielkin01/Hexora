export { checkTx }                                   from "./checkTx.js"
export { KNOWN_ROUTERS }                             from "./methodIds.js"
export { KNOWN_PROTOCOL_ADDRESSES, isKnownProtocol } from "./knownProtocols.js"
export { MAX_UINT256 }                               from "./calldataParser.js"
export { analyzeTokenName, isFakeAirdrop }           from "./tokenNameAnalyzer.js"
export { detectDelegation }                          from "./delegationDetector.js"

export type {
  CheckTxParams, CheckTxResult, TxScamReason,
  RawTransaction, TypedDataPayload,
  TxCheckDetails, SimulationResult,
} from "./types.js"

export type { DelegationRisk }        from "./delegationDetector.js"
export type { AADetectionResult }     from "./aaDetector.js"
export type { TraceSimulationResult } from "./traceSimulation.js"
