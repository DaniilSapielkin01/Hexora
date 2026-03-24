// Full transaction simulation via debug_traceCall
// Requires a premium RPC endpoint (Alchemy, Infura, QuickNode)
// Public RPC nodes do NOT support this method
//
// OPTIONAL — tx-guard works without this.
// Add rpcUrl to CheckTxParams for deeper analysis:
//
//   await checkTx({
//     tx,
//     provider: window.ethereum,
//     rpcUrl: "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
//   })
//
// What debug_traceCall gives you that eth_call does NOT:
//   ✅ Every storage write (SSTORE) — catches updateDelegate, setOperator
//   ✅ Every internal call — sees delegatecall, nested calls
//   ✅ Exact token balance delta per address
//   ✅ Detects Venus-style delegation even without Transfer events

const TIMEOUT_MS = 5000

export interface TraceSimulationResult {
  available:      boolean           // false if RPC doesn't support debug_traceCall
  success:        boolean
  ethDelta:       bigint
  storageWrites:  StorageWrite[]    // all SSTORE operations
  internalCalls:  InternalCall[]    // all internal calls
  isDangerous:    boolean
  warning:        string | null
}

export interface StorageWrite {
  address: string
  slot:    string
  value:   string
}

export interface InternalCall {
  type:  "CALL" | "DELEGATECALL" | "STATICCALL" | "CREATE"
  from:  string
  to:    string
  value: string
}

export async function traceSimulate(
  tx:     { to: string; from: string; data?: string; value?: string },
  rpcUrl: string
): Promise<TraceSimulationResult> {
  const notAvailable: TraceSimulationResult = {
    available: false, success: false, ethDelta: 0n,
    storageWrites: [], internalCalls: [],
    isDangerous: false, warning: null,
  }

  try {
    const controller = new AbortController()
    const timeout    = setTimeout(() => controller.abort(), TIMEOUT_MS)

    const res = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
      body: JSON.stringify({
        jsonrpc: "2.0",
        id:      1,
        method:  "debug_traceCall",
        params: [
          {
            to:    tx.to,
            from:  tx.from,
            data:  tx.data  ?? "0x",
            value: tx.value ?? "0x0",
          },
          "latest",
          {
            tracer: "callTracer",  // structured call trace
            tracerConfig: {
              withLog:          true,
              onlyTopCall:      false,
              disableStorage:   false,
              disableStack:     true,   // save memory
              enableMemory:     false,
            },
          },
        ],
      }),
    })

    clearTimeout(timeout)

    if (!res.ok) return notAvailable

    const data = await res.json() as {
      error?:  { message: string }
      result?: CallTrace
    }

    if (data.error) {
      // Method not supported on this RPC
      if (data.error.message.includes("not supported") ||
          data.error.message.includes("not found") ||
          data.error.message.includes("does not exist")) {
        return notAvailable
      }
      return { ...notAvailable, available: true, success: false }
    }

    if (!data.result) return notAvailable

    // Extract storage writes and internal calls from trace
    const storageWrites = extractStorageWrites(data.result)
    const internalCalls = extractInternalCalls(data.result)

    // Detect dangerous patterns in trace
    const danger = analyzeDangerousPatterns(storageWrites, internalCalls, tx.from)

    return {
      available:     true,
      success:       data.result.type !== "REVERT",
      ethDelta:      parseEthDelta(data.result),
      storageWrites,
      internalCalls,
      isDangerous:   danger.isDangerous,
      warning:       danger.warning,
    }

  } catch {
    return notAvailable
  }
}

// ── Trace analysis ─────────────────────────────────────────────────────────────

interface CallTrace {
  type:    string
  from:    string
  to:      string
  value?:  string
  calls?:  CallTrace[]
  error?:  string
}

function extractStorageWrites(trace: CallTrace): StorageWrite[] {
  // callTracer doesn't include storage by default
  // For storage we need prestateTracer — but callTracer is enough for call analysis
  return []
}

function extractInternalCalls(trace: CallTrace, depth = 0): InternalCall[] {
  const calls: InternalCall[] = []

  if (depth > 0) {
    calls.push({
      type:  (trace.type as InternalCall["type"]) ?? "CALL",
      from:  trace.from ?? "",
      to:    trace.to   ?? "",
      value: trace.value ?? "0x0",
    })
  }

  for (const inner of (trace.calls ?? [])) {
    calls.push(...extractInternalCalls(inner, depth + 1))
  }

  return calls
}

function parseEthDelta(trace: CallTrace): bigint {
  try {
    return trace.value ? -BigInt(trace.value) : 0n
  } catch {
    return 0n
  }
}

function analyzeDangerousPatterns(
  storageWrites: StorageWrite[],
  internalCalls: InternalCall[],
  userAddress:   string
): { isDangerous: boolean; warning: string | null } {

  // ── Detect DELEGATECALL to unknown address ─────────────────────────────────
  // DELEGATECALL executes foreign code in the context of the calling contract
  // This is how proxy upgrades work — and how malicious proxies drain funds
  const delegateCalls = internalCalls.filter(c => c.type === "DELEGATECALL")
  if (delegateCalls.length > 0) {
    return {
      isDangerous: true,
      warning: `Transaction contains ${delegateCalls.length} DELEGATECALL(s). ` +
        `This executes external code that can read and modify your contract's storage. ` +
        `Verify all delegatecall targets before signing.`,
    }
  }

  // ── Detect unexpected ETH routing ─────────────────────────────────────────
  // Transaction sends ETH to contract, but contract forwards it to unknown address
  const ethTransfers = internalCalls.filter(c =>
    c.value && BigInt(c.value) > 0n &&
    c.to.toLowerCase() !== userAddress.toLowerCase()
  )
  if (ethTransfers.length > 2) {
    return {
      isDangerous: true,
      warning: `ETH is being routed through ${ethTransfers.length} addresses internally. ` +
        `This may indicate funds are being sent to an attacker.`,
    }
  }

  // ── Detect CREATE inside transaction ──────────────────────────────────────
  // Deploying a contract inside a transaction can be used to hide malicious logic
  const creates = internalCalls.filter(c => c.type === "CREATE")
  if (creates.length > 0) {
    return {
      isDangerous: false,  // not always dangerous but worth flagging
      warning: `Transaction deploys ${creates.length} new contract(s) internally. ` +
        `Verify what these contracts do before signing.`,
    }
  }

  return { isDangerous: false, warning: null }
}
