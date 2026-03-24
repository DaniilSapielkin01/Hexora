import { detectTransaction }              from "./detector.js"
import { getRiskLevel }                   from "./scorer.js"
import { getContractAge }                 from "./contractAge.js"
import { simulateTransaction, isSimulationDangerous } from "./simulation.js"
import { checkProxyImplementation }       from "./proxyChecker.js"
import { analyzeTokenName }               from "./tokenNameAnalyzer.js"
import { decodeCalldata, isDangerousFunctionName } from "./abiDecoder.js"
import { traceSimulate }                  from "./traceSimulation.js"
import type { CheckTxParams, CheckTxResult, TxCheckDetails } from "./types.js"

export async function checkTx(params: CheckTxParams): Promise<CheckTxResult> {
  const { tx, provider, typedData, tokenName, tokenSymbol, rpcUrl } = params

  try {
    const emptyDetails: TxCheckDetails = {
      methodId: null, methodName: null, spender: null,
      amount: null, isUnlimitedAmount: false,
      contractAge: null, isProxy: false, proxyImplAge: null,
      simulationResult: null,
    }

    // ── 0. Fake token airdrop check ───────────────────────────────────────
    if (tokenName || tokenSymbol) {
      const tokenRisk = analyzeTokenName(tokenName ?? "", tokenSymbol ?? "")
      if (tokenRisk.detected) {
        return {
          scam: true, reason: "fake_token_airdrop",
          riskLevel: "high", confidence: tokenRisk.confidence,
          warning: tokenRisk.warning,
          details: emptyDetails, error: null,
        }
      }
    }

    // ── 1. Parallel provider checks ───────────────────────────────────────
    let contractAge:  number | null = null
    let proxyResult:  { isProxy: boolean; implementationAge: number | null } | null = null
    let simResult:    import("./types.js").SimulationResult | null = null
    let chainId:      string = "0x1"

    if (provider && tx.to) {
      const [age, proxy, sim, chain] = await Promise.all([
        getContractAge(tx.to, provider),
        checkProxyImplementation(tx.to, provider),
        simulateTransaction(tx, provider),
        provider.request({ method: "eth_chainId", params: [] }).then(r => String(r)).catch(() => "0x1"),
      ])
      contractAge = age
      proxyResult = proxy
      simResult   = sim as import("./types.js").SimulationResult
      chainId     = chain
    }

    // ── 1b. Deep trace simulation (optional — requires premium RPC) ───────
    if (rpcUrl && tx.to) {
      const trace = await traceSimulate(tx, rpcUrl)
      if (trace.available && trace.isDangerous && trace.warning) {
        return {
          scam: true, reason: "ice_phishing",
          riskLevel: "high", confidence: 80,
          warning: `[Deep Simulation] ${trace.warning}`,
          details: emptyDetails, error: null,
        }
      }
    }

    // ── 2. ABI decoding — detect dangerous function names ─────────────────
    let abiWarning: string | null = null
    if (provider && tx.to && tx.data && tx.data !== "0x") {
      const decoded = await decodeCalldata(tx.to, tx.data, chainId)
      if (decoded && isDangerousFunctionName(decoded.name)) {
        abiWarning = `Function "${decoded.name}" grants elevated permissions. Signature: ${decoded.signature}`
      }
    }

    // ── 3. Pattern detection ──────────────────────────────────────────────
    const detection = detectTransaction(
      tx, typedData, contractAge,
      proxyResult?.isProxy,
      proxyResult?.implementationAge,
    )

    const details: TxCheckDetails = {
      ...detection.details,
      contractAge,
      isProxy:      proxyResult?.isProxy ?? false,
      proxyImplAge: proxyResult?.implementationAge ?? null,
      simulationResult: simResult,
      domainAge: {
        checked: false, ageInDays: null,
        isVeryNew: false, isNew: false, isRecent: false, registrar: null,
      },
    } as TxCheckDetails

    // ── 4. Proxy recently upgraded check ─────────────────────────────────
    if (proxyResult?.isProxy && proxyResult.implementationAge !== null && proxyResult.implementationAge < 7) {
      return {
        scam: true, reason: "proxy_recently_upgraded",
        riskLevel: "high", confidence: 82,
        warning: `Contract implementation upgraded ${proxyResult.implementationAge} days ago. Recently upgraded proxies are a major red flag.`,
        details, error: null,
      }
    }

    // ── 5. Simulation dangerous loss ─────────────────────────────────────
    if (simResult && isSimulationDangerous(simResult) && !detection.detected) {
      return {
        scam: true, reason: "simulation_loss",
        riskLevel: "high", confidence: 75,
        warning: simResult.success
          ? "Simulation shows unexpected fund loss."
          : "This transaction will fail (revert). May indicate a scam contract.",
        details, error: null,
      }
    }

    // ── 6. ABI dangerous function name warning ────────────────────────────
    if (abiWarning && !detection.detected) {
      return {
        scam: true, reason: "ice_phishing",
        riskLevel: "medium", confidence: 65,
        warning: abiWarning,
        details, error: null,
      }
    }

    // ── 7. Primary detection result ───────────────────────────────────────
    if (detection.detected) {
      return {
        scam: true,
        reason: detection.reason,
        riskLevel: getRiskLevel(detection.reason, detection.confidence),
        confidence: detection.confidence,
        warning: detection.warning,
        details, error: null,
      }
    }

    return {
      scam: false, reason: null, riskLevel: "none",
      confidence: 0, warning: null,
      details, error: null,
    }

  } catch (err) {
    return {
      scam: false, reason: null, riskLevel: "none",
      confidence: 0, warning: null,
      details: {
        methodId: null, methodName: null, spender: null,
        amount: null, isUnlimitedAmount: false,
        contractAge: null, isProxy: false, proxyImplAge: null,
        simulationResult: null,
      },
      error: {
        code: "unknown",
        message: err instanceof Error ? err.message : "Unknown error",
      },
    }
  }
}
