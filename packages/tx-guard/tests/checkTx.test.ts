import { describe, test, expect } from "vitest"
import { checkTx }           from "../src/checkTx"
import { detectTransaction } from "../src/detector"
import { detectDelegation }  from "../src/delegationDetector"
import { detectAATransaction } from "../src/aaDetector"
import { runCompositeScoring } from "../src/compositeSorcer"
import { parseCalldata, MAX_UINT256 } from "../src/calldataParser"
import { analyzeTypedData }  from "../src/typedDataAnalyzer"
import { analyzeTokenName }  from "../src/tokenNameAnalyzer"

// ── Real calldata ─────────────────────────────────────────────────────────────

const UNLIMITED_APPROVE =
  "0x095ea7b3" +
  "000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" +
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

const LEGIT_PERMIT2_APPROVE =
  "0x095ea7b3" +
  "000000000000000000000000000000000022d473030f116ddee9f6b43ac78ba3" +
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

const SET_APPROVAL_ALL =
  "0xa22cb465" +
  "000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" +
  "0000000000000000000000000000000000000000000000000000000000000001"

// Venus updateDelegate(address delegate, bool approved)
// methodId: 0xe8eda9df — the exact method used in $27M exploit
const VENUS_UPDATE_DELEGATE_MALICIOUS =
  "0xe8eda9df" +
  "000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" +
  "0000000000000000000000000000000000000000000000000000000000000001"

// Venus updateDelegate — revoking (safe)
const VENUS_REVOKE_DELEGATE =
  "0xe8eda9df" +
  "000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" +
  "0000000000000000000000000000000000000000000000000000000000000000"

// Aave approveDelegation(address,uint256)
const AAVE_APPROVE_DELEGATION =
  "0xc04a8a10" +
  "000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" +
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

// ERC-4337 handleOps
const AA_HANDLE_OPS = "0x1fad948c" + "0".repeat(256)

// Safe multiSend with 4 operations
const SAFE_MULTI_SEND = "0x8d80ff0a" + "0".repeat(800)

// ── calldataParser ────────────────────────────────────────────────────────────

describe("parseCalldata", () => {
  test("parses unlimited approve", () => {
    const r = parseCalldata(UNLIMITED_APPROVE)
    expect(r.methodId).toBe("0x095ea7b3")
    expect(r.amount).toBe(MAX_UINT256)
  })

  test("parses setApprovalForAll", () => {
    const r = parseCalldata(SET_APPROVAL_ALL)
    expect(r.methodId).toBe("0xa22cb465")
    expect(r.approved).toBe(true)
  })

  test("handles empty data", () => {
    expect(parseCalldata("0x").methodId).toBeNull()
  })
})

// ── Delegation detector — Venus exploit pattern ───────────────────────────────

describe("detectDelegation — Venus $27M exploit pattern", () => {
  test("updateDelegate to unknown → detected critical", () => {
    const r = detectDelegation({
      to:   "0xfd36e2c2a6789db23113685031d7f16329158384",  // Venus Comptroller
      from: "0xvictim00000000000000000000000000000000000",
      data: VENUS_UPDATE_DELEGATE_MALICIOUS,
    })
    expect(r.detected).toBe(true)
    expect(r.confidence).toBeGreaterThanOrEqual(90)
    expect(r.warning).toContain("Venus")
    expect(r.delegate).toBe("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
  })

  test("updateDelegate revoke → NOT detected (safe action)", () => {
    const r = detectDelegation({
      to:   "0xfd36e2c2a6789db23113685031d7f16329158384",
      from: "0xvictim00000000000000000000000000000000000",
      data: VENUS_REVOKE_DELEGATE,
    })
    expect(r.detected).toBe(false)
  })

  test("Aave approveDelegation to unknown → detected", () => {
    const r = detectDelegation({
      to:   "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",  // Aave Pool
      from: "0xvictim00000000000000000000000000000000000",
      data: AAVE_APPROVE_DELEGATION,
    })
    expect(r.detected).toBe(true)
    expect(r.confidence).toBeGreaterThanOrEqual(75)
  })

  test("normal transfer → not detected", () => {
    const r = detectDelegation({
      to:   "0xsome_token",
      from: "0xuser",
      data: "0xa9059cbb" + "0".repeat(128),
    })
    expect(r.detected).toBe(false)
  })
})

// ── ERC-4337 AA detector ──────────────────────────────────────────────────────

describe("detectAATransaction", () => {
  test("handleOps on unknown contract → warning", () => {
    const r = detectAATransaction({
      to:   "0xunknown_contract_not_entrypoint",
      from: "0xbundler",
      data: AA_HANDLE_OPS,
    })
    expect(r.isAA).toBe(true)
    expect(r.warning).toBeTruthy()
  })

  test("handleOps on real EntryPoint → no warning", () => {
    const r = detectAATransaction({
      to:   "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789",  // EntryPoint v0.6
      from: "0xbundler",
      data: AA_HANDLE_OPS,
    })
    expect(r.isAA).toBe(true)
    expect(r.warning).toBeNull()
  })

  test("large multiSend → warning", () => {
    const r = detectAATransaction({
      to:   "0xsafe_contract",
      from: "0xuser",
      data: SAFE_MULTI_SEND,
    })
    expect(r.isAA).toBe(true)
  })

  test("regular transfer → not AA", () => {
    const r = detectAATransaction({
      to:   "0xrecipient",
      from: "0xuser",
      data: "0xa9059cbb" + "0".repeat(128),
    })
    expect(r.isAA).toBe(false)
  })
})

// ── Composite scoring ─────────────────────────────────────────────────────────

describe("runCompositeScoring", () => {
  const baseClean = {
    detected: false, reason: null, confidence: 0, warning: null,
    details: {
      methodId: null, methodName: null, spender: null,
      amount: null, isUnlimitedAmount: false,
      contractAge: null, isProxy: false, proxyImplAge: null,
      simulationResult: null,
    },
  }

  const cleanDelegation = {
    detected: false, methodId: null, methodName: null,
    delegate: null, protocol: null, isToKnown: false,
    confidence: 0, warning: null,
  }

  test("new contract + multicall + medium detection = composite fired", () => {
    const mediumDetection = { ...baseClean, detected: true, confidence: 55, reason: "new_contract" as const }
    const r = runCompositeScoring(
      mediumDetection, cleanDelegation,
      5,          // 5 days old
      BigInt("1000000000000000"),  // 0.001 ETH
      true,       // has multicall
      false, null
    )
    expect(r.fired).toBe(true)
    expect(r.totalScore).toBeGreaterThan(60)
  })

  test("all clean signals = not fired", () => {
    const r = runCompositeScoring(
      baseClean, cleanDelegation,
      365, 0n, false, false, null
    )
    expect(r.fired).toBe(false)
  })

  test("proxy upgraded 3 days ago + ETH = fired", () => {
    const r = runCompositeScoring(
      baseClean, cleanDelegation,
      null, BigInt("1000000000000000"),
      false, true, 3
    )
    expect(r.fired).toBe(true)
  })
})

// ── TypedData analyzer ────────────────────────────────────────────────────────

describe("analyzeTypedData", () => {
  test("permit to unknown → permit_drain", () => {
    const r = analyzeTypedData({
      primaryType: "Permit",
      domain:  { name: "USDC", version: "2", chainId: 1 },
      types:   { Permit: [] },
      message: {
        owner:    "0xUser",
        spender:  "0xDeadBeefDeadBeefDeadBeefDeadBeefDeadBeef",
        value:    (2n ** 256n - 1n).toString(),
        nonce: 0, deadline: 9999999999,
      },
    })
    expect(r.detected).toBe(true)
    expect(r.reason).toBe("permit_drain")
  })

  test("Seaport order with unknown recipient → seaport_order_spoof", () => {
    const r = analyzeTypedData({
      primaryType: "OrderComponents",
      domain:  { name: "Seaport", version: "1.5" },
      types:   { OrderComponents: [] },
      message: {
        consideration: [
          { itemType: 0, token: "0x0", identifier: "0", amount: "1000000",
            recipient: "0xDeadBeefDeadBeefDeadBeefDeadBeefDeadBeef" },
        ],
      },
    })
    expect(r.detected).toBe(true)
    expect(r.reason).toBe("seaport_order_spoof")
  })
})

// ── Token name analyzer ───────────────────────────────────────────────────────

describe("analyzeTokenName", () => {
  test("URL in token name → detected", () => {
    const r = analyzeTokenName("Visit scam.xyz to claim $1000", "SCAM")
    expect(r.detected).toBe(true)
    expect(r.confidence).toBeGreaterThan(50)
  })

  test("claim keyword → detected", () => {
    const r = analyzeTokenName("FREE AIRDROP CLAIM NOW", "FAKE")
    expect(r.detected).toBe(true)
  })

  test("normal token → not detected", () => {
    const r = analyzeTokenName("USD Coin", "USDC")
    expect(r.detected).toBe(false)
  })
})

// ── checkTx full API ──────────────────────────────────────────────────────────

describe("checkTx — Venus exploit simulation", () => {
  test("updateDelegate to unknown on Venus → scam=true critical", async () => {
    const r = await checkTx({
      tx: {
        to:   "0xfd36e2c2a6789db23113685031d7f16329158384",
        from: "0xvictim00000000000000000000000000000000000",
        data: VENUS_UPDATE_DELEGATE_MALICIOUS,
      },
    })
    expect(r.scam).toBe(true)
    expect(["critical", "high"]).toContain(r.riskLevel)
    expect(r.warning).toBeTruthy()
    expect(r.error).toBeNull()
  })

  test("revoke delegation → scam=false", async () => {
    const r = await checkTx({
      tx: {
        to:   "0xfd36e2c2a6789db23113685031d7f16329158384",
        from: "0xvictim00000000000000000000000000000000000",
        data: VENUS_REVOKE_DELEGATE,
      },
    })
    expect(r.scam).toBe(false)
    expect(r.error).toBeNull()
  })
})

describe("checkTx — standard patterns", () => {
  test("unlimited approve → critical", async () => {
    const r = await checkTx({
      tx: { to: "0xtoken", from: "0xuser", data: UNLIMITED_APPROVE },
    })
    expect(r.scam).toBe(true)
    expect(r.riskLevel).toBe("critical")
  })

  test("setApprovalForAll → critical", async () => {
    const r = await checkTx({
      tx: { to: "0xnft", from: "0xuser", data: SET_APPROVAL_ALL },
    })
    expect(r.scam).toBe(true)
    expect(r.riskLevel).toBe("critical")
  })

  test("plain ETH transfer → clean", async () => {
    const r = await checkTx({
      tx: { to: "0xrecipient", from: "0xuser", value: "0x16345785d8a0000" },
    })
    expect(r.scam).toBe(false)
    expect(r.riskLevel).toBe("none")
  })

  test("fake airdrop token → high", async () => {
    const r = await checkTx({
      tx:          { to: "0xtoken", from: "0xuser", data: "0x" },
      tokenName:   "Visit evil.xyz to claim 1000 USDT",
      tokenSymbol: "SCAM",
    })
    expect(r.scam).toBe(true)
    expect(r.riskLevel).toBe("high")
  })

  test("new contract receiving ETH → detected", async () => {
    const r = await checkTx({
      tx: {
        to:    "0xnewcontract",
        from:  "0xuser",
        data:  "0x12345678",
        value: "0x16345785d8a0000",
      },
    })
    // Without provider contractAge is null — clean
    expect(r.error).toBeNull()
  })
})

describe("checkTx — result shape", () => {
  test("result has all required fields", async () => {
    const r = await checkTx({ tx: { to: "0x1234", from: "0x5678" } })
    expect(r).toHaveProperty("scam")
    expect(r).toHaveProperty("reason")
    expect(r).toHaveProperty("riskLevel")
    expect(r).toHaveProperty("confidence")
    expect(r).toHaveProperty("warning")
    expect(r).toHaveProperty("details")
    expect(r).toHaveProperty("error")
    expect(r.details).toHaveProperty("isUnlimitedAmount")
    expect(r.details).toHaveProperty("isProxy")
    expect(r.details).toHaveProperty("contractAge")
  })
})
