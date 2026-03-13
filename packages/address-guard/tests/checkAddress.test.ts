import { describe, test, expect } from "vitest";
import { calculateSimilarity, findMostSimilar } from "@hexora/core";
import { validateAddress } from "@hexora/core";
import { analyzeInputAddress } from "../src/detector";
import { buildResult } from "../src/scorer";
import type { NormalizedTransaction } from "@hexora/core";

// Real attack — BNB Chain
// Victim:    0xa6C28ADa4e2f8A18ff0d8482D68Bc059aAAFc7A1
// Legit:     0xD2d047342069cd7FF425b6F89E49b2c3e2549E52
// Fake:      0xD2204a5f31f93051005089a3fC8174E434549E52
// Attack tx: 0x05c6e673787275bdff029723492a07f4d9aad9b0e4fbfb7ff95bfb12e641bd48

const LEGIT = "0xD2d047342069cd7FF425b6F89E49b2c3e2549E52";
const FAKE = "0xD2204a5f31f93051005089a3fC8174E434549E52";
const VICTIM = "0xa6C28ADa4e2f8A18ff0d8482D68Bc059aAAFc7A1";
const PHISH = "0xfd278BFB64964DF91Fd22053e76BA176eC0D4e4D";

describe("Similarity", () => {
  test("detects real attack pair", () => {
    expect(calculateSimilarity(LEGIT, FAKE)).toBeGreaterThanOrEqual(60);
  });
  test("identical = 100", () => {
    expect(calculateSimilarity(LEGIT, LEGIT)).toBe(100);
  });
  test("completely different = low", () => {
    expect(
      calculateSimilarity(
        "0x1111111111111111111111111111111111111111",
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      )
    ).toBeLessThan(50);
  });
  test("case insensitive", () => {
    expect(calculateSimilarity(LEGIT, LEGIT.toLowerCase())).toBe(100);
  });
  test("finds fake in history", () => {
    const match = findMostSimilar(FAKE, [LEGIT], 50);
    expect(match).not.toBeNull();
    expect(match!.address.toLowerCase()).toBe(LEGIT.toLowerCase());
  });
});

describe("Validator", () => {
  test("valid EVM", () => {
    expect(validateAddress(VICTIM, "ethereum")).toBe(true);
    expect(validateAddress(VICTIM, "bnb")).toBe(true);
  });
  test("invalid EVM", () => {
    expect(validateAddress("0x1234", "ethereum")).toBe(false);
  });
  test("valid Solana", () => {
    expect(
      validateAddress("DYw8jCTfwHNRJhhmFcbXvVDTqWMEVFBX6ZKUmG5CNSKH", "solana")
    ).toBe(true);
  });
  test("valid Bitcoin bech32", () => {
    expect(
      validateAddress("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "bitcoin")
    ).toBe(true);
  });
});

describe("Detector", () => {
  const batchTx: NormalizedTransaction = {
    hash: "0x05c6e673",
    from: PHISH.toLowerCase(),
    to: VICTIM.toLowerCase(),
    value: 0n,
    tokenValue: 0n,
    timestamp: 1735164253,
    blockNumber: 72926137,
    isIncoming: false,
    isZeroValue: true,
    isBatchPoison: true,
    methodId: "0xe19c2253",
  };

  test("detects batch poisoning", () => {
    const result = analyzeInputAddress(FAKE, [batchTx]);
    expect(result.detected).toBe(true);
    expect(result.reason).toBe("batch_poisoning");
    expect(result.confidence).toBeGreaterThanOrEqual(90);
  });
});

describe("Scorer", () => {
  test("critical for batch poisoning", () => {
    const result = buildResult({
      chain: "bnb",
      userAddress: VICTIM,
      inputAddress: FAKE,
      historyScanned: 20,
      similarityScore: 70,
      matchedAddress: null,
      zeroValueFound: true,
      batchPoisonFound: true,
      dustFound: false,
      transferFromFound: false,
      inputAddrDetection: {
        detected: true,
        reason: "batch_poisoning",
        confidence: 98,
      },
    });
    expect(result.scam).toBe(true);
    expect(result.riskLevel).toBe("critical");
  });

  test("none for clean address", () => {
    const result = buildResult({
      chain: "ethereum",
      userAddress: VICTIM,
      inputAddress: "0x1234567890abcdef1234567890abcdef12345678",
      historyScanned: 20,
      similarityScore: 10,
      matchedAddress: null,
      zeroValueFound: false,
      batchPoisonFound: false,
      dustFound: false,
      transferFromFound: false,
      inputAddrDetection: { detected: false, reason: null, confidence: 0 },
    });
    expect(result.scam).toBe(false);
    expect(result.riskLevel).toBe("none");
  });
});
