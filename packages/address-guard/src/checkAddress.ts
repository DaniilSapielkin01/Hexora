import {
  detectProvider,
  validateAddress,
  findMostSimilar,
  DefaultHistoryProvider,
  txCache,
} from "@hexora/core";
import type { NormalizedTransaction } from "@hexora/core";
import type { CheckAddressParams, CheckResult } from "./types.js";
import { analyzeInputAddress, analyzeUserHistory } from "./detector.js";
import { buildResult, buildErrorResult } from "./scorer.js";

const DEFAULT_HISTORY_LIMIT = 20;
const DEFAULT_SIMILARITY_THRESHOLD = 85;

export async function checkAddress(
  params: CheckAddressParams
): Promise<CheckResult> {
  const {
    userAddress,
    inputAddress,
    provider,
    historyProvider,
    historyLimit = DEFAULT_HISTORY_LIMIT,
    similarityThreshold = DEFAULT_SIMILARITY_THRESHOLD,
    dustThreshold,
    apiKeys = {},
  } = params;

  // Step 1: detect provider, resolve chain
  let chain: CheckResult["details"]["chain"];
  try {
    chain = await detectProvider(provider).chainId();
  } catch (err: unknown) {
    const e = err as Error & { hexoraCode?: string };
    return buildErrorResult(
      e.hexoraCode ?? "unknown",
      e.message ?? "Failed to detect provider"
    );
  }

  // Step 2: validate addresses
  if (!validateAddress(userAddress, chain))
    return buildErrorResult(
      "invalid_address",
      `userAddress "${userAddress}" is not valid for chain "${chain}"`,
      chain
    );
  if (!validateAddress(inputAddress, chain))
    return buildErrorResult(
      "invalid_address",
      `inputAddress "${inputAddress}" is not valid for chain "${chain}"`,
      chain
    );

  // Step 3: fetch history (in-memory cache, 5 min TTL)
  const fetcher = historyProvider ?? new DefaultHistoryProvider(apiKeys);
  let userHistory: NormalizedTransaction[] = [];
  let inputAddrHistory: NormalizedTransaction[] = [];

  try {
    const cached = txCache.get(userAddress, chain);
    const [userTxs, inputTxs] = await Promise.all([
      cached
        ? Promise.resolve(cached)
        : fetcher.getTransactions(
            userAddress,
            chain,
            Math.min(historyLimit, 50)
          ),
      fetcher.getTransactions(inputAddress, chain, 50),
    ]);
    if (!cached) txCache.set(userAddress, chain, userTxs);
    userHistory = userTxs;
    inputAddrHistory = inputTxs;
  } catch {
    /* continue with empty history */
  }

  // Step 4: similarity check
  const known = extractKnownAddresses(userHistory, userAddress);
  const match = findMostSimilar(inputAddress, known, similarityThreshold);

  // Step 5: analyze user history for injected poison
  const histAnalysis = analyzeUserHistory(
    inputAddress,
    userHistory,
    userAddress
  );

  // Step 6: analyze input address on-chain behavior
  const inputAnalysis = analyzeInputAddress(
    inputAddress,
    inputAddrHistory,
    dustThreshold
  );

  // Step 7: combine signals
  return buildResult({
    chain,
    userAddress,
    inputAddress,
    historyScanned: userHistory.length,
    similarityScore: match?.similarityScore ?? 0,
    matchedAddress: match?.address ?? null,
    zeroValueFound: histAnalysis.zeroValueFound,
    batchPoisonFound: histAnalysis.batchPoisonFound,
    dustFound: histAnalysis.dustFound,
    transferFromFound: histAnalysis.transferFromFound,
    inputAddrDetection: {
      detected: inputAnalysis.detected,
      reason: inputAnalysis.reason,
      confidence: inputAnalysis.confidence,
    },
  });
}

function extractKnownAddresses(
  history: NormalizedTransaction[],
  userAddress: string
): string[] {
  const lower = userAddress.toLowerCase();
  const seen = new Set<string>();
  for (const tx of history) {
    if (tx.from === lower && tx.to) seen.add(tx.to);
    if (tx.to === lower && tx.from && !tx.isZeroValue) seen.add(tx.from);
  }
  return Array.from(seen);
}
