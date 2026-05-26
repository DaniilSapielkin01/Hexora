import {
  detectProvider,
  validateAddress,
  findMostSimilar,
  DefaultHistoryProvider,
  txCache,
  logEvent,
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
  // Both fetches run concurrently. allSettled — so a failure on the input
  // address fetch doesn't lose the user history (and vice versa); each
  // independent signal still contributes whatever data it could pull.
  const fetcher = historyProvider ?? new DefaultHistoryProvider(apiKeys);
  let userHistory: NormalizedTransaction[] = [];
  let inputAddrHistory: NormalizedTransaction[] = [];

  const cachedUser  = txCache.get(userAddress,  chain);
  const cachedInput = txCache.get(inputAddress, chain);

  const [userRes, inputRes] = await Promise.allSettled([
    cachedUser
      ? Promise.resolve(cachedUser)
      : fetcher.getTransactions(userAddress, chain, Math.min(historyLimit, 50)),
    cachedInput
      ? Promise.resolve(cachedInput)
      : fetcher.getTransactions(inputAddress, chain, 50),
  ]);

  if (userRes.status === "fulfilled") {
    userHistory = userRes.value;
    if (!cachedUser) txCache.set(userAddress, chain, userHistory);
  } else {
    logEvent("warn", "checkAddress", "user history fetch failed",
      { chain, error: errMsg(userRes.reason) });
  }

  if (inputRes.status === "fulfilled") {
    inputAddrHistory = inputRes.value;
    if (!cachedInput) txCache.set(inputAddress, chain, inputAddrHistory);
  } else {
    logEvent("warn", "checkAddress", "input history fetch failed",
      { chain, error: errMsg(inputRes.reason) });
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

// Build the set of peers we'll check `inputAddress` against for similarity.
// Address-poisoning attacks copy an EOA the user has previously transacted
// with — comparing the input to a contract address (DEX router, token,
// protocol) is meaningless and produces false positives. Heuristic: if a tx
// carries a methodId it's a contract call, so the `to` is a contract; we
// only treat it as a peer when there's no methodId (plain transfer).
function extractKnownAddresses(
  history: NormalizedTransaction[],
  userAddress: string
): string[] {
  const lower = userAddress.toLowerCase();
  const seen  = new Set<string>();
  for (const tx of history) {
    const isContractCall = !!tx.methodId && tx.methodId !== "0x";
    if (tx.from === lower && tx.to && !isContractCall) seen.add(tx.to);
    if (tx.to === lower && tx.from && !tx.isZeroValue) seen.add(tx.from);
  }
  return Array.from(seen);
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
