import type { NormalizedTransaction, ScamReason } from "@hexora/core";

export const DEFAULT_DUST_THRESHOLD = 10_000_000_000_000n; // 0.00001 ETH in wei

export interface DetectionResult {
  detected: boolean;
  reason: ScamReason | null;
  confidence: number;
  evidence: string[];
}

export function analyzeInputAddress(
  inputAddress: string,
  inputAddrHistory: NormalizedTransaction[],
  dustThreshold: bigint = DEFAULT_DUST_THRESHOLD
): DetectionResult {
  const evidence: string[] = [];
  let maxConfidence = 0;
  let reason: ScamReason | null = null;
  const addr = inputAddress.toLowerCase();

  const batchTxs = inputAddrHistory.filter((tx) => tx.isBatchPoison);
  if (batchTxs.length > 0) {
    evidence.push(
      `Address executed ${batchTxs.length} batch poisoning transaction(s) with zero-value token transfers`
    );
    maxConfidence = Math.max(maxConfidence, 98);
    reason = "batch_poisoning";
  }

  const zeroSent = inputAddrHistory.filter(
    (tx) => tx.isZeroValue && tx.from === addr
  );
  if (zeroSent.length >= 2) {
    evidence.push(`Address sent ${zeroSent.length} zero-value token transfers`);
    maxConfidence = Math.max(maxConfidence, 90);
    if (!reason) reason = "zero_value_transfer";
  }

  const dustSent = inputAddrHistory.filter(
    (tx) =>
      tx.from === addr &&
      !tx.isZeroValue &&
      tx.value > 0n &&
      tx.value < dustThreshold
  );
  const uniqueTargets = new Set(dustSent.map((tx) => tx.to)).size;
  if (uniqueTargets >= 5) {
    evidence.push(`Address sent dust to ${uniqueTargets} unique addresses`);
    maxConfidence = Math.max(maxConfidence, 85);
    if (!reason) reason = "dust_attack";
  }

  if (inputAddrHistory.length > 0) {
    const firstTx = Math.min(...inputAddrHistory.map((tx) => tx.timestamp));
    const ageDays = (Date.now() / 1000 - firstTx) / 86400;
    const onlyOut = inputAddrHistory.every(
      (tx) => tx.from === addr || tx.isBatchPoison
    );
    if (ageDays < 30 && onlyOut && inputAddrHistory.length >= 3) {
      evidence.push(
        `Address is ${Math.round(ageDays)} days old with only outgoing activity`
      );
      maxConfidence = Math.max(maxConfidence, 75);
      if (!reason) reason = "new_suspicious_address";
    }
  }

  return {
    detected: evidence.length > 0,
    reason,
    confidence: maxConfidence,
    evidence,
  };
}

export function analyzeUserHistory(
  inputAddress: string,
  userHistory: NormalizedTransaction[],
  userAddress: string
): {
  zeroValueFound: boolean;
  batchPoisonFound: boolean;
  dustFound: boolean;
  transferFromFound: boolean;
  evidence: string[];
} {
  const evidence: string[] = [];
  const inputLower = inputAddress.toLowerCase();
  const userLower = userAddress.toLowerCase();
  const fromInput = userHistory.filter((tx) => tx.from === inputLower);

  const zeroValueFound = fromInput.some((tx) => tx.isZeroValue);
  const batchPoisonFound = fromInput.some((tx) => tx.isBatchPoison);
  const dustFound = fromInput.some(
    (tx) =>
      !tx.isZeroValue && tx.value > 0n && tx.value < DEFAULT_DUST_THRESHOLD
  );
  const transferFromFound = userHistory.some(
    (tx) =>
      tx.from === userLower &&
      tx.to === inputLower &&
      tx.isZeroValue &&
      tx.contractAddress !== undefined &&
      tx.contractAddress !== userLower
  );

  if (zeroValueFound)
    evidence.push(`Incoming zero-value transfer from ${inputAddress}`);
  if (batchPoisonFound)
    evidence.push(`Batch poisoning transaction from ${inputAddress}`);
  if (dustFound)
    evidence.push(`Dust transaction received from ${inputAddress}`);
  if (transferFromFound)
    evidence.push(`transferFrom spoofing detected involving ${inputAddress}`);

  return {
    zeroValueFound,
    batchPoisonFound,
    dustFound,
    transferFromFound,
    evidence,
  };
}
