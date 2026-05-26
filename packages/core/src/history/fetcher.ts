import {
  ChainId,
  NormalizedTransaction,
  HistoryProvider,
} from "../types/index.js";
import { logEvent } from "../logger.js";
import {
  HISTORY_FETCH_TIMEOUT_MS,
  HTTP_RETRIES,
  HTTP_RETRY_DELAY_MS,
} from "../constants.js";

interface ExplorerConfig {
  baseUrl: string;
}

const EXPLORER_CONFIG: Partial<Record<ChainId, ExplorerConfig>> = {
  ethereum: { baseUrl: "https://api.etherscan.io/api" },
  bnb: { baseUrl: "https://api.bscscan.com/api" },
  polygon: { baseUrl: "https://api.polygonscan.com/api" },
  avalanche: { baseUrl: "https://api.snowtrace.io/api" },
  arbitrum: { baseUrl: "https://api.arbiscan.io/api" },
  optimism: { baseUrl: "https://api-optimistic.etherscan.io/api" },
};

type ApiKeys = Record<string, string | undefined>;

interface ExplorerTx {
  hash: string;
  from: string;
  to: string;
  value: string;
  timeStamp: string;
  blockNumber: string;
  contractAddress?: string;
  input?: string;
}
interface ExplorerTokenTx {
  hash: string;
  from: string;
  to: string;
  value: string;
  timeStamp: string;
  blockNumber: string;
  contractAddress: string;
}

// Works without API key (rate limited). Pass apiKeys for higher limits.
export class DefaultHistoryProvider implements HistoryProvider {
  constructor(private readonly apiKeys: ApiKeys = {}) {}

  async getTransactions(
    address: string,
    chain: ChainId,
    limit: number
  ): Promise<NormalizedTransaction[]> {
    const config = EXPLORER_CONFIG[chain];
    if (!config) return [];

    const key = this.getApiKey(chain);
    const [normal, token] = await Promise.allSettled([
      this.fetchNormal(config.baseUrl, address, limit, key),
      this.fetchToken(config.baseUrl, address, limit, key),
    ]);

    const results: NormalizedTransaction[] = [];
    if (normal.status === "fulfilled") results.push(...normal.value);
    if (token.status === "fulfilled") results.push(...token.value);

    const seen = new Set<string>();
    return results
      .filter((tx) => {
        if (seen.has(tx.hash)) return false;
        seen.add(tx.hash);
        return true;
      })
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, limit);
  }

  private getApiKey(chain: ChainId): string {
    const map: Partial<Record<ChainId, string | undefined>> = {
      ethereum: this.apiKeys["etherscan"],
      bnb: this.apiKeys["bscscan"],
      polygon: this.apiKeys["polygonscan"],
    };
    return map[chain] ?? "";
  }

  private async fetchNormal(
    base: string,
    address: string,
    limit: number,
    key: string
  ): Promise<NormalizedTransaction[]> {
    const data = await fetchWithRetry(
      buildUrl(base, {
        module: "account",
        action: "txlist",
        address,
        startblock: "0",
        endblock: "99999999",
        page: "1",
        offset: String(limit),
        sort: "desc",
        apikey: key,
      })
    );
    if (!data?.result || !Array.isArray(data.result)) return [];
    return (data.result as ExplorerTx[]).map((tx) =>
      normalizeEVMTx(tx, address)
    );
  }

  private async fetchToken(
    base: string,
    address: string,
    limit: number,
    key: string
  ): Promise<NormalizedTransaction[]> {
    const data = await fetchWithRetry(
      buildUrl(base, {
        module: "account",
        action: "tokentx",
        address,
        startblock: "0",
        endblock: "99999999",
        page: "1",
        offset: String(limit),
        sort: "desc",
        apikey: key,
      })
    );
    if (!data?.result || !Array.isArray(data.result)) return [];
    return (data.result as ExplorerTokenTx[]).map((tx) =>
      normalizeEVMTokenTx(tx, address)
    );
  }
}

// 0xe19c2253 — batch transfer(address[],address[],address[],uint256[])
// Real attack tx: 0x05c6e673787275bdff029723492a07f4d9aad9b0e4fbfb7ff95bfb12e641bd48
const BATCH_POISON_IDS = new Set(["0xe19c2253"]);

function normalizeEVMTx(
  tx: ExplorerTx,
  userAddress: string
): NormalizedTransaction {
  const value = BigInt(tx.value || "0");
  const methodId = tx.input?.slice(0, 10) ?? "0x";
  return {
    hash: tx.hash,
    from: tx.from.toLowerCase(),
    to: (tx.to || "").toLowerCase(),
    value,
    timestamp: Number(tx.timeStamp),
    blockNumber: Number(tx.blockNumber),
    isIncoming: tx.to?.toLowerCase() === userAddress.toLowerCase(),
    contractAddress: tx.contractAddress || undefined,
    methodId: methodId || undefined,
    isZeroValue: value === 0n,
    isBatchPoison: value === 0n && BATCH_POISON_IDS.has(methodId),
  };
}

function normalizeEVMTokenTx(
  tx: ExplorerTokenTx,
  userAddress: string
): NormalizedTransaction {
  const tokenValue = BigInt(tx.value || "0");
  // Mirror the null-safety used in normalizeEVMTx — Etherscan can return
  // empty / partial rows and unguarded .toLowerCase() would crash the whole
  // history fetch on a single malformed entry.
  const from = (tx.from || "").toLowerCase();
  const to   = (tx.to   || "").toLowerCase();
  const userLower = userAddress.toLowerCase();
  return {
    hash: tx.hash,
    from,
    to,
    value: 0n,
    tokenValue,
    timestamp: Number(tx.timeStamp),
    blockNumber: Number(tx.blockNumber),
    isIncoming: to === userLower,
    contractAddress: tx.contractAddress,
    isZeroValue: tokenValue === 0n,
    isBatchPoison: tokenValue === 0n,
  };
}

function buildUrl(base: string, params: Record<string, string>): string {
  return (
    base +
    "?" +
    Object.entries(params)
      .filter(([, v]) => v !== "")
      .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
      .join("&")
  );
}

async function fetchWithRetry(
  url: string,
  retries = HTTP_RETRIES,
  delay   = HTTP_RETRY_DELAY_MS
): Promise<{ result: unknown } | null> {
  for (let i = 0; i <= retries; i++) {
    try {
      const res = await fetch(url, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(HISTORY_FETCH_TIMEOUT_MS),
      });
      if (!res.ok) {
        if (res.status === 429 && i < retries) {
          logEvent("warn", "historyFetcher", "rate limited, retrying",
            { attempt: i + 1, status: res.status });
          await sleep(delay * (i + 1));
          continue;
        }
        logEvent("warn", "historyFetcher", "http error",
          { status: res.status });
        return null;
      }
      const json = await res.json();
      if (json?.status === "0" && json?.message !== "No transactions found") {
        logEvent("warn", "historyFetcher", "explorer api error",
          { message: json?.message, result: json?.result });
        return null;
      }
      return json;
    } catch (err) {
      if (i < retries) {
        logEvent("warn", "historyFetcher", "network error, retrying",
          { attempt: i + 1, error: errMsg(err) });
        await sleep(delay);
        continue;
      }
      logEvent("error", "historyFetcher", "network error, giving up",
        { error: errMsg(err) });
      return null;
    }
  }
  return null;
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
