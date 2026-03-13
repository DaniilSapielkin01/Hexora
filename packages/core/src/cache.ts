import { NormalizedTransaction, ChainId } from "./types/index.js";

// In-memory session cache. Privacy-first — no persistence, clears on page unload.
const CACHE_TTL_MS = 5 * 60 * 1000;

interface CacheEntry {
  transactions: NormalizedTransaction[];
  fetchedAt: number;
}

class TransactionCache {
  private store = new Map<string, CacheEntry>();

  private key(address: string, chain: ChainId): string {
    return `${chain}:${address.toLowerCase()}`;
  }

  get(address: string, chain: ChainId): NormalizedTransaction[] | null {
    const entry = this.store.get(this.key(address, chain));
    if (!entry) return null;
    if (Date.now() - entry.fetchedAt > CACHE_TTL_MS) {
      this.store.delete(this.key(address, chain));
      return null;
    }
    return entry.transactions;
  }

  set(address: string, chain: ChainId, txs: NormalizedTransaction[]): void {
    this.store.set(this.key(address, chain), {
      transactions: txs,
      fetchedAt: Date.now(),
    });
  }

  clear(): void {
    this.store.clear();
  }
}

export const txCache = new TransactionCache();
