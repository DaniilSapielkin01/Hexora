import { NormalizedTransaction, ChainId } from "./types/index.js";

// In-memory session cache. Privacy-first — no persistence, clears on page unload.
const CACHE_TTL_MS = 5 * 60 * 1000;
// Bounded LRU. Long-running services check many distinct addresses; without
// a cap the cache grows until the process is killed. Map preserves insertion
// order so we evict the oldest entry once we exceed the cap — O(1) LRU.
const CACHE_MAX_ENTRIES = 1000;

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
    const k = this.key(address, chain);
    const entry = this.store.get(k);
    if (!entry) return null;
    if (Date.now() - entry.fetchedAt > CACHE_TTL_MS) {
      this.store.delete(k);
      return null;
    }
    // Touch on access — move to most-recently-used end.
    this.store.delete(k);
    this.store.set(k, entry);
    return entry.transactions;
  }

  set(address: string, chain: ChainId, txs: NormalizedTransaction[]): void {
    const k = this.key(address, chain);
    if (this.store.has(k)) this.store.delete(k);
    this.store.set(k, { transactions: txs, fetchedAt: Date.now() });
    if (this.store.size > CACHE_MAX_ENTRIES) {
      const oldest = this.store.keys().next().value;
      if (oldest !== undefined) this.store.delete(oldest);
    }
  }

  clear(): void {
    this.store.clear();
  }
}

export const txCache = new TransactionCache();
