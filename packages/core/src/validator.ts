import { ChainId } from "./types/index.js";

const EVM_CHAINS = new Set<ChainId>([
  "ethereum",
  "bnb",
  "polygon",
  "avalanche",
  "arbitrum",
  "optimism",
]);

export function validateAddress(address: string, chain: ChainId): boolean {
  if (!address || typeof address !== "string") return false;
  if (EVM_CHAINS.has(chain)) return /^0x[0-9a-fA-F]{40}$/.test(address);
  if (chain === "solana") return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address);
  if (chain === "bitcoin")
    return (
      /^1[a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(address) ||
      /^3[a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(address) ||
      /^bc1[a-z0-9]{6,87}$/.test(address)
    );
  if (chain === "tron") return /^T[a-km-zA-HJ-NP-Z1-9]{33}$/.test(address);
  return address.length > 0;
}
