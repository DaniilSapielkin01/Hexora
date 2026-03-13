import {
  RawProvider,
  EIP1193Provider,
  PhantomProvider,
  HexoraProvider,
  ProviderType,
  ChainId,
  EVM_CHAIN_MAP,
  CheckError,
} from "../types/index.js";

function isEIP1193(p: unknown): p is EIP1193Provider {
  return (
    typeof p === "object" &&
    p !== null &&
    "request" in p &&
    typeof (p as EIP1193Provider).request === "function"
  );
}

function isPhantom(p: unknown): p is PhantomProvider {
  return (
    typeof p === "object" &&
    p !== null &&
    ("isPhantom" in p || "publicKey" in p)
  );
}

class EVMAdapter implements HexoraProvider {
  constructor(private readonly provider: EIP1193Provider) {}
  isEVM(): boolean {
    return true;
  }
  getProviderType(): ProviderType {
    return "eip1193";
  }

  async rawChainId(): Promise<string> {
    try {
      const id = await this.provider.request({ method: "eth_chainId" });
      return String(id);
    } catch {
      try {
        const v = await this.provider.request({ method: "net_version" });
        return "0x" + Number(v).toString(16);
      } catch {
        throw buildError(
          "network_unavailable",
          "Failed to get chainId from provider"
        );
      }
    }
  }

  async chainId(): Promise<ChainId> {
    const raw = await this.rawChainId();
    const hex = raw.startsWith("0x") ? raw : "0x" + Number(raw).toString(16);
    const chain = EVM_CHAIN_MAP[hex];
    if (!chain)
      throw buildError(
        "unsupported_chain",
        `Chain ${raw} is not supported yet`
      );
    return chain;
  }
}

class SolanaAdapter implements HexoraProvider {
  constructor(private readonly _provider: PhantomProvider) {}
  isEVM(): boolean {
    return false;
  }
  getProviderType(): ProviderType {
    return "phantom";
  }
  async rawChainId(): Promise<string> {
    return "solana-mainnet";
  }
  async chainId(): Promise<ChainId> {
    return "solana";
  }
}

// Auto-detects provider type and wraps into unified HexoraProvider.
// Supports all EIP-1193 wallets + Phantom.
// New chains (Bitcoin, Tron) — add adapter here, nothing else changes.
export function detectProvider(raw: RawProvider): HexoraProvider {
  if (isEIP1193(raw)) return new EVMAdapter(raw);
  if (isPhantom(raw)) return new SolanaAdapter(raw);
  throw buildError(
    "unknown_provider",
    "Unknown provider. Must implement EIP-1193 or be Phantom-compatible."
  );
}

function buildError(
  code: CheckError["code"],
  message: string
): Error & { hexoraCode: CheckError["code"] } {
  const err = new Error(message) as Error & { hexoraCode: CheckError["code"] };
  err.hexoraCode = code;
  return err;
}
