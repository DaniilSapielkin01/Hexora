// Known legitimate protocol contract addresses
// Used to distinguish legitimate delegation from malicious delegation
// A delegation to Venus's own contracts is normal
// A delegation to unknown address via Venus interface is suspicious

export interface ProtocolInfo {
  name:     string
  category: "lending" | "dex" | "nft" | "bridge" | "staking" | "multisig"
  chain:    string[]
}

// Known protocol addresses — delegations TO these are safe
export const KNOWN_PROTOCOL_ADDRESSES = new Map<string, ProtocolInfo>([

  // ── Venus Protocol (BNB Chain) ─────────────────────────────────────────────
  ["0xfd36e2c2a6789db23113685031d7f16329158384", { name: "Venus: Comptroller",  category: "lending", chain: ["bnb"] }],
  ["0x95c78222b3d6e262173aea1bb4cf0b8d1b2a9b0a", { name: "Venus: vBNB",         category: "lending", chain: ["bnb"] }],
  ["0xeca88125a5adbe82614ffc12d0db554e2e2867c8", { name: "Venus: vUSDC",        category: "lending", chain: ["bnb"] }],
  ["0xf508fcd89b8bd15579dc79a6827cb4686a3592c8", { name: "Venus: vETH",         category: "lending", chain: ["bnb"] }],

  // ── Aave (Ethereum) ───────────────────────────────────────────────────────
  ["0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2", { name: "Aave: Pool v3",              category: "lending", chain: ["ethereum"] }],
  ["0x2f39d218133afab8f2b819b1066c7e434ad94e9e", { name: "Aave: PoolAddressesProvider", category: "lending", chain: ["ethereum"] }],
  ["0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9", { name: "Aave: AAVE Token",            category: "lending", chain: ["ethereum"] }],

  // ── Compound (Ethereum) ───────────────────────────────────────────────────
  ["0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b", { name: "Compound: Comptroller", category: "lending", chain: ["ethereum"] }],
  ["0xc3d688b66703497daa19211eedff47f25384cdc3", { name: "Compound: Comet USDC",  category: "lending", chain: ["ethereum"] }],
  ["0xc00e94cb662c3520282e6f5717214004a7f26888", { name: "Compound: COMP Token",  category: "lending", chain: ["ethereum"] }],

  // ── Morpho (Ethereum) ─────────────────────────────────────────────────────
  ["0xbbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb", { name: "Morpho: Blue",    category: "lending", chain: ["ethereum"] }],
  ["0x9ee31e845ff1358bf6b1f914d3918c6223c75573", { name: "Morpho: AaveV3", category: "lending", chain: ["ethereum"] }],

  // ── dYdX ─────────────────────────────────────────────────────────────────
  ["0x1e0447b19bb6ecfdae1e4ae1694b0c3659614e4e", { name: "dYdX: Solo Margin", category: "lending", chain: ["ethereum"] }],

  // ── Safe (Gnosis Safe) ────────────────────────────────────────────────────
  ["0xd9db270c1b5e3bd161e8c8503c55ceabee709552", { name: "Safe: 1.3.0",    category: "multisig", chain: ["ethereum", "bnb", "polygon"] }],
  ["0x69f4d1788e39c87893c980c06edf4b7f686e2938", { name: "Safe: 1.3.0+L2", category: "multisig", chain: ["ethereum"] }],
])

// Is address a known legitimate protocol?
export function isKnownProtocol(address: string): ProtocolInfo | null {
  return KNOWN_PROTOCOL_ADDRESSES.get(address.toLowerCase()) ?? null
}

// Delegation-granting method signatures across lending protocols
// These methods give a third party rights to borrow/withdraw on your behalf
export const DELEGATION_METHOD_IDS = new Map<string, string>([
  // Venus Protocol
  ["0xe8eda9df", "updateDelegate(address,bool)"],               // Venus — the exact Venus exploit method
  ["0x6a20de92", "approveDelegation(address,uint256)"],        // Venus debt delegation

  // Aave
  ["0xc04a8a10", "approveDelegation(address,uint256)"],        // Aave variable debt
  ["0x395093d1", "increaseAllowance(address,uint256)"],        // Aave stable debt

  // Compound
  ["0x0aaf7043", "allow(address,bool)"],                       // Compound Comet — allow manager
  ["0xb27b8804", "setUserUseReserveAsCollateral(address,bool)"],// Aave collateral toggle

  // Generic operator approvals used across DeFi
  ["0xa22cb465", "setApprovalForAll(address,bool)"],           // ERC-721/1155 — already covered
  ["0x1b6b9e4a", "setOperator(address,bool)"],                 // generic operator pattern
  ["0x6352211e", "approveDelegate(address)"],                  // generic delegate pattern
  ["0x3b4da69f", "updateDelegateForAll(address,bool)"],        // generic delegate all
])

// ERC-4337 Account Abstraction method IDs
export const AA_METHOD_IDS = new Map<string, string>([
  ["0x1fad948c", "handleOps((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[],address)"],
  ["0x765e827f", "handleAggregatedOps((((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[],address,bytes)[]),address)"],
  ["0xb61d27f6", "execute(address,uint256,bytes)"],            // Safe/AA execute
  ["0x8d80ff0a", "multiSend(bytes)"],                         // Safe multiSend
])

// Re-export with expected names for backward compatibility
export const KNOWN_PROTOCOLS = KNOWN_PROTOCOL_ADDRESSES

export function isDelegationMethod(methodId: string): string | null {
  return DELEGATION_METHOD_IDS.get(methodId.toLowerCase()) ?? null
}

export function assessProtocolMethodRisk(
  contractAddress: string,
  methodId:        string
): { risk: "safe" | "warning" | "danger"; reason: string | null } {
  const protocol    = isKnownProtocol(contractAddress)
  const isDelegation = isDelegationMethod(methodId)

  if (!isDelegation) return { risk: "safe", reason: null }

  if (protocol) {
    return {
      risk:   "warning",
      reason: `${protocol.name}: calling ${isDelegation} — grants third-party access to funds`,
    }
  }

  return {
    risk:   "danger",
    reason: `Unknown contract calling ${isDelegation} — common attack pattern`,
  }
}
