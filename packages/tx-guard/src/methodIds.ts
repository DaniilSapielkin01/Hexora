// Known method IDs (first 4 bytes of keccak256 of function signature)
// Used for offline calldata pattern detection — no ABI decoding needed

// ── ERC-20 ────────────────────────────────────────────────────────────────────
// approve(address,uint256)
export const METHOD_APPROVE            = "0x095ea7b3"
// transfer(address,uint256)
export const METHOD_TRANSFER           = "0xa9059cbb"
// transferFrom(address,address,uint256)
export const METHOD_TRANSFER_FROM      = "0x23b872dd"
// permit(address,address,uint256,uint256,uint8,bytes32,bytes32) — EIP-2612
export const METHOD_PERMIT             = "0xd505accf"
// increaseAllowance(address,uint256)
export const METHOD_INCREASE_ALLOWANCE = "0x39509351"

// ── ERC-721 / ERC-1155 (NFT) ──────────────────────────────────────────────────
// setApprovalForAll(address,bool)
export const METHOD_SET_APPROVAL_FOR_ALL = "0xa22cb465"
// approve(address,uint256) — same selector as ERC-20 approve
// safeTransferFrom(address,address,uint256)
export const METHOD_SAFE_TRANSFER_FROM   = "0x42842e0e"

// ── Uniswap Permit2 ───────────────────────────────────────────────────────────
// approve(address,address,uint160,uint48) — Permit2 token approval
export const METHOD_PERMIT2_APPROVE = "0x87517c45"
// permit(address,(address,uint160,uint48,uint48),bytes) — Permit2 single permit
export const METHOD_PERMIT2_PERMIT  = "0x2b67b570"

// ── Seaport (OpenSea) — spoofed by Inferno/Angel Drainer ─────────────────────
// fulfillBasicOrder(BasicOrderParameters) — legitimate Seaport
export const METHOD_SEAPORT_BASIC  = "0xfb0f3ee1"
// fulfillOrder((Order,bytes),bytes32) — legitimate Seaport
export const METHOD_SEAPORT_FULFILL = "0xb3a34c4c"

// ── Multicall patterns ────────────────────────────────────────────────────────
// multicall(bytes[]) — Uniswap v3 / many protocols
export const METHOD_MULTICALL      = "0xac9650d8"
// multicall(uint256,bytes[]) — Uniswap v3 with deadline
export const METHOD_MULTICALL_DEADLINE = "0x5ae401dc"

// ── Address Poison (batch) — from address-guard research ─────────────────────
// batch poison method used by Fake_Phishing contracts on BNB Chain
export const METHOD_BATCH_POISON   = "0xe19c2253"

// ── Known drainer contract signatures ────────────────────────────────────────
// These method IDs appear in known drainer contracts
// Source: on-chain analysis of Inferno/Pink/Angel drainer transactions
export const KNOWN_DRAINER_METHOD_IDS = new Set([
  "0x1cff79cd",  // execute(address,bytes) — generic proxy drain
  "0x3593564c",  // execute(bytes,bytes[],uint256) — Uniswap UniversalRouter (spoofed)
  "0x12aa3caf",  // swap() — 1inch spoofed
  METHOD_BATCH_POISON,
])

// Map method ID → human readable name
export const METHOD_NAMES: Record<string, string> = {
  [METHOD_APPROVE]:               "approve",
  [METHOD_TRANSFER]:              "transfer",
  [METHOD_TRANSFER_FROM]:         "transferFrom",
  [METHOD_PERMIT]:                "permit (EIP-2612)",
  [METHOD_INCREASE_ALLOWANCE]:    "increaseAllowance",
  [METHOD_SET_APPROVAL_FOR_ALL]:  "setApprovalForAll",
  [METHOD_SAFE_TRANSFER_FROM]:    "safeTransferFrom",
  [METHOD_PERMIT2_APPROVE]:       "permit2.approve",
  [METHOD_PERMIT2_PERMIT]:        "permit2.permit",
  [METHOD_SEAPORT_BASIC]:         "seaport.fulfillBasicOrder",
  [METHOD_SEAPORT_FULFILL]:       "seaport.fulfillOrder",
  [METHOD_MULTICALL]:             "multicall",
  [METHOD_MULTICALL_DEADLINE]:    "multicall (with deadline)",
  [METHOD_BATCH_POISON]:          "batchPoison",
}

// Known legitimate spenders — DEX routers, aggregators, etc.
// If approve() goes to one of these — lower risk
export const KNOWN_ROUTERS = new Set([
  // Uniswap
  "0x000000000022d473030f116ddee9f6b43ac78ba3",  // Permit2
  "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad",  // UniversalRouter v2
  "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b",  // UniversalRouter v1
  "0xe592427a0aece92de3edee1f18e0157c05861564",  // SwapRouter v2
  // 1inch
  "0x1111111254eeb25477b68fb85ed929f73a960582",  // 1inch AggregationRouter v5
  "0x111111125421ca6dc452d289314280a0f8842a65",  // 1inch AggregationRouter v6
  // PancakeSwap
  "0x13f4ea83d0bd40e75c8222255bc855a974568dd4",  // PancakeSwap UniversalRouter
  // OpenSea Seaport
  "0x00000000000000adc04c56bf30ac9d3c0aaf14dc",  // Seaport 1.5
  "0x0000000000000068f116a894984e2db1123eb395",  // Seaport 1.6
  // Blur
  "0x00000000000111abe46ff893f3b2fdf1f759a8a8",  // Blur Marketplace
  // Safe
  "0xd9db270c1b5e3bd161e8c8503c55ceabee709552",  // Gnosis Safe 1.3
])
