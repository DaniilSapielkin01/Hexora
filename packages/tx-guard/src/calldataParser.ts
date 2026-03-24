// Offline calldata analysis — no RPC needed
// Extracts method, spender, amount from raw hex calldata

import {
  METHOD_APPROVE, METHOD_PERMIT, METHOD_TRANSFER_FROM,
  METHOD_SET_APPROVAL_FOR_ALL, METHOD_PERMIT2_APPROVE, METHOD_PERMIT2_PERMIT,
  METHOD_MULTICALL, METHOD_MULTICALL_DEADLINE, METHOD_NAMES,
} from "./methodIds.js"

export interface ParsedCalldata {
  methodId:   string | null
  methodName: string | null
  // approve / permit fields
  spender:    string | null
  amount:     bigint | null
  // setApprovalForAll fields
  operator:   string | null
  approved:   boolean | null
  // transferFrom fields
  from:       string | null
  to:         string | null
}

// Max uint256 = 2^256 - 1 — unlimited approval
export const MAX_UINT256 =
  0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn

export function parseCalldata(data: string): ParsedCalldata {
  const empty: ParsedCalldata = {
    methodId: null, methodName: null,
    spender: null, amount: null,
    operator: null, approved: null,
    from: null, to: null,
  }

  if (!data || data === "0x" || data.length < 10) return empty

  const hex      = data.startsWith("0x") ? data.slice(2) : data
  const methodId = "0x" + hex.slice(0, 8).toLowerCase()
  const params   = hex.slice(8)

  const base: ParsedCalldata = {
    ...empty,
    methodId,
    methodName: METHOD_NAMES[methodId] ?? null,
  }

  // approve(address spender, uint256 amount)
  if (methodId === METHOD_APPROVE && params.length >= 128) {
    return {
      ...base,
      spender: extractAddress(params, 0),
      amount:  extractUint256(params, 32),
    }
  }

  // permit(address owner, address spender, uint256 value, uint256 deadline, ...)
  if (methodId === METHOD_PERMIT && params.length >= 256) {
    return {
      ...base,
      spender: extractAddress(params, 32),   // second param is spender
      amount:  extractUint256(params, 64),
    }
  }

  // setApprovalForAll(address operator, bool approved)
  if (methodId === METHOD_SET_APPROVAL_FOR_ALL && params.length >= 128) {
    return {
      ...base,
      operator: extractAddress(params, 0),
      approved: extractBool(params, 32),
    }
  }

  // transferFrom(address from, address to, uint256 amount)
  if (methodId === METHOD_TRANSFER_FROM && params.length >= 192) {
    return {
      ...base,
      from:   extractAddress(params, 0),
      to:     extractAddress(params, 32),
      amount: extractUint256(params, 64),
    }
  }

  // permit2.approve(address token, address spender, uint160 amount, uint48 expiration)
  if (methodId === METHOD_PERMIT2_APPROVE && params.length >= 128) {
    return {
      ...base,
      spender: extractAddress(params, 32),
      amount:  extractUint256(params, 64),
    }
  }

  // permit2.permit — single token permit
  if (methodId === METHOD_PERMIT2_PERMIT) {
    return { ...base }
  }

  // multicall — flag for further analysis
  if (methodId === METHOD_MULTICALL || methodId === METHOD_MULTICALL_DEADLINE) {
    return { ...base }
  }

  return base
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Extract EVM-encoded address at 32-byte slot offset (in hex chars = offset*2)
function extractAddress(params: string, byteOffset: number): string | null {
  const start = byteOffset * 2
  const slice = params.slice(start, start + 64)
  if (slice.length < 64) return null
  // Address is right-padded in first slot, last 40 hex chars = 20 bytes
  return "0x" + slice.slice(24).toLowerCase()
}

// Extract uint256 at 32-byte slot offset
function extractUint256(params: string, byteOffset: number): bigint | null {
  const start = byteOffset * 2
  const slice = params.slice(start, start + 64)
  if (slice.length < 64) return null
  try {
    return BigInt("0x" + slice)
  } catch {
    return null
  }
}

// Extract bool at 32-byte slot offset
function extractBool(params: string, byteOffset: number): boolean | null {
  const start = byteOffset * 2
  const slice = params.slice(start, start + 64)
  if (slice.length < 64) return null
  return slice.endsWith("1")
}
