// Analyze EIP-712 typed data signature requests
// This is the #1 drainer attack vector — "Sign this message" looks safe
// but can grant unlimited token access without gas
//
// Inferno/Angel Drainer primarily use:
//   1. Permit (EIP-2612) — ERC-20 offline approval
//   2. Permit2 — Uniswap's universal permit for any token
//   3. Seaport order spoofing — fake OpenSea orders

import type { TypedDataPayload } from "./types.js"
import { KNOWN_ROUTERS } from "./methodIds.js"

export interface TypedDataRisk {
  detected:   boolean
  reason:     string | null
  confidence: number
  spender:    string | null
  amount:     bigint | null
  warning:    string | null
}

// EIP-2612 Permit primary types
const PERMIT_TYPES = new Set(["Permit", "PermitSingle", "PermitBatch"])
// Seaport order types — commonly spoofed by drainers
const SEAPORT_TYPES = new Set([
  "Order", "OrderComponents", "BasicOrderParameters",
  "BulkOrder", "ConsiderationItem",
])
// Permit2 types
const PERMIT2_TYPES = new Set(["PermitSingle", "PermitBatch", "PermitTransferFrom"])

export function analyzeTypedData(payload: TypedDataPayload): TypedDataRisk {
  const clean: TypedDataRisk = {
    detected: false, reason: null, confidence: 0,
    spender: null, amount: null, warning: null,
  }

  const primaryType = payload.primaryType
  const message     = payload.message

  // ── 1. EIP-2612 Permit ───────────────────────────────────────────────────
  // permit(owner, spender, value, deadline, v, r, s)
  // Looks like "Approve token spending" — but happens offline, no gas
  if (PERMIT_TYPES.has(primaryType) && !PERMIT2_TYPES.has(primaryType)) {
    const spender = extractStringField(message, ["spender"])
    const value   = extractBigIntField(message, ["value", "amount"])

    // If spender is known router — lower risk
    if (spender && KNOWN_ROUTERS.has(spender.toLowerCase())) {
      return clean
    }

    const isUnlimited = value !== null && value >= (2n ** 200n)  // generous threshold

    return {
      detected:   true,
      reason:     "permit_drain",
      confidence: isUnlimited ? 90 : 75,
      spender,
      amount:     value,
      warning:    isUnlimited
        ? "This signature grants UNLIMITED token access to an unknown address. Never sign this outside a trusted DEX."
        : `This signature grants token access to ${spender ?? "unknown"}. Verify this is a trusted contract.`,
    }
  }

  // ── 2. Permit2 (Uniswap) ─────────────────────────────────────────────────
  // Permit2 is legitimate but drainers spoof it to get blanket access
  if (PERMIT2_TYPES.has(primaryType)) {
    const spender = extractStringField(message, ["spender", "to"])
    const amount  = extractBigIntField(message, ["amount", "value"])

    if (spender && KNOWN_ROUTERS.has(spender.toLowerCase())) {
      return clean
    }

    return {
      detected:   true,
      reason:     "permit2_drain",
      confidence: 85,
      spender,
      amount,
      warning:    `Permit2 signature to unknown spender ${spender ?? "unknown"}. This can drain all approved tokens in one transaction.`,
    }
  }

  // ── 3. Seaport order spoofing ─────────────────────────────────────────────
  // Inferno Drainer spoofs Seaport orders — victim thinks they're listing NFT
  // but actually signing away ETH or tokens to the attacker
  if (SEAPORT_TYPES.has(primaryType)) {
    // Check consideration items — what the "seller" receives
    // In a legit order: consideration goes to the seller
    // In a drainer: consideration goes to attacker address
    const consideration = message["consideration"] as Array<Record<string, unknown>> | undefined

    if (consideration && Array.isArray(consideration)) {
      for (const item of consideration) {
        // Strict type-check: a `null` recipient was previously coerced via
        // String(null) → "null" and treated as a real recipient (false
        // positive). Skip anything that isn't a non-empty string.
        const recipient = item["recipient"]
        if (typeof recipient !== "string" || !recipient) continue
        if (!KNOWN_ROUTERS.has(recipient.toLowerCase())) {
          return {
            detected:   true,
            reason:     "seaport_order_spoof",
            confidence: 80,
            spender:    recipient,
            amount:     null,
            warning:    "This looks like a Seaport marketplace order but sends assets to an unknown address. This is a common NFT drainer technique.",
          }
        }
      }
    }
  }

  return clean
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractStringField(
  obj: Record<string, unknown>,
  keys: string[]
): string | null {
  for (const key of keys) {
    const val = obj[key]
    if (typeof val === "string") return val
  }
  return null
}

function extractBigIntField(
  obj: Record<string, unknown>,
  keys: string[]
): bigint | null {
  for (const key of keys) {
    const val = obj[key]
    if (typeof val === "string" || typeof val === "number" || typeof val === "bigint") {
      try { return BigInt(val) } catch { continue }
    }
  }
  return null
}
