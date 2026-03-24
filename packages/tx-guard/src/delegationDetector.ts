// Delegation pattern detector — closes the Venus exploit gap
// Detects when a transaction grants another address rights to act on your behalf
// in lending protocols (borrow, withdraw, transfer)
//
// Real attack: Venus Protocol $27M exploit (2025)
// Attacker used fake Zoom → victim signed updateDelegate() → attacker drained funds

import { DELEGATION_METHOD_IDS, KNOWN_PROTOCOL_ADDRESSES, isKnownProtocol } from "./knownProtocols.js"
import type { RawTransaction } from "./types.js"

export interface DelegationRisk {
  detected:    boolean
  methodId:    string | null
  methodName:  string | null
  delegate:    string | null     // address receiving delegation
  protocol:    string | null     // protocol name if known
  isToKnown:   boolean           // delegation to known protocol = lower risk
  confidence:  number
  warning:     string | null
}

export function detectDelegation(tx: RawTransaction): DelegationRisk {
  const clean: DelegationRisk = {
    detected: false, methodId: null, methodName: null,
    delegate: null, protocol: null, isToKnown: false,
    confidence: 0, warning: null,
  }

  const data = tx.data ?? "0x"
  if (!data || data === "0x" || data.length < 10) return clean

  const hex      = data.startsWith("0x") ? data.slice(2) : data
  const methodId = "0x" + hex.slice(0, 8).toLowerCase()
  const params   = hex.slice(8)

  // Check if this is a delegation method
  const methodName = DELEGATION_METHOD_IDS.get(methodId)
  if (!methodName) return clean

  // Extract delegate address (first param in most delegation methods)
  let delegate: string | null = null
  if (params.length >= 64) {
    delegate = "0x" + params.slice(24, 64).toLowerCase()
  }

  // Extract bool param (second param — true = granting, false = revoking)
  let granting = true  // assume granting if we can't determine
  if (params.length >= 128) {
    const boolSlice = params.slice(64, 128)
    granting = !boolSlice.endsWith("0")
  }

  // If revoking delegation — that's actually GOOD, user is protecting themselves
  if (!granting) {
    return clean
  }

  // Check if delegate is a known protocol address (lower risk)
  const knownProtocol = delegate ? isKnownProtocol(delegate) : null
  const isToKnown     = knownProtocol !== null

  // Check if the contract being called is a known protocol
  const calledProtocol = tx.to ? isKnownProtocol(tx.to) : null

  // High risk: calling known protocol (e.g. Venus) but delegating to UNKNOWN address
  // This is exactly the Venus exploit pattern
  if (calledProtocol && !isToKnown) {
    return {
      detected:   true,
      methodId,
      methodName,
      delegate,
      protocol:   calledProtocol.name,
      isToKnown:  false,
      confidence: 92,
      warning:    [
        `🚨 DELEGATION ATTACK DETECTED`,
        ``,
        `This transaction grants "${delegate}" the ability to borrow and withdraw`,
        `your funds from ${calledProtocol.name}.`,
        ``,
        `This is exactly the technique used in the Venus Protocol $27M exploit.`,
        `The delegated address is NOT a known protocol contract.`,
        ``,
        `DO NOT sign this transaction unless you explicitly set this up yourself.`,
        `If you received a link to sign this — it is a phishing attack.`,
      ].join("\n"),
    }
  }

  // Medium risk: unknown contract with delegation method
  if (!calledProtocol && !isToKnown) {
    return {
      detected:   true,
      methodId,
      methodName,
      delegate,
      protocol:   null,
      isToKnown:  false,
      confidence: 75,
      warning:    `This transaction grants borrowing/withdrawal rights to ${delegate}. Verify this is intentional before signing.`,
    }
  }

  // Lower risk: delegation to known protocol (e.g. Compound allow manager)
  if (isToKnown) {
    return {
      detected:   false,  // not flagging — delegation to known protocol is normal
      methodId,
      methodName,
      delegate,
      protocol:   knownProtocol?.name ?? null,
      isToKnown:  true,
      confidence: 0,
      warning:    null,
    }
  }

  return clean
}
