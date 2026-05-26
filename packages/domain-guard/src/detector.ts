import { domainToUnicode } from "node:url"
import { KNOWN_LEGIT_DOMAINS, KNOWN_PHISHING_DOMAINS } from "./knownDomains.js"
import {
  normalizeDomain, getRegisteredDomain, getSubdomainDepth,
  hasHomoglyph, normalizeHomoglyphs, isIDN,
  hasLeetSubstitution, normalizeLeet,
} from "./normalizer.js"
import { domainSimilarity, findMostSimilarLegit } from "./similarity.js"
import { runHeuristics, heuristicReason }          from "./heuristics.js"
import type { DomainScamReason } from "./types.js"

export interface DetectionResult {
  detected:        boolean
  reason:          DomainScamReason | null
  confidence:      number
  matchedLegit:    string | null
  similarityScore: number
  details: {
    isIDN:             boolean
    hasHomoglyph:      boolean
    subdomainDepth:    number
    registeredDomain:  string
    heuristicScore:    number
    heuristicSignals:  string[]
  }
}

const DEFAULT_TYPOSQUAT_THRESHOLD = 82
const HEURISTIC_CRITICAL = 55
const HEURISTIC_HIGH     = 35
const HEURISTIC_MEDIUM   = 20

export function detectDomain(
  rawInput:           string,
  typosquatThreshold = DEFAULT_TYPOSQUAT_THRESHOLD,
  customWhitelist:    string[] = [],
  customBlacklist:    string[] = [],
): DetectionResult {
  const domain           = normalizeDomain(rawInput)
  const registeredDomain = getRegisteredDomain(domain)
  const subdomainDepth   = getSubdomainDepth(domain)
  const idn              = isIDN(domain)
  const homoglyph        = hasHomoglyph(domain)
  const leet             = hasLeetSubstitution(domain)
  const heuristics       = runHeuristics(domain, registeredDomain)

  const details = {
    isIDN: idn, hasHomoglyph: homoglyph,
    subdomainDepth, registeredDomain,
    heuristicScore:   heuristics.score,
    heuristicSignals: heuristics.signals,
  }

  const blacklist = [...KNOWN_PHISHING_DOMAINS, ...customBlacklist]
  const whitelist = [...KNOWN_LEGIT_DOMAINS,    ...customWhitelist]

  // ── 1. Blacklist ──────────────────────────────────────────────────────────
  if (blacklist.includes(domain) || blacklist.includes(registeredDomain)) {
    return { detected: true, reason: "blacklisted_domain", confidence: 99,
      matchedLegit: null, similarityScore: 0, details }
  }

  // ── 2. Whitelist ──────────────────────────────────────────────────────────
  if (whitelist.includes(domain) || whitelist.includes(registeredDomain)) {
    return { detected: false, reason: null, confidence: 0,
      matchedLegit: domain, similarityScore: 100, details }
  }

  // ── 3. Homoglyph ──────────────────────────────────────────────────────────
  if (homoglyph) {
    const normalized = normalizeHomoglyphs(domain)
    if (whitelist.includes(normalized) || whitelist.includes(getRegisteredDomain(normalized))) {
      return { detected: true, reason: "homoglyph", confidence: 97,
        matchedLegit: normalized, similarityScore: 95, details }
    }
  }

  // ── 4. Leet substitution — "un1swap.org", "0pensea.io" ───────────────────
  if (leet) {
    const normalized = normalizeLeet(domain)
    const normalizedRD = getRegisteredDomain(normalized)
    if (whitelist.includes(normalized) || whitelist.includes(normalizedRD)) {
      return { detected: true, reason: "typosquat", confidence: 95,
        matchedLegit: normalized, similarityScore: 93, details }
    }
    // Also run similarity on leet-normalized version
    const leetMatch = findMostSimilarLegit(normalizedRD, whitelist, typosquatThreshold)
    if (leetMatch) {
      return { detected: true, reason: "typosquat", confidence: 90,
        matchedLegit: leetMatch.domain, similarityScore: leetMatch.score, details }
    }
  }

  // ── 5. IDN / Punycode ─────────────────────────────────────────────────────
  // Decode punycode (xn--…) to the actual unicode form, then strip homoglyphs
  // so we can compare against latin whitelist domains.
  if (idn) {
    let decoded = domain
    try { decoded = domainToUnicode(domain) || domain } catch { /* keep raw */ }
    decoded = normalizeHomoglyphs(decoded)
    const match = findMostSimilarLegit(getRegisteredDomain(decoded), whitelist, 70)
    if (match) {
      return { detected: true, reason: "idn_suspicious", confidence: 90,
        matchedLegit: match.domain, similarityScore: match.score, details }
    }
  }

  // ── 6. Subdomain hijack ───────────────────────────────────────────────────
  // Two patterns we catch:
  //   a) "opensea.io.phishing.com"     — full legit registered domain appears
  //      as a subdomain, but the actual registered domain is the attacker's.
  //   b) "app.uniswap.evil.com"        — only the legit SLD ("uniswap") is
  //      embedded as a label to fool users glancing at the URL bar.
  if (subdomainDepth >= 1) {
    const domainParts     = domain.split(".")
    // Labels that belong to the subdomain (everything except the last two).
    const subdomainLabels = domainParts.slice(0, -2)

    for (const legit of whitelist) {
      const legitBase = getRegisteredDomain(legit)
      if (legitBase === registeredDomain) continue   // legit's own subdomain

      // (a) full registered domain embedded in subdomain
      if (subdomainDepth >= 2 && domain.includes(legitBase + ".") && !domain.endsWith(legitBase)) {
        return { detected: true, reason: "subdomain_hijack", confidence: 92,
          matchedLegit: legit, similarityScore: 85, details }
      }

      // (b) legit SLD appears as a standalone subdomain label
      const legitSld = legitBase.split(".")[0] ?? ""
      if (legitSld.length >= 4 && subdomainLabels.includes(legitSld)) {
        return { detected: true, reason: "subdomain_hijack", confidence: 88,
          matchedLegit: legit, similarityScore: 80, details }
      }
    }
  }

  // ── 7. Heuristics (NFT spam / suspicious) ─────────────────────────────────
  if (heuristics.score >= HEURISTIC_CRITICAL) {
    return {
      detected: true,
      reason: heuristicReason(heuristics) as DomainScamReason,
      confidence: Math.min(heuristics.score + 10, 95),
      matchedLegit: null, similarityScore: 0, details,
    }
  }

  // ── 8. Typosquat ──────────────────────────────────────────────────────────
  const match = findMostSimilarLegit(registeredDomain, whitelist, typosquatThreshold)
  if (match) {
    // Confidence mapped from similarity. >=85 already means SLD is identical
    // or off by one — treat as high; >=90 means barely-distinguishable squat.
    const confidence =
      match.score >= 95 ? 95 :
      match.score >= 90 ? 90 :
      match.score >= 85 ? 80 :
      70
    const boosted = heuristics.score >= HEURISTIC_MEDIUM
      ? Math.min(confidence + 10, 97) : confidence
    return { detected: true, reason: "typosquat", confidence: boosted,
      matchedLegit: match.domain, similarityScore: match.score, details }
  }

  // ── 9. Weak heuristic signal ───────────────────────────────────────────────
  if (heuristics.score >= HEURISTIC_HIGH) {
    return {
      detected: true,
      reason: heuristicReason(heuristics) as DomainScamReason,
      confidence: heuristics.score,
      matchedLegit: null, similarityScore: 0, details,
    }
  }

  // ── Clean ─────────────────────────────────────────────────────────────────
  return { detected: false, reason: null, confidence: 0,
    matchedLegit: null, similarityScore: 0, details }
}
