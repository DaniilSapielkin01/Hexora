import { normalizeDomain }   from "./normalizer.js"
import { detectDomain }      from "./detector.js"
import { buildDomainResult } from "./scorer.js"
import { checkDomainAge, applyAgeSignal } from "./domainAge.js"
import type { CheckDomainParams, CheckDomainResult } from "./types.js"

export async function checkDomain(params: CheckDomainParams): Promise<CheckDomainResult> {
  const {
    domain: rawInput,
    typosquatThreshold,
    customWhitelist = [],
    customBlacklist = [],
    checkAge        = false,
  } = params

  try {
    const domain    = normalizeDomain(rawInput)
    const detection = detectDomain(domain, typosquatThreshold, customWhitelist, customBlacklist)
    const result    = buildDomainResult(domain, detection)

    // Default age block — not checked
    let domainAge = {
      checked: false, ageInDays: null as number | null,
      isVeryNew: false, isNew: false, isRecent: false,
      registrar: null as string | null,
    }

    if (checkAge) {
      const age        = await checkDomainAge(domain)
      const ageBoosted = applyAgeSignal(
        result.confidence,
        age,
        detection.details.heuristicScore
      )

      domainAge = {
        checked:   age.available,
        ageInDays: age.ageInDays,
        isVeryNew: age.isVeryNew,
        isNew:     age.isNew,
        isRecent:  age.isRecent,
        registrar: age.registrar,
      }

      // New domain + existing signals → flag as scam
      // New domain alone (no other signals) → low risk warning only
      const scam = result.scam ||
        (ageBoosted.boosted && age.isNew && detection.details.heuristicScore >= 15)

      // If age made this a new scam detection — set reason
      const reason = scam && !result.scam ? "new_domain" : result.reason

      return {
        ...result,
        scam,
        reason,
        confidence: ageBoosted.confidence,
        details: { ...result.details, domainAge },
        error: null,
      }
    }

    return {
      ...result,
      details: { ...result.details, domainAge },
      error: null,
    }

  } catch (err) {
    return {
      scam: false, reason: null, riskLevel: "none",
      confidence: 0, domain: rawInput,
      matchedLegit: null, similarityScore: 0,
      details: {
        isIDN: false, hasHomoglyph: false,
        subdomainDepth: 0, registeredDomain: rawInput,
        heuristicScore: 0, heuristicSignals: [],
        domainAge: {
          checked: false, ageInDays: null,
          isVeryNew: false, isNew: false, isRecent: false, registrar: null,
        },
      },
      error: {
        code:    "unknown",
        message: err instanceof Error ? err.message : "Unknown error",
      },
    }
  }
}
