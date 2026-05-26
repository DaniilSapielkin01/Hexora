// Domain age check via RDAP (primary) and Shreshta WHOIS API (fallback)
//
// RDAP — open protocol mandated by ICANN, no key, no registration required
// https://www.iana.org/assignments/rdap-dns/rdap-dns.xhtml
//
// Shreshta WHOIS — free, no key, returns creation_date + registrar
// https://domaininfo.shreshtait.com/api/search/{domain}
//
// Logic: young domain + high heuristic score = very likely scam
// We never block on age alone — it's a signal booster like PhishTank

const TIMEOUT_MS      = 3000
const RDAP_BASE       = "https://rdap.org/domain"
const SHRESHTA_BASE   = "https://domaininfo.shreshtait.com/api/search"

// Age thresholds in days
export const AGE_THRESHOLDS = {
  VERY_NEW:   7,   // < 7 days  → +25 pts (almost certainly scam if any other signal fires)
  NEW:        30,  // < 30 days → +18 pts
  RECENT:     90,  // < 90 days → +10 pts
  ESTABLISHED: 365 // > 1 year  → domain is old, no penalty
}

export interface DomainAgeResult {
  available:       boolean   // API was reachable
  createdAt:       Date | null
  ageInDays:       number | null
  registrar:       string | null
  isVeryNew:       boolean   // < 7 days
  isNew:           boolean   // < 30 days
  isRecent:        boolean   // < 90 days
}

// ── RDAP lookup ───────────────────────────────────────────────────────────────
async function fromRDAP(domain: string): Promise<DomainAgeResult> {
  const controller = new AbortController()
  const timeout    = setTimeout(() => controller.abort(), TIMEOUT_MS)

  try {
    const res = await fetch(`${RDAP_BASE}/${domain}`, {
      signal: controller.signal,
      headers: { Accept: "application/rdap+json" },
    })
    clearTimeout(timeout)

    if (!res.ok) return notAvailable()

    const data = await res.json() as {
      events?: Array<{ eventAction: string; eventDate: string }>
    }

    // RDAP uses eventAction: "registration" for creation date
    const registrationEvent = (data.events ?? []).find(
      (e) => e.eventAction === "registration"
    )

    if (!registrationEvent) return notAvailable()

    const createdAt = new Date(registrationEvent.eventDate)
    return buildResult(createdAt, null)
  } catch {
    clearTimeout(timeout)
    return notAvailable()
  }
}

// ── Shreshta WHOIS fallback ───────────────────────────────────────────────────
async function fromShreshta(domain: string): Promise<DomainAgeResult> {
  const controller = new AbortController()
  const timeout    = setTimeout(() => controller.abort(), TIMEOUT_MS)

  try {
    const res = await fetch(`${SHRESHTA_BASE}/${domain}`, {
      signal: controller.signal,
    })
    clearTimeout(timeout)

    if (!res.ok) return notAvailable()

    const data = await res.json() as {
      creation_date?: string
      registrar?:     string
    }

    if (!data.creation_date) return notAvailable()

    const createdAt = new Date(data.creation_date)
    return buildResult(createdAt, data.registrar ?? null)
  } catch {
    clearTimeout(timeout)
    return notAvailable()
  }
}

// ── Public API ────────────────────────────────────────────────────────────────
export async function checkDomainAge(domain: string): Promise<DomainAgeResult> {
  // Try RDAP first — it's the open standard
  const rdap = await fromRDAP(domain)
  if (rdap.available) return rdap

  // Fallback to Shreshta WHOIS
  return fromShreshta(domain)
}

// ── Apply age signal as confidence booster ────────────────────────────────────
export function applyAgeSignal(
  localConfidence: number,
  age:             DomainAgeResult,
  heuristicScore:  number
): { confidence: number; boosted: boolean; ageBonus: number } {
  if (!age.available || age.ageInDays === null) {
    return { confidence: localConfidence, boosted: false, ageBonus: 0 }
  }

  // Bonus = base (age-tier alone) + linear amplifier scaled by heuristicScore.
  // Previously these were step functions ("heuristicScore > 0 ? 25 : 15"),
  // which created brittle 10-point jumps when a single signal in the adjacent
  // heuristics module flipped on/off. Continuous interpolation keeps the
  // intent (newer + more heuristic signals → bigger bonus) but is stable to
  // small changes in the underlying scoring.
  let bonus = 0

  if (age.isVeryNew) {
    // < 7 days — strong base, scales up to +25 at heuristicScore=20
    bonus = 15 + Math.min(10, heuristicScore / 2)
  } else if (age.isNew) {
    // < 30 days — moderate base, scales up to +18 at heuristicScore=40
    bonus = 10 + Math.min(8, heuristicScore / 5)
  } else if (age.isRecent) {
    // < 90 days — weak alone, scales up to +10 at heuristicScore=50
    bonus = 5 + Math.min(5, heuristicScore / 10)
  }
  bonus = Math.round(bonus)

  if (bonus === 0) {
    return { confidence: localConfidence, boosted: false, ageBonus: 0 }
  }

  return {
    confidence: Math.min(localConfidence + bonus, 99),
    boosted:    true,
    ageBonus:   bonus,
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function buildResult(createdAt: Date, registrar: string | null): DomainAgeResult {
  const ageInDays = Math.floor(
    (Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24)
  )

  return {
    available:  true,
    createdAt,
    ageInDays,
    registrar,
    isVeryNew:  ageInDays < AGE_THRESHOLDS.VERY_NEW,
    isNew:      ageInDays < AGE_THRESHOLDS.NEW,
    isRecent:   ageInDays < AGE_THRESHOLDS.RECENT,
  }
}

function notAvailable(): DomainAgeResult {
  return {
    available:  false,
    createdAt:  null,
    ageInDays:  null,
    registrar:  null,
    isVeryNew:  false,
    isNew:      false,
    isRecent:   false,
  }
}
