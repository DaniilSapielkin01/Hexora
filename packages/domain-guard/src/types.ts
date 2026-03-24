import type { RiskLevel, CheckError } from "@hexora/core"

export type DomainScamReason =
  | "blacklisted_domain"
  | "typosquat"
  | "homoglyph"
  | "subdomain_hijack"
  | "idn_suspicious"
  | "nft_spam_domain"
  | "suspicious_domain"
  | "new_domain"          // domain registered < 30 days ago + other signals

export interface CheckDomainParams {
  domain:               string
  typosquatThreshold?:  number     // default 82
  customWhitelist?:     string[]   // your own safe domains
  customBlacklist?:     string[]   // your own blocked domains
  checkAge?:            boolean    // enable RDAP domain age check (default false)
}

export interface CheckDomainResult {
  scam:            boolean
  reason:          DomainScamReason | null
  riskLevel:       RiskLevel
  confidence:      number           // 0–100
  domain:          string
  matchedLegit:    string | null
  similarityScore: number
  details: {
    isIDN:             boolean
    hasHomoglyph:      boolean
    subdomainDepth:    number
    registeredDomain:  string
    heuristicScore:    number
    heuristicSignals:  string[]
    domainAge: {
      checked:   boolean
      ageInDays: number | null
      isVeryNew: boolean           // < 7 days
      isNew:     boolean           // < 30 days
      isRecent:  boolean           // < 90 days
      registrar: string | null
    }
  }
  error: CheckError | null
}
