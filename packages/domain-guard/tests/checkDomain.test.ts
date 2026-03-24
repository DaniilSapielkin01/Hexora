import { describe, test, expect } from "vitest"
import { checkDomain } from "../src/checkDomain"
import { detectDomain } from "../src/detector"
import { normalizeDomain, getRegisteredDomain, getSubdomainDepth, hasHomoglyph, isIDN } from "../src/normalizer"
import { domainSimilarity } from "../src/similarity"

// ── Normalizer ────────────────────────────────────────────────────────────────

describe("normalizeDomain", () => {
  test("strips scheme and path from URL", () => {
    expect(normalizeDomain("https://app.uniswap.org/swap?foo=1")).toBe("app.uniswap.org")
  })
  test("lowercases domain", () => {
    expect(normalizeDomain("UNISWAP.ORG")).toBe("uniswap.org")
  })
  test("handles bare domain", () => {
    expect(normalizeDomain("uniswap.org")).toBe("uniswap.org")
  })
  test("strips trailing slash", () => {
    expect(normalizeDomain("https://uniswap.org/")).toBe("uniswap.org")
  })
  test("handles http scheme", () => {
    expect(normalizeDomain("http://opensea.io/collection/test")).toBe("opensea.io")
  })
})

describe("getRegisteredDomain", () => {
  test("returns last two parts", () => {
    expect(getRegisteredDomain("app.uniswap.org")).toBe("uniswap.org")
  })
  test("handles bare domain", () => {
    expect(getRegisteredDomain("uniswap.org")).toBe("uniswap.org")
  })
  test("deep subdomain", () => {
    expect(getRegisteredDomain("a.b.uniswap.evil.com")).toBe("evil.com")
  })
})

describe("getSubdomainDepth", () => {
  test("no subdomain", () => {
    expect(getSubdomainDepth("uniswap.org")).toBe(0)
  })
  test("one subdomain", () => {
    expect(getSubdomainDepth("app.uniswap.org")).toBe(1)
  })
  test("two subdomains", () => {
    expect(getSubdomainDepth("a.app.uniswap.org")).toBe(2)
  })
})

describe("hasHomoglyph", () => {
  test("detects Cyrillic а (looks like Latin a)", () => {
    // The 'а' below is Cyrillic U+0430
    expect(hasHomoglyph("uniswаp.org")).toBe(true)
  })
  test("clean domain returns false", () => {
    expect(hasHomoglyph("uniswap.org")).toBe(false)
  })
})

describe("isIDN", () => {
  test("detects punycode domain", () => {
    expect(isIDN("xn--unisap-n2a.org")).toBe(true)
  })
  test("clean domain is not IDN", () => {
    expect(isIDN("uniswap.org")).toBe(false)
  })
})

// ── Similarity ────────────────────────────────────────────────────────────────

describe("domainSimilarity", () => {
  test("identical = 100", () => {
    expect(domainSimilarity("uniswap.org", "uniswap.org")).toBe(100)
  })
  test("uniswap.org vs uniswaap.org — one char difference → high similarity", () => {
    expect(domainSimilarity("uniswap.org", "uniswaap.org")).toBeGreaterThan(85)
  })
  test("completely different domains → low similarity", () => {
    expect(domainSimilarity("uniswap.org", "google.com")).toBeLessThan(50)
  })
  test("uniswap.org vs uniswap.com — only TLD change", () => {
    expect(domainSimilarity("uniswap.org", "uniswap.com")).toBeGreaterThan(88)
  })
})

// ── Detector ──────────────────────────────────────────────────────────────────

describe("detectDomain — blacklist", () => {
  test("known phishing domain → blacklisted", () => {
    const r = detectDomain("uniswap.com")
    expect(r.detected).toBe(true)
    expect(r.reason).toBe("blacklisted_domain")
    expect(r.confidence).toBeGreaterThanOrEqual(99)
  })

  test("openseas.io → blacklisted", () => {
    const r = detectDomain("openseas.io")
    expect(r.detected).toBe(true)
    expect(r.reason).toBe("blacklisted_domain")
  })
})

describe("detectDomain — legit domains", () => {
  test("uniswap.org → clean", () => {
    const r = detectDomain("uniswap.org")
    expect(r.detected).toBe(false)
    expect(r.reason).toBe(null)
  })

  test("app.uniswap.org → clean", () => {
    const r = detectDomain("app.uniswap.org")
    expect(r.detected).toBe(false)
  })

  test("opensea.io → clean", () => {
    const r = detectDomain("opensea.io")
    expect(r.detected).toBe(false)
  })
})

describe("detectDomain — typosquatting", () => {
  test("uniswaap.org → typosquat of uniswap.org", () => {
    const r = detectDomain("uniswaap.org")
    expect(r.detected).toBe(true)
    expect(r.reason).toBe("typosquat")
    expect(r.matchedLegit).toBe("uniswap.org")
  })

  test("uniswap-app.com → typosquat", () => {
    const r = detectDomain("uniswap-app.com")
    expect(r.detected).toBe(true)
  })

  test("pancakeswap.org → typosquat of pancakeswap.finance", () => {
    const r = detectDomain("pancakeswap.org")
    expect(r.detected).toBe(true)
    expect(r.reason).toBe("typosquat")
  })
})

describe("detectDomain — subdomain hijack", () => {
  test("app.uniswap.evil.com → subdomain hijack", () => {
    const r = detectDomain("app.uniswap.evil.com")
    expect(r.detected).toBe(true)
    expect(r.reason).toBe("subdomain_hijack")
  })

  test("opensea.io.phishing.com → subdomain hijack", () => {
    const r = detectDomain("opensea.io.phishing.com")
    expect(r.detected).toBe(true)
    expect(r.reason).toBe("subdomain_hijack")
  })
})

describe("detectDomain — IDN", () => {
  test("punycode domain resembling uniswap → idn_suspicious", () => {
    const r = detectDomain("xn--unisap-n2a.org")
    expect(r.detected).toBe(true)
    expect(r.reason).toBe("idn_suspicious")
  })
})

// ── checkDomain (full API) ─────────────────────────────────────────────────────

describe("checkDomain", () => {
  test("full URL — phishing domain → scam=true, critical", async () => {
    const r = await checkDomain({ domain: "https://uniswap.com/swap" })
    expect(r.scam).toBe(true)
    expect(r.riskLevel).toBe("critical")
    expect(r.error).toBe(null)
  })

  test("legit domain → scam=false, none", async () => {
    const r = await checkDomain({ domain: "https://app.uniswap.org/swap" })
    expect(r.scam).toBe(false)
    expect(r.riskLevel).toBe("none")
    expect(r.error).toBe(null)
  })

  test("typosquat → scam=true, high or critical", async () => {
    const r = await checkDomain({ domain: "uniswaap.org" })
    expect(r.scam).toBe(true)
    expect(["high", "critical"]).toContain(r.riskLevel)
    expect(r.matchedLegit).toBeTruthy()
  })

  test("subdomain hijack → scam=true", async () => {
    const r = await checkDomain({ domain: "metamask.io.login.xyz" })
    expect(r.scam).toBe(true)
  })

  test("result has correct shape", async () => {
    const r = await checkDomain({ domain: "uniswap.org" })
    expect(r).toHaveProperty("scam")
    expect(r).toHaveProperty("reason")
    expect(r).toHaveProperty("riskLevel")
    expect(r).toHaveProperty("confidence")
    expect(r).toHaveProperty("domain")
    expect(r).toHaveProperty("matchedLegit")
    expect(r).toHaveProperty("similarityScore")
    expect(r).toHaveProperty("details")
    expect(r).toHaveProperty("error")
    expect(r.details).toHaveProperty("isIDN")
    expect(r.details).toHaveProperty("hasHomoglyph")
    expect(r.details).toHaveProperty("subdomainDepth")
    expect(r.details).toHaveProperty("registeredDomain")
  })
})

// ── Heuristics — NFT spam / suspicious domains ────────────────────────────────

describe("detectDomain — NFT spam (SHIBAR.la pattern)", () => {
  test("SHIBAR.la → nft_spam_domain", () => {
    const r = detectDomain("shibar.la")
    expect(r.detected).toBe(true)
    expect(["nft_spam_domain", "suspicious_domain"]).toContain(r.reason)
  })

  test("SHIBOS.vip → nft_spam_domain", () => {
    const r = detectDomain("shibos.vip")
    expect(r.detected).toBe(true)
  })

  test("NFTWOOD.top → nft_spam_domain", () => {
    const r = detectDomain("nftwood.top")
    expect(r.detected).toBe(true)
    expect(["nft_spam_domain", "suspicious_domain"]).toContain(r.reason)
  })

  test("USDART.top → suspicious", () => {
    const r = detectDomain("usdart.top")
    expect(r.detected).toBe(true)
  })
})

describe("detectDomain — suspicious keywords", () => {
  test("claim-airdrop-eth.xyz → high risk", async () => {
    const r = await checkDomain({ domain: "claim-airdrop-eth.xyz" })
    expect(r.scam).toBe(true)
    expect(["high", "critical"]).toContain(r.riskLevel)
  })

  test("free-nft-voucher.top → high risk", async () => {
    const r = await checkDomain({ domain: "free-nft-voucher.top" })
    expect(r.scam).toBe(true)
  })

  test("secure-wallet-verify.com → suspicious", async () => {
    const r = await checkDomain({ domain: "secure-wallet-verify.com" })
    expect(r.scam).toBe(true)
  })
})

describe("detectDomain — suspicious TLD combos", () => {
  test("metamask.tk → high risk", async () => {
    const r = await checkDomain({ domain: "metamask.tk" })
    expect(r.scam).toBe(true)
  })

  test("uniswap.xyz → flagged", async () => {
    const r = await checkDomain({ domain: "uniswap.xyz" })
    expect(r.scam).toBe(true)
  })
})

describe("detectDomain — custom lists", () => {
  test("custom blacklist domain → blacklisted", async () => {
    const r = await checkDomain({
      domain: "myscamdomain.io",
      customBlacklist: ["myscamdomain.io"],
    })
    expect(r.scam).toBe(true)
    expect(r.reason).toBe("blacklisted_domain")
  })

  test("custom whitelist domain → clean", async () => {
    const r = await checkDomain({
      domain: "mynewprotocol.io",
      customWhitelist: ["mynewprotocol.io"],
    })
    expect(r.scam).toBe(false)
    expect(r.riskLevel).toBe("none")
  })
})

describe("heuristic details in result", () => {
  test("result contains heuristicScore and heuristicSignals", async () => {
    const r = await checkDomain({ domain: "nftwood.top" })
    expect(r.details).toHaveProperty("heuristicScore")
    expect(r.details).toHaveProperty("heuristicSignals")
    expect(r.details.heuristicScore).toBeGreaterThan(0)
    expect(r.details.heuristicSignals.length).toBeGreaterThan(0)
  })
})
