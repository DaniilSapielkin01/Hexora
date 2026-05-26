# Hexora v2.0.0 — Session notes and continuation prompt

> Hand-off doc for the next AI session. Captures everything that changed
> between `v1.0.4` and `v2.0.0`, plus open work and conventions to follow.

---

## Project context

`hexora-npm` is a pnpm monorepo publishing 5 npm packages — a Web3 security
SDK for wallets and dApps. Audience: **developers** (not end-users), so the
API style favours honest results, structured types, opt-in observability,
and not hiding complexity behind magic.

| Package | Role |
|---|---|
| `@hexora/core` | Shared types, validator, similarity, history fetcher, **logger**, **constants**, cache |
| `@hexora/address-guard` | Address poisoning, dust attacks, zero-value transfers |
| `@hexora/domain-guard` | Phishing domains, typosquat, IDN, subdomain hijack, NFT spam |
| `@hexora/tx-guard` | Malicious calldata, EIP-712 typed data, ERC-4337 (uses **viem**) |
| `hexora` | Umbrella — re-exports the three guards + setLogger |

Build: `pnpm -r build`. Tests: `pnpm -r test` (vitest, 90 total).
Size limit: `pnpm size-limit`. Release: `pnpm release` (changesets-driven).

---

## All v2.0.0 changes

### `@hexora/core`

**New**
- `logger.ts` — opt-in observability. `setLogger(logger | null)` + internal
  `logEvent(level, source, message, context?)`. Default is no-op. Currently
  emitted from `historyFetcher` and `abiDecoder` catch sites.
- `constants.ts` — shared HTTP timings: `HTTP_TIMEOUT_MS`,
  `HISTORY_FETCH_TIMEOUT_MS`, `HTTP_RETRIES`, `HTTP_RETRY_DELAY_MS`.

**Fixed**
- `cache.ts` — added **bounded LRU** (max 1000 entries, 5 min TTL).
  Touch-on-access via insertion-order Map. Was unbounded.
- `history/fetcher.ts` — null-safe `tx.to`/`tx.from` in
  `normalizeEVMTokenTx` (was crashing on malformed Etherscan responses).
  Wired `logEvent` into rate-limit / network / explorer-API error paths.
- `similarity.ts` — `prefixSimilarity`/`suffixSimilarity` now divide by
  `min(pa.length, pb.length)` instead of hardcoded `len`. Was inflating
  scores on strings shorter than 6 chars.
- `validator.ts` — default case for unknown chains returns `false` (was
  permissive `address.length > 0`).

### `@hexora/domain-guard`

**Fixed**
- `similarity.ts` — `domainSimilarity` now uses **SLD-weighted** scoring
  (0.9 SLD + 0.1 TLD). Catches `uniswap.com` vs `uniswap.org` (~90% now,
  was ~73% with flat Levenshtein). Added `MAX_LEN = 256` guard against
  pathological inputs. `findMostSimilarLegit` breaks ties by shorter
  domain (prefers `uniswap.org` over `app.uniswap.org`).
- `detector.ts` — SLD-label subdomain hijack detection (`app.uniswap.evil.com`).
  Browser-safe punycode stripping (`stripPunycode`, **no `node:url` import** —
  that broke browser bundling). Typosquat confidence: 95→95, 90→90, 85→80,
  else 70 (was 95/85/70, missed close squats at high risk).
- `heuristics.ts` — unreachable second branch in `heuristicReason` removed;
  introduced new reason `"suspicious_tld_combo"` for `tldSuspicious &&
  hasMediumRiskKeyword` case.
- `normalizer.ts` — `hasLeetSubstitution` now extracts SLD via
  `parts[parts.length - 2]` (was leftmost label — missed `app.un1swap.org`).
- `knownDomains.ts` — removed `uniswaap.org`, `pancakeswap.org` from
  blacklist (better detected as typosquat with `matchedLegit` context).
- `domainAge.ts` — step-function `bonus` replaced with continuous
  interpolation. Stable to small changes in adjacent scoring.
- `types.ts` — added `"suspicious_tld_combo"` to `DomainScamReason` union.
- `scorer.ts` — handles the new reason in `getRiskLevel` switch.

### `@hexora/tx-guard`

**New dependency**
- `viem ^2.51.0` — added because hand-rolled ABI decoding had real bugs.
  Tree-shaken to ~6 kB inside the package. tx-guard bundle: 8.3 → 14.6 kB.

**Fixed**
- `abiDecoder.ts` — `methodIdFromSig` was hardcoded to return `""` (ABI
  matching completely broken). Now uses **viem's `keccak256(toBytes(sig))`**
  by default; custom keccak still injectable via optional param.
  `decodeParams` uses **viem's `decodeAbiParameters`** (was manual slot
  slicing with broken bool detection). LRU-bounded ABI cache (max 500).
- `calldataParser.ts` — `extractBool` rewritten via `BigInt`. Was
  `slice.endsWith("1")` which accepted any uint ending in 1 (e.g. `uint=5`)
  as `true`. Now exported for reuse.
- `delegationDetector.ts` — uses shared `extractBool` instead of duplicating
  the brittle string-suffix check.
- `compositeScoring.ts` — renamed from `compositeSorcer.ts` (typo fix).
  Imports in `detector.ts` and tests updated. ETH-value amplifier added:
  when `ethValue > 0n` AND another signal fired, +30 weight (catches
  "send ETH to freshly-upgraded proxy" drainer setup). Proxy upgrade
  weight bumped 25→35 for `<7d`.
- `tokenNameAnalyzer.ts` — input length cap (`safeName.slice(0,512)`,
  `safeSymbol.slice(0,64)` — token metadata is untrusted contract data).
  Multi-word accumulation instead of `break` after first match (caught
  "FREE AIRDROP CLAIM" with 3 signals, was missing at 20 < 35).
- `typedDataAnalyzer.ts` — strict `typeof recipient !== "string"` check
  for Seaport consideration (was `String(null) → "null"` treated as valid
  recipient → false positive).
- `simulation.ts` — gas cost uses **real `eth_gasPrice`** from provider
  (was hardcoded 20 gwei → 10–100× wrong on L2s and L1 spikes).
  Falls back to 20 gwei via `safeGasPrice` if RPC call fails.
- `erc4337.ts` — `extractUserOp` was returning **garbage** from
  fixed-offset slicing. Replaced with `extractUserOps` using viem's
  `decodeFunctionData` and proper ABIs for **both v0.6** (`0x1fad948c`,
  11 fields) **and v0.7** (`0x765e827f`, packed format with
  `accountGasLimits`/`gasFees` bytes32). Helper `splitBytes32` unpacks
  v0.7 into v0.6-shape `UserOperation`. New export
  `isHandleOpsCalldata(callData)` for quick selector check.
- `proxyChecker.ts` — added **policy comment** explaining why
  `getContractDeployAge` returns synthetic `30` for older contracts.
  Scoring policy only cares about `<7d / <30d / older` buckets, so a
  full binary search to genesis would add ~25 RPC calls for zero
  scoring change. Comment exists to defend against future "optimisations".

**Removed**
- `compositeSorcer.ts` (renamed)
- Dead duplicate `compositeScoring.ts` (the *old* one — was unused,
  different API)

### `@hexora/address-guard`

**Fixed**
- `checkAddress.ts` — `Promise.all` → `Promise.allSettled` so a failed
  fetch on one address doesn't lose the other. Both fetches now wired
  through `txCache` (input address was uncached). Logger calls on fetch
  failure. `extractKnownAddresses` filters out contract addresses
  (heuristic: tx with `methodId` set → `to` is a contract) — comparing
  input against a DEX router gave bogus poisoning hits.
- `detector.ts` — **ERC-20 dust detection** added. Was only counting
  native `value > 0`; real attackers almost always use cheap token
  transfers (`tokenValue`). Both `analyzeInputAddress` and
  `analyzeUserHistory` updated. Removed dead `evidence: string[]` from
  `analyzeUserHistory` (caller discarded it).
- `scorer.ts` — `+7` per extra signal (was `+3`). Scam flag also fires
  for `signals.length >= 2 && riskScore >= 50` (forward-compat path).
  **Trust upstream similarity match** via `matchedAddress !== null`
  check, not hardcoded `>= 85` — was silently dropping lowered-threshold
  matches.

**Tests added**
- ERC-20 dust attack (positive + negative)
- Multi-signal confidence boost
- Lowered-threshold similarity match
- (Total: 12 → 16)

### `hexora` (umbrella)

- Re-exports `setLogger`, `Logger`, `LogEvent`, `LogLevel` from `@hexora/core`.

### Docs

- Updated `README.md` in all 5 packages + root README for v2.0.0 features
  (new logger section, viem note, ERC-20 dust mention, v0.6/v0.7 EntryPoint).

---

## What's **not** done (worth tackling next session)

### Architectural (major bump if done)
- **Factory pattern** to replace module-global singletons (`txCache`,
  `abiCache`, active logger). Currently a Next.js SSR scenario shares
  the same cache across requests, and a multi-tenant SDK can't isolate
  loggers. Senior fix would be `createHexora({ logger?, txCache?,
  abiCache?, historyProvider? })`. Out of scope for v2 — keep for v3.

### Quality-of-life
- `SimulationResult` should expose `gasPriceSource: "provider" | "fallback"`
  so callers can detect when `safeGasPrice` quietly substituted the
  20-gwei fallback. Currently the `ethDelta` quietly lies in that case.
- viem as **peerDependency** instead of dependency. Most consumers
  already have viem in their dApp — would dedupe and let them control
  the version. Currently it's a regular dep in `tx-guard`.
- Unit tests for `@hexora/core` — currently no test framework set up
  there. Logger smoke-test exists only as ad-hoc node script.

### Known limitations (documented in code, not bugs)
- `proxyChecker.getContractDeployAge` returns synthetic `30` for
  contracts older than 30 days. **Policy decision** — don't "fix" this.
- `erc4337.analyzeUserOperation` only reads `initCode`, `callData`,
  `paymasterAndData` — ignores gas-related fields. Adequate for
  current detection; expand only if a new detector needs them.

---

## Conventions established in this session

1. **Honest uncertainty > fake precision.** When a parser can't actually
   parse something (e.g. `extractUserOp` with hand-rolled offsets, or
   `extractBool` with garbage uint), return `null` / empty rather than
   confident wrong values. Downstream UI must be able to distinguish
   "we don't know" from "we checked and it's fine."
2. **Module-global state is suspect.** Logger is acceptable as global,
   caches are bounded but still concerning. Don't add more globals
   without first considering a factory pattern.
3. **External data is untrusted.** Token metadata, Etherscan responses,
   user-supplied addresses — all clamped/null-safed at the boundary
   before regex / BigInt / address ops.
4. **Detector thresholds are policy, not config.** They live in the
   detector file with a comment explaining the choice. Don't move them
   to a global constants file unless multiple detectors actually share.
   `core/constants.ts` is for cross-cutting *infrastructure* values
   (HTTP timeouts, retry counts), not domain logic.
5. **Use shared logger at every swallow point.** If a `catch` returns
   `null`/empty/safe-default, log it via `logEvent` so users opting
   into observability can see what happened.
6. **Browser safety matters.** Avoid `node:*` imports in any published
   package — these are dApp SDKs that bundle into browsers. `viem` is
   isomorphic and OK; `node:url` is not.
7. **For developers, not end-users.** API leans toward explicit
   parameters, structured types, and dependency injection (e.g. custom
   `keccak256` override, custom `HistoryProvider`).

---

## Continuation prompt for next session

> I'm working on the hexora-npm monorepo
> (`/Users/danil/Documents/hexora/hexora-npm`) — a Web3 security SDK
> (5 packages: `@hexora/core`, `@hexora/address-guard`,
> `@hexora/domain-guard`, `@hexora/tx-guard`, `hexora`). Current
> published version: `v2.0.0`.
>
> Read `packages/SESSION_NOTES_v2.md` for full context on what changed
> in v2.0.0 and what conventions we've established. Pay attention to
> the "What's not done" and "Conventions" sections — those are the
> rails I want you to operate within.
>
> Today I want to: **[describe today's task]**.
>
> Senior expectations: honest uncertainty over fake precision, browser
> safety (no `node:*` in published packages), bounded caches and
> opt-in logger at swallow points, detector thresholds stay local to
> their detector. Tests at `pnpm -r test` must stay green
> (currently 90/90). Build at `pnpm -r build` and size-limit at
> `pnpm size-limit` must pass.

---

_Generated end of session that shipped v2.0.0._
