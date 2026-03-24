// Curated whitelist of legitimate Web3 domains
// ~120 domains across 10 categories
// See scripts/update-blacklist.ts to regenerate the phishing list

export const KNOWN_LEGIT_DOMAINS: readonly string[] = [

  // ── DEX / AMM ──────────────────────────────────────────────────────────────
  "1inch.io", "app.1inch.io",
  "app.uniswap.org", "uniswap.org",
  "balancer.fi", "curve.fi",
  "dydx.exchange", "gmx.io", "app.gmx.io",
  "hyperliquid.xyz", "odos.xyz",
  "pancakeswap.finance", "raydium.io",
  "sushi.com", "app.sushi.com",
  "velodrome.finance", "aerodrome.finance",
  "kyberswap.com", "paraswap.io",
  "drift.trade", "vertex.xyz",

  // ── Lending / Borrowing ───────────────────────────────────────────────────
  "aave.com", "app.aave.com",
  "compound.finance", "app.compound.finance",
  "euler.finance", "morpho.org", "app.morpho.org",
  "radiant.capital", "spark.fi", "app.spark.fi",
  "venus.io", "app.venus.io", "benqi.fi",

  // ── Bridges ───────────────────────────────────────────────────────────────
  "bridge.arbitrum.io", "app.optimism.io",
  "portal.zksync.io", "bridge.base.org",
  "hop.exchange", "app.hop.exchange",
  "stargate.finance", "app.stargate.finance",
  "across.to", "relay.link",
  "bungee.exchange", "li.fi",

  // ── Wallets / Portfolio ───────────────────────────────────────────────────
  "argent.xyz", "debank.com", "exodus.com",
  "frame.sh", "metamask.io", "myetherwallet.com",
  "phantom.app", "rainbow.me", "rabby.io",
  "safe.global", "app.safe.global",
  "trustwallet.com", "wallet.coinbase.com",
  "zapper.fi", "zerion.io", "cobowallet.com",

  // ── NFT ───────────────────────────────────────────────────────────────────
  "blur.io", "foundation.app", "magiceden.io",
  "opensea.io", "rarible.com", "superrare.com",
  "x2y2.io", "element.market", "niftygateway.com",

  // ── Staking / Yield ───────────────────────────────────────────────────────
  "lido.fi", "stake.lido.fi",
  "rocketpool.net", "app.rocketpool.net",
  "convexfinance.com", "app.convexfinance.com",
  "yearn.fi", "beefy.com", "app.beefy.com",
  "pendle.finance", "app.pendle.finance",
  "eigenlayer.xyz", "app.eigenlayer.xyz",

  // ── Launchpads ────────────────────────────────────────────────────────────
  "coinlist.co", "polkastarter.com",

  // ── Chains / Explorers ────────────────────────────────────────────────────
  "arbiscan.io", "basescan.org", "bscscan.com",
  "etherscan.io", "optimistic.etherscan.io",
  "polygonscan.com", "snowtrace.io", "solscan.io",
  "explorer.zksync.io",
  "arbitrum.io", "avalanche.network", "base.org",
  "bnbchain.org", "ethereum.org", "optimism.io",
  "polygon.technology", "solana.com",
  "starkware.co", "zksync.io",

  // ── Data / Analytics ─────────────────────────────────────────────────────
  "coingecko.com", "coinmarketcap.com",
  "defillama.com", "dune.com",
  "nansen.ai", "arkham.network",
  "the-graph.network",

  // ── Developer Infrastructure ──────────────────────────────────────────────
  "alchemy.com", "chainlink.link", "infura.io",
  "moralis.io", "quicknode.com",
  "thirdweb.com", "openzeppelin.com",
]

// Curated blacklist — confirmed phishing domains
// To expand with 500 domains from MetaMask, run:
//   npx tsx scripts/update-blacklist.ts
export const KNOWN_PHISHING_DOMAINS: readonly string[] = [
  // Uniswap fakes
  "app-uniswap.org", "app-uniswap.io",
  "uniswap.com", "uniswap-app.com",
  "uniswap-exchange.com", "uniswaap.org", "uniswapdex.io",
  // OpenSea fakes
  "openseas.io", "open-sea.io", "opensea.com",
  // MetaMask fakes
  "metamask-login.com", "metamask-wallet.com",
  "metmask.io", "meta-mask.io",
  // Etherscan fakes
  "etherscan-login.com", "etherscan.com",
  // MEW fakes
  "myetherwallet.com.co", "myetherwllet.com",
  // PancakeSwap fakes
  "pancakeswap.org", "pancakeswap.com",
  // Aave fakes
  "defi-aave.com", "aave-app.com",
  // Trust Wallet fakes
  "trustwalet.com", "trust-wallet.com",
  // Lido fakes
  "lido-stake.com", "staking-lido.com",
  // From MetaMask eth-phishing-detect (sample)
  "login-metamask.com", "uniswap-claim.com",
  "dexuniswap.org", "freeuniswap.com",
  "eventuniswap.com", "metamsk.io",
  "1inch-exchange.com", "metamask-online-io.com",
  "coingecko.pro", "maskmetaa.io",
  "metamaskweb.com", "metamaskwallet.net",
  "installmetamask.org",
  // Generic
  "wallet-connect-secure.com",
  "defi-rewards-claim.com",
  "nft-airdrop-claim.io",
]
