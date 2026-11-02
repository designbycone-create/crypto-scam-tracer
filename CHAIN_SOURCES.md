# Free data sources, per chain

What ScamHunter reads from for each blockchain, all free. "Verified" means it was called successfully from
a normal home connection on Nov 2, 2026. Optional keys go in `config.json` (or the setup page) and are
never required.

| Chain | In use now (no key) | Optional free key / endpoint | History reach | Status |
|---|---|---|---|---|
| XRP Ledger | Ripple `s2.ripple.com`, `xrplcluster.com` (full-history servers) | none needed | Full | In use |
| Bitcoin | mempool.space (Esplora API) | Blockstream Esplora as backup | Full | In use |
| Litecoin | litecoinspace.org (Esplora API, same as mempool.space) | Blockchair | Full | **In use (new)** |
| Ethereum, Base, Optimism, Arbitrum, Polygon | Blockscout public instances, Etherscan free tier (ETH/Polygon/Arbitrum) | `blockscout_key` (100K credits/day), `etherscan_key`, `ankr_key`, `ethereum_rpc` (NodeReal) | Full | In use |
| BNB Chain | public RPC (balances only) | `ankr_key` (full history), `bsc_rpc` (NodeReal) | Full with Ankr | In use |
| opBNB | public RPC | `opbnb_rpc` (NodeReal) | Recent window | In use |
| Avalanche | Routescan (no key: 2 req/s, 10K/day) | `routescan_key`, `ankr_key` | Full | In use |
| Tron | TronGrid | TronGrid key | Full | In use |
| Solana | public RPC (last 30 tx) | `solana_rpc` (Helius free: 1M credits/month) | 200 tx per check with Helius | In use |
| Aptos | Aptos Labs fullnode (pruned) | `aptos_rpc` (NodeReal), `aptos_indexer_key` (Geomi) | Full with Geomi | In use |
| Dogecoin | BlockCypher (no key: 3 req/s, 200/hour); Blockchair | BlockCypher token (500/hour) | Full | Verified, adapter next |
| Bitcoin Cash | Blockchair | Blockchair key | Full | Verified, adapter next |
| TON | toncenter v3 (no key: 1 req/s) | toncenter free key (10 req/s) | Full | Verified, adapter next |
| Stellar | SDF Horizon (public) | third-party Horizon | **1 year only** on SDF's free servers | Verified, adapter next |
| Cardano | Koios public (5,000 req/day, no key) | Koios free key (50,000/day) | Full | Verified, adapter next |
| Sui | Sui GraphQL `graphql.mainnet.sui.io` (old JSON-RPC on public nodes is retired) | provider RPCs | Full | Verified, adapter next |
| NEAR | NearBlocks API | NearBlocks key | Full | Verified, adapter next |
| Hyperliquid | public `api.hyperliquid.xyz/info` | none | Account activity | Verified, adapter next |

Priority for the next adapters is by scam volume: TON (Telegram-based scams), Dogecoin, Stellar, Cardano,
Sui, NEAR, Hyperliquid, Bitcoin Cash.

Sources: [TON Center rate limits](https://docs.ton.org/ecosystem/api/toncenter/rate-limit) ·
[Koios tiers](https://koios.rest/tiers.html) ·
[SDF Horizon one-year history](https://stellar.org/blog/foundation-news/sdf-s-horizon-limiting-data-to-1-year) ·
[BlockCypher and Esplora limits (Spark comparison)](https://www.spark.money/tools/bitcoin-block-explorer-api-comparison) ·
[Blockscout free key](https://docs.blockscout.com/devs/pro-api-info) ·
[Routescan plans](https://routescan.io/docs/plans-and-limits/api-keys-and-pricing) ·
[Helius plans](https://helius.dev/docs/billing/plans) ·
[Aptos indexer access](https://aptos.dev/build/indexer/indexer-api)
