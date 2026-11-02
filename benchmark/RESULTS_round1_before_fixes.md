# ScamHunter error-rate benchmark

Run 2026-11-02. Every number below comes from running the released tool on public ground truth it does not itself use. Intervals are 95% Wilson score intervals; small samples give wide ones.

## 1. Exchange identification (`exchange-label/1`)

- Named the right exchange: **15% (13/87; 95% CI 9% to 24%)** of exchange-published wallets.
- When it named someone, it was right: **87% (13/15; 95% CI 62% to 96%)**.
- Named the WRONG exchange: **0% (0/15; 95% CI 0% to 20%)** of the times it named one.
- Unlabelled (no name given; the tool says "unidentified"): 72 of 87.
- On known scam / sanctioned wallets, named an exchange: 0% (0/80; 95% CI 0% to 5%).

## 2. Pre-screen behaviour signals alone (`behavior-signal/1`), every list lookup switched off

- Flagged known scam / sanctioned wallets: **48% (38/80; 95% CI 37% to 58%)** (10 of them had no readable history at all).
- Wrongly flagged exchange wallets: **46% (40/87; 95% CI 36% to 56%)**.
- As users actually run it (lists and identity on), exchange wallets flagged: 48% (42/87; 95% CI 38% to 59%).

## By chain

| Chain | Identification recall | Behaviour recall on bad | Behaviour false flags |
|---|---|---|---|
| bitcoin | 0% (0/9; 95% CI 0% to 30%) | 25% (5/20; 95% CI 11% to 47%) | 78% (7/9; 95% CI 45% to 94%) |
| ethereum | 16% (5/32; 95% CI 7% to 32%) | 52% (21/40; 95% CI 38% to 67%) | 38% (12/32; 95% CI 23% to 55%) |
| tron | 0% (0/22; 95% CI 0% to 15%) | 60% (12/20; 95% CI 39% to 78%) | 32% (7/22; 95% CI 16% to 53%) |
| xrpl | 33% (8/24; 95% CI 18% to 53%) | not measured | 58% (14/24; 95% CI 39% to 76%) |

Tests that errored or timed out (excluded, never counted as passes): 0.

## Limits

- Exchange reserve wallets are busy institutional wallets, not typical personal wallets.
- Sanctioned and listed scam wallets are often old or emptied; signals that need recent activity can't fire on them.
- Behaviour signals are risk indicators, not proof. The pre-screen says so on every result.
- Samples are drawn by hash, so anyone can rebuild the same case set from the sources below.

## Ground-truth sources

- okx proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/okex/index.js (SHA-256 `c08799550fc6ab14…`, retrieved 2026-11-01T22:48:12Z)
- htx proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/huobi/index.js (SHA-256 `512ee6c67f926744…`, retrieved 2026-11-01T22:48:12Z)
- gate proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/gate-io/index.js (SHA-256 `ca6d5afab98672cc…`, retrieved 2026-11-01T22:48:12Z)
- bitget proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/bitget/index.js (SHA-256 `55402dd8299d8112…`, retrieved 2026-11-01T22:48:12Z)
- bitstamp proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/bitstamp/index.js (SHA-256 `b39b3b3bd0b1c403…`, retrieved 2026-11-01T22:48:12Z)
- kucoin proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/kucoin/index.js (SHA-256 `840ad01ba1696a6a…`, retrieved 2026-11-01T22:48:12Z)
- bitfinex proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/bitfinex/index.js (SHA-256 `68bc0edf9e94f5a2…`, retrieved 2026-11-01T22:48:12Z)
- binance proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/binance/index.js (SHA-256 `7ff3afcb677c9d7b…`, retrieved 2026-11-01T22:48:12Z)
- OFAC sanctions list (US Treasury): https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.txt (SHA-256 `5545c44c2e0b8611…`, retrieved 2026-11-01T22:48:12Z)
- OFAC sanctions list (US Treasury): https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_XBT.txt (SHA-256 `a72d4f30fb2c3029…`, retrieved 2026-11-01T22:48:12Z)
- OFAC sanctions list (US Treasury): https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_TRX.txt (SHA-256 `c5005805ada68a84…`, retrieved 2026-11-01T22:48:12Z)
- ScamSniffer scam database (GPL-3.0 data): https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json (SHA-256 `5f5e5fcb1c20015d…`, retrieved 2026-11-01T22:48:12Z)
