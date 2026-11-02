# ScamHunter error-rate benchmark (round 2)

Run 2026-11-02. Every number below comes from running the released tool on public ground truth it does not itself use. Intervals are 95% Wilson score intervals; small samples give wide ones.

## 1. Exchange identification (`exchange-label/1`)

- Named the right exchange: **8% (6/74; 95% CI 4% to 17%)** of exchange-published wallets.
- When it named someone, it was right: **86% (6/7; 95% CI 49% to 97%)**.
- Named the WRONG exchange: **0% (0/7; 95% CI 0% to 35%)** of the times it named one.
- Unlabelled (no name given; the tool says "unidentified"): 67 of 74.
- On known scam / sanctioned wallets, named an exchange: 0% (0/80; 95% CI 0% to 5%).

## 2. Pre-screen behaviour signals alone (`behavior-signal/1`), every list lookup switched off

- Flagged known scam / sanctioned wallets with on-chain activity: **34% (23/67; 95% CI 24% to 46%)**.
- Never-used addresses, not judged (no behaviour exists): 13 known-bad, 13 exchange-published.
- Wrongly flagged exchange wallets: **16% (10/61; 95% CI 9% to 28%)**.
- As users actually run it (lists and identity on), exchange wallets flagged: 16% (10/61; 95% CI 9% to 28%).

## By chain

| Chain | Identification recall | Behaviour recall on bad | Behaviour false flags |
|---|---|---|---|
| bitcoin | 0% (0/8; 95% CI 0% to 32%) | 22% (4/18; 95% CI 9% to 45%) | 25% (1/4; 95% CI 5% to 70%) |
| ethereum | 11% (3/28; 95% CI 4% to 27%) | 34% (10/29; 95% CI 20% to 53%) | 5% (1/22; 95% CI 1% to 22%) |
| tron | 0% (0/20; 95% CI 0% to 16%) | 45% (9/20; 95% CI 26% to 66%) | 28% (5/18; 95% CI 12% to 51%) |
| xrpl | 17% (3/18; 95% CI 6% to 39%) | not measured | 18% (3/17; 95% CI 6% to 41%) |

Tests that errored or timed out (excluded, never counted as passes): 0.

## Limits

- Exchange reserve wallets are busy institutional wallets, not typical personal wallets.
- Sanctioned and listed scam wallets are often old or emptied; signals that need recent activity can't fire on them.
- Behaviour signals are risk indicators, not proof. The pre-screen says so on every result.
- Samples are drawn by hash, so anyone can rebuild the same case set from the sources below.

## Ground-truth sources

- okx proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/okex/index.js (SHA-256 `c08799550fc6ab14…`, retrieved 2026-11-02T13:32:13Z)
- htx proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/huobi/index.js (SHA-256 `512ee6c67f926744…`, retrieved 2026-11-02T13:32:13Z)
- gate proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/gate-io/index.js (SHA-256 `ca6d5afab98672cc…`, retrieved 2026-11-02T13:32:13Z)
- bitget proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/bitget/index.js (SHA-256 `55402dd8299d8112…`, retrieved 2026-11-02T13:32:13Z)
- bitstamp proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/bitstamp/index.js (SHA-256 `b39b3b3bd0b1c403…`, retrieved 2026-11-02T13:32:13Z)
- kucoin proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/kucoin/index.js (SHA-256 `840ad01ba1696a6a…`, retrieved 2026-11-02T13:32:13Z)
- bitfinex proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/bitfinex/index.js (SHA-256 `68bc0edf9e94f5a2…`, retrieved 2026-11-02T13:32:13Z)
- binance proof-of-reserves wallets published by the exchange (via DefiLlama): https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/binance/index.js (SHA-256 `7ff3afcb677c9d7b…`, retrieved 2026-11-02T13:32:13Z)
- OFAC sanctions list (US Treasury): https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.txt (SHA-256 `5545c44c2e0b8611…`, retrieved 2026-11-02T13:32:13Z)
- OFAC sanctions list (US Treasury): https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_XBT.txt (SHA-256 `a72d4f30fb2c3029…`, retrieved 2026-11-02T13:32:13Z)
- OFAC sanctions list (US Treasury): https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_TRX.txt (SHA-256 `c5005805ada68a84…`, retrieved 2026-11-02T13:32:13Z)
- ScamSniffer scam database (GPL-3.0 data): https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json (SHA-256 `5f5e5fcb1c20015d…`, retrieved 2026-11-02T13:32:13Z)
