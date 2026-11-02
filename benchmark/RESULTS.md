# ScamHunter error-rate benchmark: summary

ScamHunter publishes how often its methods are wrong, measured on public ground truth that the tool does not
itself use. Every number has a 95% confidence interval, and anyone can rebuild the same cases from the
sources listed in each round's report.

| What was measured | Round 1, before fixes (Nov 1, 2026) | Round 2, held-out, after fixes (Nov 2, 2026) |
|---|---|---|
| Named the WRONG exchange, when it named one | 0% (0/15) | 0% (0/7; CI 0–35%) |
| Named an exchange for a scam or sanctioned wallet | 0% (0/80) | 0% (0/80; CI 0–5%) |
| Named the right exchange (recall) | 15% (13/87) | 8% (6/74; CI 4–17%) |
| Behaviour signals alone flagged known-bad wallets | 48% (38/80)* | 34% (23/67; CI 24–46%) |
| Behaviour signals alone wrongly flagged exchange wallets | 46% (40/87)* | **16% (10/61; CI 9–28%)** |

\* Round 1 also counted never-used addresses; round 2 judges behaviour only on wallets with on-chain activity
(13 never-used addresses in each group were reported separately). The rule was fixed before round 2 was drawn.

**What round 1 taught us.** Three behaviour signals (collects from many wallets, pays out to many, creates
new wallets) fired more often on exchanges than on scammers, so they were downgraded to background context.
Destination-tag and wrong-network reminders were moved to a "check before sending" list, because they are
sending mistakes, not signs of a scam. Round 2 tested those changes on a fresh sample, never seen while tuning:
false alarms on exchange wallets fell by about two thirds.

**How to read it.** Exchange naming is cautious: when unsure, ScamHunter says "unidentified" rather than
guess, and it has not yet named a wrong exchange. Behaviour signals are a backup for brand-new wallets that
no list knows yet; known scam and sanctioned wallets are caught first by the published lists in normal use.

- Round 1 report: [RESULTS_round1_before_fixes.md](RESULTS_round1_before_fixes.md)
- Round 2 report: [RESULTS_round2.md](RESULTS_round2.md)
- Method and limits: [benchmark/__init__.py](__init__.py)
- Re-run it: `python -m benchmark.truth`, `python -m benchmark.run`, `python -m benchmark.report` (set `BENCH_ROUND` for a new held-out round)
