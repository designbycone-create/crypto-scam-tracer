"""Error-rate benchmark: measure how often ScamHunter's methods are right, on public ground truth
that ScamHunter does NOT itself use, and publish the numbers with 95% intervals.

    python -m benchmark.truth      build the ground-truth set (records each source's URL, SHA-256, date)
    python -m benchmark.run        run the real tool on every case (resumable; network)
    python -m benchmark.report     compute rates + intervals, write benchmark/RESULTS.md

What is measured, and why these sources
  1. Exchange identification (method: exchange-label/1).
     Truth: wallet addresses the exchanges published themselves as proof-of-reserves, as collected in
     DefiLlama's open-source CEX adapters. ScamHunter's labels come from other sources (Etherscan
     label sets, XRPScan, Bithomp, exchanges' xrp-ledger.toml), so the test is not circular.
     Errors that matter most: naming the WRONG exchange (a freeze request sent to the wrong company).
  2. Behaviour signals of the pre-screen (method: behavior-signal/1), with every list lookup and
     identity lookup switched OFF, so only the wallet's own on-chain behaviour can raise a flag.
     Known-bad truth: OFAC-sanctioned addresses and ScamSniffer's published scam/drainer addresses.
     Known-legitimate truth: the exchange reserve addresses above.
     (ScamHunter does load OFAC and ScamSniffer lists in normal use; that is exactly why those
     lookups are disabled here: a test that looks up the answer key measures nothing.)

Limits stated in every report: exchange reserve wallets are not typical personal wallets; sanctioned
and listed scam wallets are often old and drained; samples are drawn deterministically (by hash) so
anyone can re-run the same cases.
"""
