# Roadmap

## Editions

**Victim edition — free forever (this repository, MIT).** Everything a victim
needs for their own case: live watchers, network evidence map, Submission
Center with freeze kits and Officer Packet, incident mode, radar, claim checker,
chain-of-custody hashing.

**Institutional edition — paid (planned; developed privately by FPH LLC, proprietary license).** For police departments, fraud
attorneys, credit unions, banks and private investigators who handle many cases:
- multi-case workspaces and an intake queue for victim referrals
- agency letterhead and officer details pre-filled on every packet
- exportable chain-of-custody reports; signed (not just hashed) evidence bundles
- bulk exports for subpoenas; cross-case network linking ("this cash-out
  account appears in 14 of your cases")
- hosted deployment option, user accounts, audit trail

The free edition stays complete for a single victim. Paid features are about
volume and institutional workflow, never about gating a victim's ability to
act on their own case.

## Engine
- [x] Time-forward freeze tracing + full-network evidence mapping (XRPL)
- [x] Multi-chain tracer (BTC, Tron, EVM) with issuer-freeze detection
- [x] Reliable alerts: ntfy + Telegram + email, outbox with retry
- [x] Submission Center: verified channel directory, freeze kits, Officer Packet, tracking
- [x] XRPL issuer-freeze / clawback detection (RLUSD and any issued token)
- [x] Incident mode, risk signals, exchange status, scam radar, claim checker
- [x] SHA-256 custody log + per-kit manifests
- [ ] PDF export of the Officer Packet (print-to-PDF works today)
- [ ] More verified channels (contributions welcome — include the source)
- [ ] Case workspaces (`cases/<id>/`) as the foundation for the institutional edition
