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
- data licensing: abuse.ch's MalwareBazaar, URLhaus and ThreatFox are free only for not-for-profit use
  ([terms](https://abuse.ch/terms-of-use/)); a commercial edition needs a Spamhaus/abuse.ch subscription
  (or must leave those lookups to each customer's own non-commercial key) before shipping them

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
- [x] Sealed court evidence bundle with PDF report and standalone verifier
- [x] Signed releases (Ed25519) and one-click updates with automatic rollback
- [x] Published error-rate benchmark on independent ground truth
- [x] More chains: Litecoin, Aptos, opBNB; checksum recognition for TON, Dogecoin, Bitcoin Cash
- [x] PDF export of the Officer Packet
- [ ] More verified channels (contributions welcome — include the source)
- [ ] Case workspaces (`cases/<id>/`) as the foundation for the institutional edition

## Protection (before the scam)
- [x] Message checker: any scam text, email, DM or call script, local only
- [x] Copy-paste guard with a private address book
- [x] Browser extension (Chrome / Edge): address swaps, attack code, scam addresses
- [x] Agent firewall: hidden-instruction scanning, approval gate, Claude Code hook, local API
- [x] Exposure check for equipment and remote access open to the internet
- [x] Signed campaign feed: OPTIMJACK, the Binance heist (the FBI's 628 laundering addresses), fake Binance compensation, FaceStealer, Lunex/ClickFix, midterm election scams (Nov 2026)
- [ ] Telegram bot: forward a suspicious message, get a verdict
- [ ] Voice-clone defense kit: family code word and call-back checklist, large print
- [ ] Wallet-signing gate: the agent firewall in front of wallet signatures
- [ ] Extension in the Chrome and Edge stores (after the trademark filing)
- [ ] Monthly exposure re-check with alerts
