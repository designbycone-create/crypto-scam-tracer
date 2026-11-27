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
- Hardware wallet check (`/hwcheck`) with USB name check, "My wallets" watch (alerts when money leaves) and private custody records. Next: Bait & Trace.
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

## Phone
- [x] ScamHunter Guard: warns about reported scam numbers, message checker, large print
- [x] ScamHunter Threat Desk app: the Desk on your phone through your own Cloudflare Worker, end-to-end encrypted, QR pairing
- [ ] Release-signed APKs (your own signing key) so updates install over the old version
- [ ] Desk alerts as phone notifications in the app (today: Telegram / ntfy)
- [ ] Standalone checks in the app when the Desk is off
- [ ] Guard: warn while the call is still ringing, and easier setup

## Investigate
- [x] Look up a scammer: usernames on 500 sites (Maigret), emails / phones / websites / names in public records
      (SpiderFoot, passive modules only), with an IC3-ready summary
- [ ] Add a lookup's results to the court evidence bundle with one click

## Threat Map
- [x] World map of reported threats: FBI/CISA, security news, abuse.ch botnet and malware feeds
- [x] Posts from trusted security researchers on Bluesky and Mastodon (free, named accounts only)
- [ ] X as an extra source: the user's own pay-per-use key, with a monthly spending cap the Desk enforces
- [ ] ransomware.live and Cloudflare Radar layers (each with the user's own free token)

## Look
- **Night Desk** redesign shipped from the design owner's spec (`design/redesign/`): shared shell, Overview, section pages, Threat Map, every older page restyled through the shell, phone app bar and bottom bar.
- Later: rebuild older pages one by one in the new components (they're restyled, not yet redrawn); bigger type inside the network graph.

## Add-ons
- **PatchPulse** (separate paid product, patchpulsehq.com): "My website" page shows it as coming soon. The read-only connector is built and tested but off (`addons/patchpulse.py`, `RELEASED = False`). At launch: one signed Desk update sets `RELEASED = True`; owners then connect with a PatchPulse API key. Later: a ScamHunter Pro bundle.

## Bait & Trace (after a breach)
The bank dye-pack idea for computers and wallets: plant decoys that look valuable, and when an
intruder uses one, record what *their own action* sends back, for an IC3 report.
- [ ] Decoys ("canary tokens"): a fake passwords file, a document such as "Bank login.docx", a fake
      API key, a fake seed phrase, each unique so a trigger says exactly which decoy was touched
- [ ] Trigger endpoint: a small Cloudflare Worker the user owns (no third party sees triggers;
      canarytokens.org stays an optional, clearly labelled alternative). The Desk itself stays
      on 127.0.0.1; it picks up triggers from the Worker
- [ ] Trace: IP address, time and device type from the trigger, plus public facts only: country
      (DB-IP), the network that owns the address and its abuse contact (RDAP)
- [ ] Report: timestamped evidence page laid out for IC3, plus a ready-to-send abuse report to the
      hosting provider (the user sends it)
- [ ] Decoy wallet: small balance, its seed phrase planted as bait; any sweep is followed by the
      existing network mapper
- Limits, by design: a decoy never runs code on the intruder's machine and never reaches into
  their systems (no "hacking back", a federal crime that would also spoil the evidence). It only
  records what their own action sends.
