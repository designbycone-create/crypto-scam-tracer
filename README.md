# crypto-scam-tracer — ScamHunter Threat Desk™

**A free, open-source toolkit that protects people from scams and helps victims
after one.** Before a scam: check messages, addresses, websites, your AI agents
and your own network for the warning signs. After a scam: watch the scammer's
wallet in real time, follow the stolen money across blockchains, and draft the
freeze and evidence requests that give you a real shot at getting funds frozen.
Everything runs on your own computer.

Built by a scam victim who got tired of feeling powerless. If it helps you,
star it and pass it on.

> ⚠️ **This is not a recovery guarantee.** No tool can promise your money back.
> What this does is maximize your odds: it finds every point where funds can
> still be frozen, drafts the requests for you, and builds a clean evidence
> trail for law enforcement. Speed matters — the sooner you run it after a
> theft, the better your chances.

> 🤝 **Trust pledge — free for victims, always.** This tool never asks for money,
> a seed phrase or a "recovery fee"; never contacts victims; never sends anything
> on your behalf; never promises recovery. Anyone who does is running a recovery
> scam. See [TRUST.md](TRUST.md).

---

## Supported chains

| Chain | Live watching | Tracing & freeze kits | Lookup in setup | Notes |
|---|---|---|---|---|
| XRP Ledger | real-time | yes (+ destination tags, issuer freeze/clawback) | yes | deepest coverage |
| Bitcoin | every 5 min | yes | yes | mempool.space, no key |
| Ethereum, Base, Optimism, Arbitrum, Polygon | every 5 min | yes (+ USDT/USDC issuer freezes) | yes | Blockscout, no key |
| BNB Chain, Avalanche | every 5 min | yes | yes | free Etherscan key needed for tracing |
| Tron | every 5 min | yes (+ USDT-TRC20) | yes | TronGrid, no key |
| Solana | every 5 min | yes (+ USDC/USDT SPL) | yes | public RPC, no key (set `solana_rpc` for heavy use) |
| Litecoin | every 5 min | yes | yes | litecoinspace.org, no key |
| Aptos | every 5 min | yes (+ fungible assets, takeover checks) | yes | public node; free indexer key for full history |
| opBNB | every 5 min | yes | yes | free personal RPC recommended |
| TON, Dogecoin, Bitcoin Cash | — | — | — | recognised with checksums for warnings (pre-screen, copy-paste guard, extension, message checker) |

Any asset on these chains works — native coins and tokens (USDT, USDC, …).
Every address is checksum-validated (EIP-55, Bech32/Bech32m, CashAddr, TON CRC16,
Base58Check), so a one-character typo is caught. Other chains: paste the scammer's
address into Incident mode and the threat-intel lookup; full tracing needs an
adapter (contributions welcome — one file per chain; see [CHAIN_SOURCES.md](CHAIN_SOURCES.md)).

---

## Protection before the scam

Every tool below runs on your computer; nothing you paste or copy is sent anywhere
unless the page says so. Open them from the Desk's menu.

| Tool | Desk page | What it does |
|---|---|---|
| **Is this message a scam?** | `/msgcheck` | Paste a text, email, DM or what a caller said. Plain-language red flags for every common scam (bank and government impostors, toll and delivery texts, "grandchild in jail" and voice-clone emergencies, gift cards, crypto ATMs, fake investment platforms, task jobs, "we can recover your money"). Links and addresses are checked against scam lists. |
| **Check before you send** | `/prescreen` | A verdict on a crypto address before you pay it, on 14 chains, with published error rates ([benchmark](benchmark/RESULTS.md)). Also reads Tether's and Circle's own contracts to see whether USDT / USDC at the address is frozen (Ethereum, Base, Arbitrum, Polygon, Optimism, Avalanche, Tron), and asks [Public AML](https://publicaml.org) — a free non-profit screening service — for a second opinion. The address you check is sent to Public AML; set `"publicaml": false` in `config.json` to keep every lookup on your computer. A low Public AML score is never shown as "safe". |
| **Check a phone number** | `/numbercheck` | Has this number been reported to the FTC as a scam or robocall? Uses the FTC's Do Not Call reported-calls data through its official API (free key from [api.data.gov](https://api.data.gov/signup/), saved as `ftc_api_key`). Reports are unverified, so a number is rated by how many separate reports it has, never by one. |
| **Copy-paste guard** | `/clipguard` | Optional. Checks every crypto address you copy: large red STOP for a known scammer address, green note for an address in your private address book. Defeats clipboard-swapping malware. |
| **ScamHunter Guard browser extension** | `/extension` | Chrome / Edge. Warns when a page swaps the address you copy (even to an address no list knows yet), loads code from known attack servers, tampers with core browser functions, or shows a scammer's address; blocks pasting one. Install: `edge://extensions` → Developer mode → Load unpacked → the `extension` folder, then connect it with the code on `/extension`. |
| **Agent firewall** | `/agentguard` | For AI agents that read the web or email: finds instructions hidden from people (invisible text, comments, encoded text) and holds risky actions — payments, deletes, installs of look-alike packages, sending secrets — for your OK. Includes a Claude Code hook and a token-protected local API for your own agents. |
| **Exposure check** | `/exposure` | Is anything at your home or business open to the internet? Refrigeration, HVAC and building controllers, remote desktop, cameras. Uses the public Shodan InternetDB record for your own address and never logs in to anything. Known flaws found there are checked against CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog: flaws attackers are using right now (and automated attack tools try first) are marked CRITICAL. The Desk re-checks your address weekly and alerts only if something new is open (`"exposure_watch": false` turns that off). Built after the October 2026 attacks that heated supermarket fridges through internet-exposed controllers. |
| **Malware & link check** | `/malware` | Is Windows Defender on, real-time and up to date, and what has it caught lately; run a quick scan. Check a download before opening it (your recent Downloads are listed): Windows Defender scans it, and the Desk looks for disguised names (`invoice.pdf.exe`), programs hidden in zips, a missing or broken digital signature, and where Windows says it was downloaded from. Check a link before clicking: look-alike brands and other scam signs plus ScamHunter's attack lists. With your own free [abuse.ch](https://auth.abuse.ch/) key (stored encrypted), files are also looked up by fingerprint in MalwareBazaar and links in URLhaus and ThreatFox (free for not-for-profit use under [abuse.ch's terms](https://abuse.ch/terms-of-use/)). The file itself never leaves your computer. It never says "safe": only what was and wasn't found. It never changes Defender's settings. |
| **Secrets left in the open** | `/secretscan` | Finds wallet recovery (seed) phrases, private keys, wallet and keystore files, API keys and password notes saved in ordinary files (text, Word, spreadsheets, settings files) in the folders you choose: what key-stealing malware and automated attack tools search for first. Seed phrases are confirmed with the BIP-39 checksum; files in cloud-synced folders (OneDrive, Dropbox, Google Drive) are flagged as copied online. Runs only on your computer and never shows, logs or saves the secret itself: you see the file, the line and what to do. Pictures aren't checked. |
| **Sites I use** | `/sitewatch` | Early warning when a site you use is hijacked, including a trusted outside script that starts loading new code (how the OPTIMJACK attack worked). |
| **ScamHunter Threat Desk for Android** | `android/desk/`, `relay/`, `worker/relay/` | Your PC's Desk on your phone, at home or away, in the same layout. It reaches the Desk through **your own** free Cloudflare Worker: the Desk connects out to the Worker (nothing on the PC is opened to the internet) and everything is encrypted end to end (AES-256-GCM, key shared once by QR code), so the Worker only passes along data it can't read. From the phone you can read the Desk and run checks; settings, keys, updates and share copies stay at the computer. Set up in **Settings → Phone app**. Separate from ScamHunter Guard. |
| **ScamHunter Guard for Android** | `android/` | For phones, built for older users: large print, warns while the phone rings: a large card over the incoming call (after you allow "Appear on top") for reported scam numbers, and a calm "Unknown caller, be careful" card for any number not in your contacts (Android's call-screening feature: the number only, never the call audio), an "Am I being scammed?" screen, spoken call reports: one button opens the FCC's unwanted-call complaint form already filled in (from details kept only on the phone; the person reviews it, ticks the attest box and taps Submit), plus copy-and-paste reports for the FTC / Do Not Call / FBI, and a ready-to-send text to a family member. Uses the same scam rules as the Desk. Build: `gradle -p android assembleDebug`. |
| **Campaign feed** | — | Known attacks (addresses, attacker hosts, script fingerprints) ship inside each signed release, so every user gets them under the same signature check as the code. |

---

## What it does

Three tools that work together, each able to run on its own:

### 1. Live wallet watcher (`xrpl_watcher.py`)
Subscribes to the XRP Ledger and alerts you **the instant funds leave** a scam
wallet — console, log, desktop popup, and an optional **phone push**. When money
moves to a new private wallet it can follow it automatically.

### 2. XRPL network mapper + investigator (`scam_investigator`)
Traces the stolen funds **forward in time** across the XRP Ledger, hop by hop,
and builds a network map. It flags every exchange cash-out and every
bridge/swap, screens addresses against the **OFAC sanctions list**, scans the
scam site's infrastructure (DNS, hosting, registrar), and auto-drafts:
- **freeze/preservation requests** to exchanges that received funds,
- **cease-and-desist / takedown letters** to hosts and registrars.

### 3. Multi-chain tracer (`multichain`)
When funds leave the XRP Ledger, the trail continues. This follows stolen crypto
across **Bitcoin, Tron, Ethereum, Polygon, BNB Chain, Arbitrum, Base, Optimism,
and Avalanche**, flagging every wallet, exchange, bridge, and mixer. It captures
**every freeze opportunity** automatically, including the strongest one:

> 💠 **Stablecoin issuer freezes.** Tether and Circle can freeze USDT/USDC at
> *any* address, on any chain. Whenever stolen value lands in USDT or USDC, this
> tool drafts a ready-to-send freeze request to the issuer — not just to
> exchanges. This is often the single most effective lever a victim has.

It runs as an automated daemon: re-traces known addresses on a loop, auto-drafts
reports, and phone-alerts you whenever the trail grows.

### 4. Submission Center (`freezekit`) — freeze requests that actually get through
Emailing exchanges from your own inbox mostly fails: support addresses bounce,
many exchanges only take portal submissions, US users get geo-blocked, and
**exchanges freeze on law-enforcement requests, not victim emails.** So instead
of guessed email drafts, the Desk builds a **freeze kit** for every platform the
money reached and routes it through the channels that work:

1. **SEAL 911** (free, Telegram `@seal_911_bot`) — security researchers who are
   members of TRM's **Beacon Network**, which alerts member exchanges
   automatically when flagged funds arrive. A prefilled message is ready.
2. **The platform's victim channel**, where one exists and is verified (e.g.
   MEXC's report form — which starts a 48-hour clock the Desk counts down).
3. **An Officer Packet** — a printable, signed-request-ready package your local
   police / sheriff / FBI field office submits through each exchange's
   **law-enforcement portal** (no geo-blocks, no support queue).
4. **IC3 and Chainabuse updates**, prefilled with every new wallet and exchange.
5. **Issuer freezes** — if the network swaps into an issued token (RLUSD on
   XRPL, USDT/USDC elsewhere), the issuer can freeze or claw it back. The Desk
   scans every network wallet's trust lines and reads issuer flags.

Every channel lives in a **verified directory** (`freezekit/channels.json`)
with its source; an email draft is only ever built for a verified address.
Every kit file is SHA-256 hashed into a hash-chained **custody log**, and each
kit has a `MANIFEST.txt` an officer can verify. Status tracking (to do →
submitted → acknowledged → frozen) shows what's left.

### 5. Incident mode, scam radar, claim checker (`responder`)
- **Incident mode** — a hack just happened? Paste any text with attacker
  addresses (any chain, checksum-validated). XRPL addresses are watched live;
  others seed the multi-chain tracer. Public address feeds can be subscribed.
- **Early-warning signals** — fresh throwaway wallets, victim collectors,
  laundering splitters, drained wallets, exchange-funded wallets (KYC leads),
  EIP-7702-delegated and mixer-funded EVM wallets.
- **Exchange status** — reads public status pages where they exist.
- **Scam radar** — watches public Certificate Transparency logs for new
  "refund / compensation / claim" lookalike domains, which appear within hours
  of every big hack.
- **Claim checker** — paste a message or link; get the red flags and whether
  any address or domain in it belongs to the network you're tracking.

### 6. Free attribution + interactive graph
- **Attribution** (`scam_investigator/attribution.py`) — for every cash-out
  point the explorers can't name, it gathers free public evidence and grades
  it: **verified** (the account's Domain + that site's `xrp-ledger.toml` list
  each other), **likely** (most of its XRP sweeps into one labeled exchange, or a
  labeled exchange activated a destination-tag account, or Bithomp names it),
  **hint** (claimed domain, custodial flags). The evidence is printed in the
  officer request, so nobody has to take a label on faith. Optional free
  Bithomp key: `"bithomp_token"` in `config.json`.
- **Network graph** (`/graph` on the Desk) — every wallet and flow, sized by
  volume, colored by role, with your stolen funds' path in red. Click a wallet
  for its deposits, attribution evidence and explorer links. Uses Ripple's free
  full-history servers; no paid infrastructure.

---

## Quick start

New user? **[SETUP.md](SETUP.md)** walks through install, first start, the optional free keys, alerts and
privacy, step by step. To give ScamHunter to someone else without giving them your case, use the Desk's
**Settings → Share ScamHunter** page.

**Windows (one line, no admin needed)** — open PowerShell and paste:

```powershell
irm https://raw.githubusercontent.com/designbycone-create/crypto-scam-tracer/main/install.ps1 | iex
```

It installs Python if needed, puts the Desk in `%USERPROFILE%\ScamHunter`,
adds Desktop / Start Menu shortcuts, starts it at sign-in, and opens the
**setup page** in your browser:

1. **Where did your crypto go?** Paste the transaction hash or explorer link of
   the payment you sent. The Desk reads it from the XRP Ledger and fills in the
   scammer's wallet, your wallet, the amount and the time. (Or paste the
   scammer's address directly.)
2. **About you** (optional) — name, email, IC3 number, other reports. Used only
   in the drafts *you* choose to send.
3. **Alerts** — a private ntfy topic is generated; subscribe in the free ntfy
   app. Updates install from the Desk's **Updates** page (one click, backed up, self-tested, undoable). Telegram connects from **Settings → Alerts to your phone** in about 2 minutes (no command line).

Press **Start tracking**. The watchers start, and within minutes the Desk shows
where your funds are, the network behind the scam, and freeze kits.

**Finding your way around the Desk.** Every page has the same tabs across the top:

| Tab | What's in it |
|---|---|
| **Overview** | Everything at a glance: live status, a map of scam-call reports by state, the most-reported scam types and numbers, the latest warning, and one live feed of what every part of the Desk is seeing (filter by section, warnings only, or search). It refreshes itself every 20 seconds. |
| **Threat Map** | A world map of threats being reported right now: FBI and security-news alerts, posts from trusted security researchers on Bluesky and Mastodon, botnet servers, malware sites and newly exploited flaws. Zoom, drag, click a country; switch layers and 24 hours / 7 days / 30 days. "Rising" marks countries and malware families well above their usual level. Each source is credited on the page with its terms; abuse.ch layers use your own free key. |
| **Crypto & Wallets** | *Protect*: check before you send, wallet shield, copy-paste guard, claim checker, wallet compromised. *My case*: where your funds are, freeze requests, officer packets, court evidence. *Investigate*: network graph and table, scam radar, threat intel, incident mode. *Investigate* also has **Look up a scammer**: a username, email, phone number, website or name the scammer used, checked in public records with Maigret and SpiderFoot (free, separate programs; passive only). |
| **Phone & Messages** | Check a phone number, check a message, the scam-call map, and the Android app. |
| **Online Defense** | Browser extension, sites you use, exposure check, malware & link check, secrets left in the open, agent firewall. |
| **Settings** | Alerts to your phone, updates, case setup, share ScamHunter. |

The Desk keeps a small log of the checks you make on it (`desk_activity.jsonl`): only the kind
of check and its result, never the message you pasted or the number you looked up.

**Mac / Linux / manual:** Python 3.10 or newer. `git clone` this repo, `pip install --require-hashes -r requirements.txt`
(every package is pinned to an exact version and checked against its published hash),
`python desk.py` — the same setup page opens.

---

## Alerts (optional, free) — use two channels

Critical alerts (your funds hitting an exchange) go to **every** channel you
configure, so one channel being down or over quota never loses one. Test them
with `python alerts.py test`.

- **Telegram** — open **Settings → Alerts to your phone** on the Desk: create a bot with @BotFather, paste its token, press START in your bot, done (it finds your chat id, saves it and sends a test). `python telegram_setup.py` does the same from a terminal. Or manually: put `bot_token` and your
  `chat_id` under `"telegram"` in `config.json`.
- **Email** — a Gmail *app password* under `"alert_email"` (critical alerts only).
- **ntfy** — below.

### ntfy

Install the free **[ntfy](https://ntfy.sh)** app, subscribe to a hard-to-guess
topic name, and put that topic in `config.json` under `"ntfy_topic"`. You'll get
a push the moment funds move, with one-tap buttons to open the drafted report.

> Pick a long, random topic (e.g. `scamwatch-7f3q9x2`). Anyone who knows your
> topic can send you notifications, so don't use a guessable name.

## EVM chains (optional, free key)

Bitcoin and Tron work with no setup. The Ethereum-family chains use the free
[Etherscan V2 API](https://etherscan.io/apis) (one key covers all of them). Get
a free key and put it in `config.json` under `"etherscan_key"` (or set the
`ETHERSCAN_API_KEY` environment variable). Until you do, those chains are simply
skipped.

---

## How it handles cross-chain crossings

When funds go through a **custodial swap** (e.g. an instant exchange) or a
**centralized exchange**, the on-chain link breaks — nobody can follow the money
through a company's internal books without that company's records. Here's how
the tool handles it honestly:

- It **drafts the request** to that service automatically (freeze + disclose the
  destination).
- It opens a **resumable "handoff" lead**. The moment you learn where the funds
  came out (from the service's reply, or your own research), one command
  continues the trace on the next chain — all the way to the end.
- **EVM→EVM bridge hops** are followed automatically (shared address space).

---

## Accuracy & safety

- **Your keys are stored encrypted.** API keys, personal RPC endpoints, the Telegram bot token, the email
  app password, your private ntfy topic and the Desk's own tokens are sealed in `config.json` with Windows'
  account protection (DPAPI): only your Windows account on this computer can unlock them, so a copied
  settings file, a backup or a cloud-synced folder reveals nothing. The Desk encrypts existing values on
  start. Malware already running as you could still unlock them; this stops the common file-grabbing
  kind. On Mac and Linux the values stay as they are and the file is made readable by your account only.
  Check with `python securestore.py status`.
- **Packages are pinned and hash-checked.** Every dependency is an exact version checked against its
  published hash (`pip --require-hashes`), so a swapped or hijacked package can't arrive through an update.
- **The Desk only answers its own address.** It listens on 127.0.0.1 only and refuses requests made under any
  other host name, so a website can't reach it through DNS rebinding.

- **Time-forward tracing — no false trails.** Stolen funds often pass through
  reused laundering/consolidation wallets that have months of unrelated history
  and other people's money flowing through them. The tracer only follows a
  wallet's outgoing payments that occur *at or after* your stolen funds arrived
  there — so it never attributes a shared wallet's prior activity to your case.
  (A plain trace that ignores time can report dozens of "cash-outs" that
  predate the theft and aren't yours; this tool does not.)
- **No fabricated labels.** The tool never invents an exchange "deposit address."
  Only published, canonical contracts (stablecoins, sanctioned addresses) are
  hardcoded; everything else comes from public, community-maintained label data,
  or is flagged "unidentified — investigate." A freeze request never lands on an
  innocent third party.
- **Nothing is sent automatically.** Every report is a *draft* for you to review
  and send yourself.
- **Reports name no individuals.** They state verifiable on-chain facts and cite
  your existing case references.
- **Your case data is private.** `config.json`, `victim.json`, logs, maps, and
  drafts are all git-ignored and never committed.

---

## Report first, always

Before anything else, file a report with law enforcement. In the U.S. that's the
FBI's **[IC3](https://www.ic3.gov)** — and get a report number from your local
police, because exchanges freeze on law-enforcement requests. If funds are
still moving, contact **SEAL 911** (Telegram `@seal_911_bot`). Also report the
wallet/site to **[Chainabuse](https://chainabuse.com)**. **Never use a VPN** to
get around an exchange's geo-block; law-enforcement systems reject it. This tool helps you act fast and build
the evidence — it does not replace law enforcement.

---

## Contributing

Issues and pull requests welcome — new chain adapters, verified exchange/issuer
contact routes, better heuristics. If you've been scammed and used this, I'd
love to hear what worked.

## Disclaimer

Provided as-is under the MIT License, for lawful use by victims and
investigators. It performs only public blockchain lookups and open-source
intelligence on public infrastructure. It is not legal or financial advice. Verify
every contact route before sending anything, and work with law enforcement.

---

© 2026 Matthew Cone / FPH LLC · Code under the MIT License · "ScamHunter Threat Desk" is a trademark of FPH LLC — see [NOTICE.md](NOTICE.md).
