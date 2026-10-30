# crypto-scam-tracer — ScamHunter Desk™

**A free, open-source toolkit for victims of cryptocurrency fraud.** Watch the
scammer's wallet in real time, follow the stolen money across blockchains, and
automatically draft the freeze and evidence-preservation requests that give you
a real shot at getting funds frozen — before they vanish.

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

Any asset on these chains works — native coins and tokens (USDT, USDC, …).
Other chains: paste the scammer's address into Incident mode and the threat-intel
lookup; full tracing needs an adapter (contributions welcome — one file per chain).

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
   app. Telegram is one command (`python telegram_setup.py`).

Press **Start tracking**. The watchers start, and within minutes the Desk shows
where your funds are, the network behind the scam, and freeze kits.

**Mac / Linux / manual:** `git clone` this repo, `pip install -r requirements.txt`,
`python desk.py` — the same setup page opens.

---

## Alerts (optional, free) — use two channels

Critical alerts (your funds hitting an exchange) go to **every** channel you
configure, so one channel being down or over quota never loses one. Test them
with `python alerts.py test`.

- **Telegram** — create a bot with @BotFather, then run `python telegram_setup.py` (it finds your chat id and saves it). Or manually: put `bot_token` and your
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

© 2026 Matthew Cone / FPH LLC · Code under the MIT License · "ScamHunter Desk" is a trademark of FPH LLC — see [NOTICE.md](NOTICE.md).
