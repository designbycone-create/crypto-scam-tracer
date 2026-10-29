# crypto-scam-tracer

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

---

## Quick start

Requires **Python 3.9+**.

```bash
git clone https://github.com/designbycone-create/crypto-scam-tracer.git
cd crypto-scam-tracer
pip install -r requirements.txt

# set up your case (these files stay private; they're git-ignored)
cp config.example.json config.json
cp victim.example.json victim.json
#   -> edit config.json: put the scam wallet in "watched_wallets" and "scam_wallet"
#   -> edit victim.json: your IC3 complaint number, report links, contact (all optional)
```

### The Desk — easiest way to run everything (recommended)

One command starts **and supervises** all the watchers in the background and
opens a live dashboard in your browser — watcher health, where your funds are
right now (parked vs. cashed out), every real freeze opportunity with a
one-click draft button, and recent activity. If a watcher ever dies, the Desk
restarts it.

```bash
python desk.py          # Windows: double-click run_desk.cmd   ·   macOS/Linux: ./run_desk.sh
```

Leave it running; the dashboard auto-refreshes. Close the window to stop
everything. Prefer to run the pieces individually? Keep reading.

### Run just the live watcher
```bash
python xrpl_watcher.py
```

### Map the scam network and draft reports
```bash
python -m scam_investigator netmap            # builds network_map.html + freeze-request drafts
python -m scam_investigator investigate --address <scam_wallet> --domain <scam_site.com>
python -m scam_investigator ceasedesist --domain <scam_site.com>
```

### Trace across chains
```bash
# funds landed on Tron? start there:
python -m multichain trace --chain tron --address T...
# run it as an automated daemon:
python -m multichain watch
```

---

## Phone alerts (optional, free)

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
FBI's **[IC3](https://www.ic3.gov)**. Also report the wallet/site to
**[Chainabuse](https://chainabuse.com)**. This tool helps you act fast and build
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
