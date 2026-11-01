# Shield — integration guide

**Status (Nov 2026): wired into the Desk** — /shield, /prescreen, /sitewatch, /compromised and
/evidence pages, nav links, background site watch (every 30 min), claim-checker hooks, and
dollars-at-risk ranking (DefiLlama, free). Slow checks run in the background. The patches below are
kept as a record of what was changed.

## What's in it

| Module | Feature |
|---|---|
| `approvals.py` | **Check my wallet** — open approvals / standing permissions, graded danger / high / review / ok, revoke links or instructions, plus account-takeover checks |
| `drain.py` | **I signed something** — what was pulled out, by whom, where it went, likely kit fee wallet; steps switch to "account taken over" mode when needed |
| `prescreen.py` | **Check before you send** — background check on a receiving wallet; STOP / CAUTION / NO RED FLAGS; audit log |
| `sitewatch.py` | **Sites I use** — DNS / registrar / lock / IP / certificate / script-host changes on real dApp domains |
| `compromised.py` | **Same-day incident list** — paste a post naming hijacked sites; flagged everywhere |
| `evm.py`, `tron.py`, `solana.py`, `xrpl.py` | per-chain plumbing |
| `web.py` | Desk pages |

### Chain coverage (no API keys needed for any of it)

| Chain | Approvals / permissions | Takeover checks | Drain detection | Pre-screen | History source |
|---|---|---|---|---|---|
| Ethereum, Base, Optimism, Arbitrum, Polygon | ERC-20, NFT approve-all, Permit2 | EIP-7702 delegation | ✓ | ✓ | free Blockscout key (`blockscout_key`) → public Blockscout → 30-day RPC window |
| Avalanche | same | same | ✓ | ✓ | Routescan, no key (full history); RPC log window if Routescan is down |
| BNB Chain | same | same | ✓ | ✓ (token activity) | needs a free personal endpoint (`bsc_rpc`, e.g. NodeReal free tier) for the 30-day log window; paid Etherscan for full history |
| Tron | TRC-20 approvals | **permission-update hijack** | ✓ (transferFrom by others) | ✓ | TronGrid |
| Solana | SPL token delegates | **account "Assign" hijack**, foreign close authority | ✓ (moves without your signature) | ✓ (last ~60 txs) | public RPC (`solana_rpc` for a faster free endpoint) |
| XRP Ledger | RegularKey, SignerList, Checks, PayChannels, NFT sell offers | **master disabled + foreign regular key** | ✓ (payments after key change, checks cashed by others) | ✓ | public full-history servers |
| Bitcoin | n/a (no approvals) — explains key compromise | n/a | n/a | ✓ | mempool.space |

`python shield/test_allchains_offline.py` exercises every row with simulated data (17 checks).

Also in this branch: `multichain/adapters/evm.py` — the tracer now follows BNB Chain and
Avalanche without a paid key (RPC log window), since Etherscan's free tier no longer covers them.

## Patches to turn it on

**1. Desk routes** (`desk.py`, in `Handler.do_GET`, next to `/intel`):
```python
if path == "/shield":
    from urllib.parse import parse_qs
    from shield import web as sw, approvals, drain
    qs = {k: v[0] for k, v in parse_qs(query).items()}
    wallet, mode = qs.get("wallet", "").strip(), qs.get("mode")
    res = None
    if wallet and mode == "check":
        res = approvals.scan(wallet)
    elif wallet and mode == "drain":
        res = drain.analyze(wallet)
        drain.seed_tracer(res)
    return self._send(sw.shield_page(wallet, mode, res), "text/html; charset=utf-8")
if path == "/prescreen":
    from urllib.parse import parse_qs
    from shield import web as sw, prescreen
    f = {k: v[0] for k, v in parse_qs(query).items()}
    res = prescreen.screen(f["address"], f.get("chain") or None, f.get("tag"), f.get("me")) if f.get("address") else None
    return self._send(sw.prescreen_page(f, res), "text/html; charset=utf-8")
if path == "/sitewatch":
    from shield import web as sw
    return self._send(sw.sitewatch_page(), "text/html; charset=utf-8")
if path == "/compromised":
    from shield import web as sw
    return self._send(sw.compromised_page(), "text/html; charset=utf-8")
```
and in `do_POST`:
```python
if path == "/sitewatch":
    from shield import web as sw
    return self._send(sw.sitewatch_post(form), "text/html; charset=utf-8")
if path == "/compromised":
    from shield import web as sw
    return self._send(sw.compromised_post(form), "text/html; charset=utf-8")
```
Note: `/shield?mode=check` makes ~10–60 API calls; for production move it to a
background job with a "checking…" page (same pattern as the setup lookup).

**2. Navigation** (`freezekit/web.py` `shell()` and the Desk nav): add
`<a href='/shield'>Wallet shield</a>` and `<a href='/sitewatch'>Sites I use</a>`.

**3. Background job** (`responder/daemon.py`): every 30 min
```python
def job_sitewatch(desk):
    from shield import sitewatch
    sitewatch.check(log=_log, alert=lambda dom, sig: _alert(
        f"SITE CHANGED: {dom} - don't connect your wallet",
        "; ".join(sig) + ". Wait for the team to confirm it's safe.",
        key=f"site:{dom}:{sig[0][:40]}", critical=True, url=f"{desk}/sitewatch"))
```
and add `(1800, job_sitewatch, (desk,))` to `sched`.

**4a. Claim checker → pre-screen**: when a pasted message contains an address,
also run `prescreen.screen(addr)` and fold a STOP/CAUTION verdict into the
claim-checker verdict ("send 500 XRP to r…" then shows the wallet's record).

**4. Claim checker** (`responder/claimcheck.py`, in the domain loop):
```python
from shield import compromised
hit = compromised.check_domain(dom)
if hit:
    hits.append(f"Domain {dom}: {hit}.")
```
and in the address loop: `compromised.check_address(a)`.

**5. Setup wizard** (`freezekit/setup.py`): add a second entry button
"I connected my wallet / approved something" that links to
`/shield?mode=drain&wallet=<address>`; after the analysis, the receivers are
already seeded into the tracer, so the normal Desk flow (kits, officer packet,
issuer freezes) takes over.

`.gitignore` additions: `compromised.json`, `sitewatch.json`, `prescreen_log.jsonl`.

## Known limits (be honest in the UI)
- Can't intercept a signature: the wallet is where signing happens. Shield is
  the layer around it — hygiene before, warning during, response after.
- Approval history comes from explorer logs; very old or very busy wallets may
  hit API page limits (draft caps at 1,000 entries per query).
- Fee-wallet detection is a heuristic ("smaller recurring cut"); label it a lead.
- Sitewatch "no alert" is not "safe"; normal deploys produce notices.
- Solana / Tron approvals (delegate, TRC-20 approve) are not covered yet.

## Commercial path
`prescreen.py` is the seed of a **counterparty-screening API** for OTC desks,
crypto-accepting merchants and credit unions: same checks, JSON over HTTP,
per-check audit log (already written to `prescreen_log.jsonl`).

`sitewatch.py` is the seed of the **protocol monitor** (paid, shared with
PatchPulse): per-team dashboards, Slack/Telegram/SEAL routing, registrar-lock /
DNSSEC / CAA audit, 5-minute checks, an on-call promise.
