# Shield — integration guide (DRAFT, not wired in)

`shield/` is self-contained. Nothing in the Desk imports it yet, so this branch
is safe to merge as-is; turning it on is the five small patches below.

## What's in it

| Module | Retail feature | Free? |
|---|---|---|
| `approvals.py` | **Check my wallet** — every open ERC-20 / NFT-all / Permit2 approval, read live, graded danger/high/review/ok, revoke links (revoke.cash) | Yes (ETH, Base, OP, Arbitrum, Polygon key-less; BNB/Avax need the free Etherscan key) |
| `drain.py` | **I signed something** — drain transactions (tokens pulled out by someone else's tx), drainer contract, receivers, likely kit fee wallet, revoke-first steps, tracer seeds | Same |
| `sitewatch.py` | **Sites I use** — DNS / registrar / lock / IP / certificate / script-host changes on the real dApp domain | Yes (Cloudflare DoH, RDAP, crt.sh) |
| `compromised.py` | **Same-day incident list** — paste a post naming hijacked sites; flagged everywhere immediately | Yes |
| `web.py` | Desk pages for all of the above | — |

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

`.gitignore` additions: `compromised.json`, `sitewatch.json`.

## Known limits (be honest in the UI)
- Can't intercept a signature: the wallet is where signing happens. Shield is
  the layer around it — hygiene before, warning during, response after.
- Approval history comes from explorer logs; very old or very busy wallets may
  hit API page limits (draft caps at 1,000 entries per query).
- Fee-wallet detection is a heuristic ("smaller recurring cut"); label it a lead.
- Sitewatch "no alert" is not "safe"; normal deploys produce notices.
- Solana / Tron approvals (delegate, TRC-20 approve) are not covered yet.

## Commercial path
`sitewatch.py` is the seed of the **protocol monitor** (paid, shared with
PatchPulse): per-team dashboards, Slack/Telegram/SEAL routing, registrar-lock /
DNSSEC / CAA audit, 5-minute checks, an on-call promise.
