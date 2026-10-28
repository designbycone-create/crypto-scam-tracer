"""Render the multi-chain trace as one self-contained HTML page -- the detailed
log, available on demand. Chain-tolerant: unknown chain keys still render."""
import html

from .core import CHAINS


def _tx_url(chain, txid):
    ci = CHAINS.get(chain)
    return ci.explorer_tx(txid) if ci and txid else "#"


def _addr_url(chain, addr):
    ci = CHAINS.get(chain)
    return ci.explorer_addr(addr) if ci and addr else "#"


def render_html(state):
    e = html.escape
    s = state.get("summary", {})
    nodes = state.get("nodes", {})

    freeze = ""
    for op in state.get("freeze_ops", []):
        kind = {"stablecoin_issuer": "FREEZE at issuer", "exchange": "FREEZE at exchange",
                "bridge": "HALT at bridge"}.get(op["kind"], op["kind"])
        who = op.get("label") or (f"{op.get('issuer','')} ({op.get('asset','')})" if op.get("issuer") else "")
        freeze += (f"<tr><td><b>{e(kind)}</b></td><td>{e(op['chain'])}</td>"
                   f"<td class=m><a href='{_addr_url(op['chain'], op['address'])}'>{e(op['address'][:18])}…</a></td>"
                   f"<td>{e(str(who))}</td><td>{e(str(op.get('asset') or ''))}</td></tr>")

    hands = ""
    for h in state.get("handoffs", []):
        rt = h.get("resolved_to")
        dest = (f"{e(rt['chain'])}:{e(rt['address'][:16])}…" if rt else "<i>open — destination unknown</i>")
        hands += (f"<li><b>{e(h['status'].upper())}</b> — {e(h['chain'])} "
                  f"<span class=m>{e((h.get('address') or '')[:18])}…</span> "
                  f"via {e(str(h.get('service') or 'bridge/swap'))} → {dest}"
                  f"<br><small class=mut>{e(h.get('note',''))}</small></li>")

    endp = ""
    for ep in state.get("endpoints", []):
        endp += (f"<li>[{e(ep['type'])}] <b>{e(ep.get('label') or 'unidentified')}</b> on {e(ep['chain'])} — "
                 f"<span class=m><a href='{_addr_url(ep['chain'], ep['address'])}'>{e(ep['address'][:20])}…</a></span></li>")

    rows = ""
    for x in sorted(state.get("edges", []), key=lambda z: z.get("epoch") or 0):
        rows += (f"<tr><td>{x.get('depth')}</td><td>{e(x.get('time') or '')}</td><td>{e(x['chain'])}</td>"
                 f"<td class=m>{e((x['from'] or '')[:12])}…</td><td class=m>{e((x['to'] or '')[:12])}…</td>"
                 f"<td>{x.get('amount',0):,.4f} {e(x.get('asset') or '')}</td>"
                 f"<td class=m><a href='{_tx_url(x['chain'], x.get('txid'))}'>tx</a></td></tr>")

    allnodes = ""
    for k, n in sorted(nodes.items(), key=lambda kv: (kv[1]['chain'], kv[1]['type'])):
        fz = ", ".join(f["asset"] for f in n.get("freezable", []))
        allnodes += (f"<tr><td>{e(n['chain'])}</td><td class=m><a href='{_addr_url(n['chain'], n['address'])}'>{e(n['address'][:22])}…</a></td>"
                     f"<td>{e(n['type'])}</td><td>{e(n.get('label') or '')}</td><td>{e(fz)}</td></tr>")

    chains = ", ".join(s.get("chains", []))
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Multi-Chain Scam Trace</title><style>
:root{{--bg:#fff;--fg:#16181d;--mut:#5b6170;--line:#e3e5ea;--acc:#0b63ce;--warn:#b42318}}
@media(prefers-color-scheme:dark){{:root{{--bg:#111318;--fg:#e8eaf0;--mut:#9aa1b2;--line:#2a2e38;--acc:#5aa2ff;--warn:#ff6a5a}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:1040px;margin:0 auto;padding:16px}}
h1{{font-size:24px}} h2{{font-size:18px;margin-top:26px}}
.k{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}}
.k div{{border:1px solid var(--line);border-radius:10px;padding:10px}} .k b{{display:block;font-size:20px}}
table{{width:100%;border-collapse:collapse;font-size:13px;display:block;overflow-x:auto}}
td,th{{border-bottom:1px solid var(--line);padding:6px;text-align:left}}
.m{{font-family:ui-monospace,monospace;font-size:12px}} a{{color:var(--acc)}} small,.mut{{color:var(--mut)}}
.warn{{color:var(--warn);font-weight:600}}</style></head><body>
<h1>Multi-Chain Scam Trace</h1>
<p class=mut>Generated {e(state.get('generated',''))} · chains: {e(chains or '—')} · funds traced forward in time across chains</p>
<div class=k>
<div>Wallets<b>{s.get('wallets',0)}</b></div><div>Exchanges<b>{s.get('exchanges',0)}</b></div>
<div>Bridges<b>{s.get('bridges',0)}</b></div><div>Mixers<b>{s.get('mixers',0)}</b></div>
<div>Open handoffs<b>{s.get('open_handoffs',0)}</b></div><div>Freeze ops<b>{s.get('freeze_opportunities',0)}</b></div>
<div>Flows<b>{s.get('edges',0)}</b></div></div>

<h2 class=warn>Freeze / halt opportunities (act on these)</h2>
<table><tr><th>Action</th><th>Chain</th><th>Address</th><th>Who</th><th>Asset</th></tr>{freeze or '<tr><td colspan=5>None yet.</td></tr>'}</table>

<h2>Cross-chain handoffs (where funds may change chain)</h2><ul>{hands or '<li>None yet.</li>'}</ul>

<h2>Terminal endpoints (exchanges / bridges / mixers)</h2><ul>{endp or '<li>None reached yet.</li>'}</ul>

<h2>Fund flow (time-ordered, all chains)</h2>
<table><tr><th>Hop</th><th>Time</th><th>Chain</th><th>From</th><th>To</th><th>Amount</th><th></th></tr>{rows}</table>

<h2>Every wallet flagged</h2>
<table><tr><th>Chain</th><th>Address</th><th>Type</th><th>Label</th><th>Freezable</th></tr>{allnodes}</table>

<p class=mut><small>Funds commingle at hubs and at custodial services, so downstream hops are investigative leads, not proof a later transfer carries the stolen funds. A custodial crossing (exchange or swap) breaks the on-chain link; the trace resumes once the service discloses the destination. Stablecoin freeze opportunities can be acted on at any hop via the issuer.</small></p>
</body></html>"""
