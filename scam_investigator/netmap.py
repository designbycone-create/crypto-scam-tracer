"""Scam-network mapping: trace the stolen funds FORWARD IN TIME from the scam
wallet, hop by hop, and build a persistent network graph.

Key correctness rule: when stolen funds arrive at a wallet at time T, we only
follow that wallet's *outgoing* payments at time >= T. A laundering hub may
have months of unrelated history and thousands of other users' funds flowing
through it; following all of that would wrongly paint unrelated people as "the
scam network." Time-forward tracing keeps the map to the actual stolen-fund
flow. Even so, funds commingle at hubs, so downstream hops are leads, not proof
that a specific later payment contains the stolen XRP.

An exchange / custodial deposit (destination tag, known label, or the
Require-Destination-Tag flag) is a terminal cash-out point: the money left the
ledger into a company that keeps KYC records. We stop there and flag it.
"""
import json
import os
import time as _time
from datetime import datetime, timezone

from .ledger import Ledger, xrp, ripple_time, RIPPLE_EPOCH
from .trace import load_labels, LSF_REQUIRE_DEST_TAG, xrpscan_name
from .swaps import swap_info


def _epoch_from_ripple(date_field):
    """account_tx 'date' is ripple-epoch seconds."""
    return (date_field + RIPPLE_EPOCH) if isinstance(date_field, (int, float)) else None


async def _describe(L, addr, labels, use_xrpscan=True):
    info = await L.account_info(addr) or {}
    label = labels.get(addr)
    src = "labels.json" if label else None
    if not label and use_xrpscan:
        n, d = xrpscan_name(addr)
        if n:
            label, src = f"{n} {('(' + d + ')') if d else ''}".strip(), "xrpscan"
    custodial = bool(label) or bool((info.get("Flags") or 0) & LSF_REQUIRE_DEST_TAG)
    sw = swap_info(label)
    return {
        "address": addr,
        "balance_xrp": xrp(info.get("Balance")) if info else None,
        "exists": bool(info),
        "requires_dest_tag": bool((info.get("Flags") or 0) & LSF_REQUIRE_DEST_TAG),
        "label": label, "label_source": src,
        "is_exchange": custodial,
        "is_swap": bool(sw),
        "swap_name": (sw or {}).get("name"),
    }


async def _outgoing_after(L, addr, after_epoch, min_xrp):
    """Outgoing XRP payments from addr at time >= after_epoch, above min_xrp."""
    out = []
    for tx in await L.account_tx(addr, forward=True):
        if tx.get("Account") != addr or tx.get("TransactionType") != "Payment":
            continue
        if tx.get("_meta", {}).get("TransactionResult") != "tesSUCCESS":
            continue
        te = _epoch_from_ripple(tx.get("date"))
        if after_epoch is not None and te is not None and te < after_epoch:
            continue
        amt = xrp(tx.get("_meta", {}).get("delivered_amount", tx.get("Amount")))
        if amt is None or amt < min_xrp:
            continue
        out.append({"hash": tx["hash"], "time": ripple_time(tx.get("date")), "epoch": te,
                    "from": addr, "to": tx.get("Destination"),
                    "destination_tag": tx.get("DestinationTag"), "xrp": amt})
    return out


async def map_network(root, max_depth=6, max_nodes=250, min_xrp=25,
                      root_after=None, use_xrpscan=True):
    """Build a time-forward stolen-funds graph rooted at `root` (the scam wallet).

    root_after: only follow the root's outgoing at/after this epoch. Default:
    follow all of the root's outgoing (the scam wallet only existed to receive
    and forward the stolen funds, so all its outgoing is in scope).
    """
    labels = load_labels()
    nodes, edges, endpoints = {}, [], []
    async with Ledger() as L:
        nodes[root] = await _describe(L, root, labels, use_xrpscan)
        nodes[root]["role"] = "scam wallet"
        # frontier holds (address, arrival_epoch, depth)
        frontier = [(root, root_after, 0)]
        seen = {root}
        while frontier and len(nodes) < max_nodes:
            addr, after, depth = frontier.pop(0)
            if depth >= max_depth:
                continue
            for p in await _outgoing_after(L, addr, after, min_xrp):
                dest = p["to"]
                if dest not in nodes:
                    nodes[dest] = await _describe(L, dest, labels, use_xrpscan)
                n = nodes[dest]
                edges.append({**p, "depth": depth + 1})
                if n["is_exchange"]:
                    n["role"] = ("bridge / swap (funds may leave XRPL)" if n.get("is_swap")
                                 else "exchange / cash-out point")
                    endpoints.append({"address": dest, "label": n["label"],
                                      "destination_tag": p["destination_tag"],
                                      "xrp": p["xrp"], "hash": p["hash"], "time": p["time"],
                                      "depth": depth + 1,
                                      "is_swap": n.get("is_swap"), "swap_name": n.get("swap_name")})
                elif dest not in seen:
                    n.setdefault("role", "hop wallet")
                    seen.add(dest)
                    # follow this hop's funds forward from when they arrived
                    frontier.append((dest, p["epoch"], depth + 1))
    hop_wallets = [a for a, n in nodes.items() if not n.get("is_exchange") and a != root]
    return {
        "root": root,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "params": {"max_depth": max_depth, "max_nodes": max_nodes, "min_xrp": min_xrp},
        "summary": {
            "total_nodes": len(nodes),
            "hop_wallets": len(hop_wallets),
            "cash_out_points": len({e["address"] for e in endpoints}),
            "edges": len(edges),
        },
        "watchlist": [root] + hop_wallets,   # non-exchange wallets to monitor live
        "nodes": nodes, "edges": edges, "endpoints": endpoints,
    }


# ---- persistence + rendering ---------------------------------------------

def save(net, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(net, f, indent=2, default=str)


def render_html(net):
    import html
    e = html.escape
    rows = ""
    for x in sorted(net["edges"], key=lambda z: z.get("epoch") or 0):
        dest = net["nodes"].get(x["to"], {})
        role = dest.get("role", "")
        tag = x.get("destination_tag")
        rows += (f"<tr><td>{x['depth']}</td><td>{e(x['time'])}</td><td class=m>{e(x['from'][:12])}…</td>"
                 f"<td class=m>{e((x['to'] or '')[:12])}…</td><td>{x['xrp']:,.2f}</td>"
                 f"<td>{e(str(tag) if tag is not None else '')}</td>"
                 f"<td>{e(dest.get('label') or role)}</td>"
                 f"<td class=m><a href='https://livenet.xrpl.org/transactions/{x['hash']}'>tx</a></td></tr>")
    exch = ""
    seen = set()
    for ep in net["endpoints"]:
        if ep["address"] in seen:
            continue
        seen.add(ep["address"])
        flag = " ⚠ bridge / swap — funds may leave XRPL" if ep.get("is_swap") else ""
        exch += (f"<li><b>{e(ep.get('label') or 'unlabeled custodial')}</b>{e(flag)} — <span class=m>{e(ep['address'])}</span>"
                 f" (first seen tag {e(str(ep.get('destination_tag')))})</li>")
    hops = ""
    for a in net["watchlist"]:
        n = net["nodes"].get(a, {})
        if a == net["root"]:
            continue
        hops += (f"<li class=m>{e(a)}</li>")
    s = net["summary"]
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Scam Network Map</title><style>
:root{{--bg:#fff;--fg:#16181d;--mut:#5b6170;--line:#e3e5ea;--acc:#0b63ce}}
@media(prefers-color-scheme:dark){{:root{{--bg:#111318;--fg:#e8eaf0;--mut:#9aa1b2;--line:#2a2e38;--acc:#5aa2ff}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:1000px;margin:0 auto;padding:16px}}
h1{{font-size:24px}} .k{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}}
.k div{{border:1px solid var(--line);border-radius:10px;padding:10px}} .k b{{display:block;font-size:20px}}
table{{width:100%;border-collapse:collapse;font-size:13px;display:block;overflow-x:auto}} td,th{{border-bottom:1px solid var(--line);padding:6px;text-align:left}}
.m{{font-family:ui-monospace,monospace;font-size:12px}} a{{color:var(--acc)}} small,.mut{{color:var(--mut)}}</style></head><body>
<h1>Scam Network Map</h1><p class=mut>Root: <span class=m>{e(net['root'])}</span> · generated {e(net['generated'])} · funds traced forward in time</p>
<div class=k><div>Nodes<b>{s['total_nodes']}</b></div><div>Hop wallets<b>{s['hop_wallets']}</b></div>
<div>Cash-out points<b>{s['cash_out_points']}</b></div><div>Flows<b>{s['edges']}</b></div></div>
<h2>Cash-out points (exchanges / custodial — where KYC records exist)</h2><ul>{exch or '<li>None reached yet.</li>'}</ul>
<h2>Fund flow (time-ordered)</h2><table><tr><th>Hop</th><th>Time</th><th>From</th><th>To</th><th>XRP</th><th>Tag</th><th>Destination</th><th></th></tr>{rows}</table>
<h2>Wallets being watched live</h2><ul>{hops or '<li>(root only)</li>'}</ul>
<p class=mut><small>Funds commingle at hubs, so downstream hops are investigative leads, not proof a later payment carries the stolen XRP. Shared cash-out hubs carry many unrelated users' funds; only flows at or after the stolen funds arrived are included.</small></p>
</body></html>"""
