"""Full-network intelligence + evidence record for a law-enforcement handoff.

This is the EVIDENCE side of the tool (distinct from the victim/freeze side).
It traces the entire downstream network behind the scam wallet -- every wallet
the scam wallet feeds, and every exchange / custodial service those wallets
deposit to -- and accumulates it over time into a record that only grows. The
wallets that receive from a scam wallet and fan funds out to many exchange
deposits are the laundering layer of the operation; this documents them.

Outputs (all in the working directory):
  * scam_network.json  -- the accumulated graph (machine-readable)
  * scam_network.html  -- a human-readable evidence map
  * ic3_evidence.txt   -- a plain-text summary to attach to an IC3 complaint /
                          send to an exchange's law-enforcement desk
  * network_intel.heartbeat -- touched each cycle (liveness)

Run once, or as a loop (the Desk runs it as a loop):
    python -m scam_investigator.network_intel [--once] [--interval 900]
"""
import argparse
import asyncio
import html
import json
import os
from datetime import datetime, timezone

from .trace import trace
from .netreport import load_case

try:
    import scamconfig
except Exception:
    scamconfig = None

NET_JSON = "scam_network.json"
NET_HTML = "scam_network.html"
IC3_FILE = "ic3_evidence.txt"
HEARTBEAT = "network_intel.heartbeat"


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _scam_wallet():
    if scamconfig:
        w = scamconfig.scam_wallet()
        if w:
            return w
    return os.environ.get("SCAM_WALLET", "").strip()


def _theft_epoch(case):
    """Optional reference time (unix) for post-theft tagging. From config
    'theft_epoch', or None (the evidence record is shown in full either way)."""
    if scamconfig and scamconfig.get("theft_epoch"):
        try:
            return int(scamconfig.get("theft_epoch"))
        except Exception:
            return None
    return None


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def merge(old, new):
    """Union two network snapshots so the record only ever grows."""
    if not old:
        return new
    nodes = dict(old.get("nodes", {}))
    for a, n in new.get("nodes", {}).items():
        if a not in nodes or (not nodes[a].get("label") and n.get("label")):
            nodes[a] = n
    edges = {e.get("hash"): e for e in old.get("edges", []) if e.get("hash")}
    for e in new.get("edges", []):
        if e.get("hash"):
            edges[e["hash"]] = e
    eps = {(e["address"], e.get("hash")): e for e in old.get("endpoints", [])}
    for e in new.get("endpoints", []):
        eps[(e["address"], e.get("hash"))] = e
    return {"start": new.get("start") or old.get("start"), "nodes": nodes,
            "edges": list(edges.values()), "endpoints": list(eps.values()),
            "victim_sources": new.get("victim_sources") or old.get("victim_sources", {}),
            "incoming": new.get("incoming") or old.get("incoming", [])}


def _stats(net):
    nodes = net.get("nodes", {})
    exch = {e["address"] for e in net.get("endpoints", [])}
    hubs = [a for a, n in nodes.items()
            if n.get("role", "").startswith("intermediate")]
    return {"wallets": len(nodes), "exchange_points": len(exch),
            "consolidation_wallets": len(hubs), "flows": len(net.get("edges", [])),
            "exchanges": sorted({(e.get("label") or "unlabeled").split("(")[0].strip()
                                 for e in net.get("endpoints", [])})}


async def build(scam_wallet, theft_epoch, max_depth=4, min_xrp=25, max_nodes=500):
    return await trace(scam_wallet, max_depth=max_depth, min_xrp=min_xrp,
                       use_xrpscan=True, time_forward=False, theft_epoch=theft_epoch,
                       max_nodes=max_nodes)


def render_html(net):
    e = html.escape
    s = _stats(net)
    exrows = ""
    seen = set()
    for ep in sorted(net.get("endpoints", []), key=lambda z: -(z.get("xrp") or 0)):
        if ep["address"] in seen:
            continue
        seen.add(ep["address"])
        exrows += (f"<tr><td><b>{e(ep.get('label') or 'unlabeled custodial')}</b></td>"
                   f"<td class=m>{e(ep['address'])}</td><td>{e(str(ep.get('destination_tag')))}</td></tr>")
    flows = ""
    for x in sorted(net.get("edges", []), key=lambda z: z.get("epoch") or 0):
        dest = net["nodes"].get(x["to"], {})
        flows += (f"<tr><td>{x.get('depth')}</td><td>{e(x.get('time') or '')}</td>"
                  f"<td class=m>{e((x.get('from') or '')[:14])}</td>"
                  f"<td class=m>{e((x.get('to') or '')[:14])}</td>"
                  f"<td>{(x.get('xrp') or 0):,.2f}</td><td>{e(str(x.get('destination_tag') or ''))}</td>"
                  f"<td>{e(dest.get('label') or dest.get('role') or '')}</td>"
                  f"<td class=m><a href='https://livenet.xrpl.org/transactions/{e(x.get('hash',''))}'>tx</a></td></tr>")
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Scam Network — Evidence Record</title><style>
:root{{--bg:#fff;--fg:#16181d;--mut:#5b6170;--line:#e3e5ea;--acc:#0b63ce}}
@media(prefers-color-scheme:dark){{:root{{--bg:#111318;--fg:#e8eaf0;--mut:#9aa1b2;--line:#2a2e38;--acc:#5aa2ff}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:1040px;margin:0 auto;padding:16px}}
h1{{font-size:23px}} h2{{font-size:16px;margin-top:24px}}
.k{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}}
.k div{{border:1px solid var(--line);border-radius:10px;padding:10px}} .k b{{display:block;font-size:22px}}
table{{width:100%;border-collapse:collapse;font-size:13px;display:block;overflow-x:auto}} td,th{{border-bottom:1px solid var(--line);padding:6px;text-align:left}}
.m{{font-family:ui-monospace,monospace;font-size:12px}} a{{color:var(--acc)}} .mut{{color:var(--mut)}}</style></head><body>
<h1>Scam Network — Evidence Record</h1>
<p class=mut>Root scam wallet <span class=m>{e(net.get('start',''))}</span> · generated {e(_now())} · accumulated over time · all data public &amp; verifiable on the XRP Ledger</p>
<div class=k><div>Wallets in network<b>{s['wallets']}</b></div><div>Exchange deposit points<b>{s['exchange_points']}</b></div>
<div>Consolidation wallets<b>{s['consolidation_wallets']}</b></div><div>Traced flows<b>{s['flows']}</b></div></div>
<h2>Exchanges / custodial services this network uses (KYC records exist here)</h2>
<table><tr><th>Platform</th><th>Deposit address</th><th>Dest. tag</th></tr>{exrows or '<tr><td colspan=3>None mapped yet.</td></tr>'}</table>
<h2>Full flow log (time-ordered)</h2>
<table><tr><th>Hop</th><th>Time</th><th>From</th><th>To</th><th>XRP</th><th>Tag</th><th>Destination</th><th></th></tr>{flows}</table>
<p class=mut><small>These wallets received value originating from the scam wallet and relayed it onward, in many cases to custodial exchanges. This is the laundering network behind the fraud. Downstream amounts commingle at shared wallets; a specific later transfer is a lead, not proof it carries one particular victim's funds.</small></p>
</body></html>"""


def export_ic3(net, case):
    s = _stats(net)
    lines = []
    lines.append("CRYPTOCURRENCY FRAUD - ON-CHAIN EVIDENCE RECORD (XRP Ledger)")
    lines.append("Generated: " + _now())
    lines.append("Root scam receiving wallet: " + net.get("start", ""))
    refs = []
    if case.get("ic3_id"):
        refs.append("FBI IC3 complaint " + str(case["ic3_id"]))
    for r in case.get("reports", []):
        if "chainabuse" in str(r).lower():
            refs.append(str(r))
    if refs:
        lines.append("Case references: " + "; ".join(refs))
    if case.get("tx_hash"):
        lines.append("Documented victim transaction: " + str(case["tx_hash"]))
    lines.append("")
    lines.append("NETWORK SUMMARY")
    lines.append(f"  Wallets in network:            {s['wallets']}")
    lines.append(f"  Exchange/custodial deposits:   {s['exchange_points']}")
    lines.append(f"  Consolidation (layer) wallets: {s['consolidation_wallets']}")
    lines.append(f"  Traced flows:                  {s['flows']}")
    lines.append("")
    lines.append("EXCHANGE / CUSTODIAL DEPOSIT POINTS (platforms that hold KYC on the recipient):")
    seen = set()
    for ep in sorted(net.get("endpoints", []), key=lambda z: -(z.get("xrp") or 0)):
        key = (ep["address"], ep.get("destination_tag"))
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"  {ep.get('label') or 'unlabeled custodial'} | address {ep['address']} | "
                     f"dest tag {ep.get('destination_tag')} | {(ep.get('xrp') or 0):,.6f} XRP | "
                     f"{ep.get('time')} | tx {ep.get('hash')}")
    lines.append("")
    lines.append("INTERMEDIARY / CONSOLIDATION WALLETS (the laundering layer):")
    for a, n in net.get("nodes", {}).items():
        if n.get("role", "").startswith("intermediate"):
            lines.append(f"  {a} | balance {n.get('balance_xrp')} XRP"
                         + (f" | label {n['label']}" if n.get("label") else ""))
    lines.append("")
    lines.append("FULL FLOW LOG (time-ordered):")
    for x in sorted(net.get("edges", []), key=lambda z: z.get("epoch") or 0):
        lines.append(f"  {x.get('time')} | depth {x.get('depth')} | {x.get('from')} -> {x.get('to')} | "
                     f"{(x.get('xrp') or 0):,.6f} XRP | tag {x.get('destination_tag')} | tx {x.get('hash')}")
    lines.append("")
    lines.append("All transactions above are public and independently verifiable on the XRP Ledger "
                 "(https://livenet.xrpl.org). Prepared by a documented victim of the fraud; identity on "
                 "record with the FBI / IC3. The wallets listed received value traceable to the scam "
                 "wallet and relayed it onward; the exchange deposit points are where the operation "
                 "converted stolen funds at platforms that retain customer identity records.")
    return "\n".join(lines)


def _save(net, case, log):
    with open(NET_JSON, "w", encoding="utf-8") as f:
        json.dump(net, f, indent=2, default=str)
    with open(NET_HTML, "w", encoding="utf-8") as f:
        f.write(render_html(net))
    with open(IC3_FILE, "w", encoding="utf-8") as f:
        f.write(export_ic3(net, case))
    try:
        with open(HEARTBEAT, "w", encoding="utf-8") as f:
            f.write(_now())
    except Exception:
        pass


def run_once(log=print):
    scam = _scam_wallet()
    if not scam:
        log("No scam wallet configured (set scam_wallet in config.json).")
        return None
    case = load_case()
    net_new = asyncio.run(build(scam, _theft_epoch(case)))
    merged = merge(_load(NET_JSON), net_new)
    before = len((_load(NET_JSON) or {}).get("nodes", {}))
    _save(merged, case, log)
    s = _stats(merged)
    grew = s["wallets"] - before
    log(f"[{_now()}] network: {s['wallets']} wallets ({'+' + str(grew) if grew else 'no new'}), "
        f"{s['exchange_points']} exchange points, {s['flows']} flows"
        + (f"  | exchanges: {', '.join(x for x in s['exchanges'] if x)[:120]}" if s['exchanges'] else ""))
    return merged


def main():
    ap = argparse.ArgumentParser(prog="network_intel")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--interval", type=int, default=900)
    a = ap.parse_args()
    print("Scam-network evidence mapper.", flush=True)
    import time
    while True:
        try:
            run_once()
        except Exception as ex:
            print(f"[{_now()}] mapper error: {ex!r}", flush=True)
        if a.once:
            break
        time.sleep(max(120, a.interval))


if __name__ == "__main__":
    main()
