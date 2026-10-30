"""Interactive network graph for the Desk: /graph.

Builds the graph from the evidence map (scam_network.json), the freeze map
(network_map.json), attribution.json, operators.json and your recorded
cash-outs, and renders it with force-graph (canvas, animated money-flow
particles, operator-group halos, timeline replay). Template:
graph_template.html (data injected as JSON).
"""
import json
import math
import os
from datetime import datetime, timezone

MAX_NODES = 700
_TPL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "graph_template.html")


def _j(p):
    try:
        with open(p, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return {}


def _epoch(t):
    if not t:
        return None
    s = str(t).replace(" UTC", "").replace("T", " ").strip()[:19]
    try:
        return int(datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


def build():
    ev, fm, att, ops = _j("scam_network.json"), _j("network_map.json"), _j("attribution.json"), _j("operators.json")
    root = ev.get("root") or fm.get("root")
    yours_hash = set()
    try:
        with open("cashouts.jsonl", encoding="utf-8") as f:
            for line in f:
                try:
                    yours_hash.add(json.loads(line)["hash"])
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    try:   # cash-outs the live watcher logged before cashouts.jsonl existed
        import re
        with open("netwatch_events.log", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.search(r"(?:CASH-OUT|BRIDGE/SWAP): .*?tx ([0-9A-F]{64})", line)
                if m:
                    yours_hash.add(m.group(1))
    except FileNotFoundError:
        pass
    yours_hash |= {e.get("hash") for e in fm.get("edges", [])}
    nodes = {}
    for src in (ev, fm):
        for a, n in src.get("nodes", {}).items():
            nodes.setdefault(a, {}).update({k: v for k, v in n.items() if v not in (None, "")})
    eps = {}
    for src in (ev, fm):
        for e in src.get("endpoints", []):
            if not any(x.get("hash") == e.get("hash") for x in eps.get(e.get("address"), [])):
                eps.setdefault(e.get("address"), []).append(e)
    flows = {}
    for src in (ev, fm):
        for e in src.get("edges", []):
            if not e.get("from") or not e.get("to"):
                continue
            k = (e["from"], e["to"])
            f = flows.setdefault(k, {"xrp": 0.0, "n": 0, "yours": False, "t0": None, "t1": None, "hashes": set()})
            if e.get("hash") in f["hashes"]:
                continue
            f["hashes"].add(e.get("hash"))
            f["xrp"] += float(e.get("xrp") or 0)
            f["n"] += 1
            f["yours"] = f["yours"] or e.get("hash") in yours_hash
            t = e.get("epoch") if isinstance(e.get("epoch"), (int, float)) and e.get("epoch", 0) > 10**9 else _epoch(e.get("time"))
            if t:
                f["t0"] = min(f["t0"] or t, t)
                f["t1"] = max(f["t1"] or t, t)
    keep = {root} | set(eps) | {x for (a, b), f in flows.items() if f["yours"] for x in (a, b)}
    vol = {}
    for (a, b), f in flows.items():
        vol[a] = vol.get(a, 0) + f["xrp"]
        vol[b] = vol.get(b, 0) + f["xrp"]
    for a in sorted(vol, key=lambda x: -vol[x]):
        if len(keep) >= MAX_NODES:
            break
        keep.add(a)
    keep.discard(None)
    first_seen = {}
    for (x, y), f in flows.items():
        if f["t0"]:
            for a in (x, y):
                first_seen[a] = min(first_seen.get(a, f["t0"]), f["t0"])
    wg = ops.get("wallet_group", {})
    out_nodes = []
    for a in keep:
        n = nodes.get(a, {})
        at = att.get(a) or {}
        label = n.get("label") or (f"{at['name']}?" if at.get("name") and at.get("confidence") in ("verified", "likely") else "")
        role = str(n.get("role", ""))
        kind = ("root" if a == root else "exchange" if (a in eps or "exchange" in role or "custodial" in role)
                else "swap" if ("swap" in role or "bridge" in role) else "victim" if "victim" in role
                else "hub" if ("intermediate" in role or "consolidation" in role) else "wallet")
        dep = eps.get(a, [])
        first_in = first_seen.get(a)
        out_nodes.append({
            "id": a, "name": label or ("SCAM WALLET" if a == root else ""), "kind": kind, "role": role,
            "bal": n.get("balance_xrp"), "vol": round(vol.get(a, 0), 2), "group": wg.get(a),
            "yours": any(d.get("hash") in yours_hash for d in dep),
            "deps": [{"tag": d.get("destination_tag"), "xrp": d.get("xrp"), "time": d.get("time"),
                      "hash": d.get("hash"), "yours": d.get("hash") in yours_hash} for d in dep[:40]],
            "ndeps": len(dep), "att": at or None, "t": first_in,
            "r": 3 + min(14, 2.4 * math.log10(1 + vol.get(a, 0))),
        })
    links = [{"source": a, "target": b, "xrp": round(f["xrp"], 2), "n": f["n"], "yours": f["yours"],
              "t0": f["t0"], "t1": f["t1"]}
             for (a, b), f in flows.items() if a in keep and b in keep]
    # ---- other chains (multi-chain tracer) ----
    mc = _j("mc_map.json")
    cfg = _j("config.json")
    seeds = {(c["chain"], c["address"].lower()) for c in cfg.get("cases") or [] if c.get("chain") != "xrpl"}
    if mc.get("edges"):
        evm = {"ethereum", "bsc", "polygon", "arbitrum", "base", "optimism", "avalanche"}
        if any(c in evm for c, _ in seeds):
            seeds |= {(k, a) for c, a in list(seeds) if c in evm for k in evm}
        adj = {}
        for e in mc["edges"]:
            adj.setdefault((e.get("chain"), str(e.get("from")).lower()), []).append((e.get("chain"), str(e.get("to")).lower()))
        reach, stack = set(), list(seeds)
        while stack:
            x = stack.pop()
            if x not in reach:
                reach.add(x)
                stack += adj.get(x, [])
        nid = lambda c, a: f"{c}:{a}"
        mvol, mflows = {}, {}
        for e in mc["edges"]:
            c, a, b = e.get("chain"), e.get("from"), e.get("to")
            k = (nid(c, a), nid(c, b))
            f = mflows.setdefault(k, {"amt": {}, "n": 0, "t0": None, "yours": False})
            f["amt"][e.get("asset")] = f["amt"].get(e.get("asset"), 0) + float(e.get("amount") or 0)
            f["n"] += 1
            t = e.get("epoch")
            if t:
                f["t0"] = min(f["t0"] or t, t)
            f["yours"] = f["yours"] or (c, str(a).lower()) in reach
            for x in k:
                mvol[x] = mvol.get(x, 0) + 1
        for key, n in mc.get("nodes", {}).items():
            c, a = n.get("chain"), n.get("address")
            k = nid(c, a)
            if k not in mvol and (c, str(a).lower()) not in seeds:
                continue
            typ = n.get("type", "wallet")
            kind = ("root" if (c, str(a).lower()) in seeds else "exchange" if typ == "exchange"
                    else "swap" if typ == "bridge" else "hub" if typ == "mixer" else "wallet")
            out_nodes.append({"id": k, "name": n.get("label") or ("SCAM WALLET" if kind == "root" else ""),
                              "kind": kind, "role": f"{c} · {n.get('role', '')}", "bal": None, "vol": mvol.get(k, 0),
                              "group": None, "yours": kind == "exchange" and (c, str(a).lower()) in reach,
                              "deps": [], "ndeps": 0, "att": None, "chain": c,
                              "t": min([f["t0"] for (x, y), f in mflows.items() if k in (x, y) and f["t0"]] or [0]) or None,
                              "r": 4 + min(10, 2 * math.log2(1 + mvol.get(k, 0)))})
        ids = {n["id"] for n in out_nodes}
        for (a, b), f in mflows.items():
            if a in ids and b in ids:
                links.append({"source": a, "target": b, "xrp": round(sum(f["amt"].values()), 4), "n": f["n"],
                              "yours": f["yours"], "t0": f["t0"], "t1": f["t0"],
                              "label": " + ".join(f"{v:,.4f}".rstrip("0").rstrip(".") + f" {k}" for k, v in f["amt"].items())})
    groups = [{"id": g["id"], "name": g.get("name", g["id"]), "size": len(g["wallets"]),
               "links": g.get("links", [])[:30]} for g in ops.get("groups", [])]
    all_n = set(nodes) | set(eps) | {a for k in flows for a in k}
    stats = {"wallets": len(all_n) + sum(1 for n in out_nodes if n.get("chain")), "shown": len(out_nodes),
             "chains": len({n.get("chain") or "xrpl" for n in out_nodes}),
             "xrpl": any(not n.get("chain") for n in out_nodes),
             "mc_cashouts": sum(1 for n in out_nodes if n.get("chain") and n["kind"] in ("exchange", "swap")),
             "to_exchanges": round(sum(float(e.get("xrp") or 0) for v in eps.values() for e in v)),
             "cashout_points": len(eps), "operators": len(groups),
             "yours": round(sum(float(e.get("xrp") or 0) for v in eps.values() for e in v if e.get("hash") in yours_hash))}
    return {"root": root, "nodes": out_nodes, "links": links, "groups": groups, "stats": stats,
            "built": datetime.now().strftime("%Y-%m-%d %H:%M")}


def render():
    with open(_TPL, encoding="utf-8") as f:
        tpl = f.read()
    return tpl.replace("__GRAPH_DATA__", json.dumps(build()).replace("</", "<\\/"))
