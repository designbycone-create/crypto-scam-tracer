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
    groups = [{"id": g["id"], "name": g.get("name", g["id"]), "size": len(g["wallets"]),
               "links": g.get("links", [])[:30]} for g in ops.get("groups", [])]
    all_n = set(nodes) | set(eps) | {a for k in flows for a in k}
    stats = {"wallets": len(all_n), "shown": len(out_nodes),
             "to_exchanges": round(sum(float(e.get("xrp") or 0) for v in eps.values() for e in v)),
             "cashout_points": len(eps), "operators": len(groups),
             "yours": round(sum(float(e.get("xrp") or 0) for v in eps.values() for e in v if e.get("hash") in yours_hash))}
    return {"root": root, "nodes": out_nodes, "links": links, "groups": groups, "stats": stats,
            "built": datetime.now().strftime("%Y-%m-%d %H:%M")}


def render():
    with open(_TPL, encoding="utf-8") as f:
        tpl = f.read()
    return tpl.replace("__GRAPH_DATA__", json.dumps(build()).replace("</", "<\\/"))
