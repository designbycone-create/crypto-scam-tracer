"""Group the network's wallets into OPERATOR groups (wallets one party controls).

Arkham's other half: not just "who is this exchange", but "these 14 wallets are
one operator". On the XRP Ledger the strongest free signals are:

  activation  - a private wallet that CREATED (first funded) other wallets.
                Scammers spin up throwaway wallets from a seed wallet.
  regular key - wallets that delegate signing to the same RegularKey are
                controlled by whoever holds that key (cryptographic link).
  domain      - wallets that set the same Domain field.

Exchanges, victim wallets and labeled services are never used as links (an
exchange "activates" thousands of unrelated customers).

    python -m scam_investigator.operators
Output: operators.json  {"groups": [{"id","wallets","links":[...]}], "wallet_group": {addr: id}}
Cached per wallet for 7 days; a full pass is ~2 RPC calls per wallet.
"""
import json
import time
from datetime import datetime

from .attribution import _rpc, activator, domain_of

OUT = "operators.json"
CACHE = "operators_cache.json"
TTL = 7 * 86400


def _j(p, d=None):
    try:
        with open(p, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return d if d is not None else {}


def _network():
    nodes, excluded, root = {}, set(), None
    for path in ("scam_network.json", "network_map.json"):
        d = _j(path)
        root = root or d.get("root")
        for a, n in d.get("nodes", {}).items():
            nodes.setdefault(a, n)
        excluded |= {e.get("address") for e in d.get("endpoints", [])}
    for a, n in nodes.items():
        role = str(n.get("role", ""))
        if n.get("label") or n.get("is_exchange") or any(w in role for w in ("exchange", "custodial", "swap", "victim")):
            excluded.add(a)
    return root, nodes, excluded


def facts(addr, _post=None):
    info = (_rpc("account_info", {"account": addr, "ledger_index": "validated"}, _post) or {}).get("account_data") or {}
    return {"activator": activator(addr, _post=_post), "regular_key": info.get("RegularKey"),
            "domain": domain_of(info), "ts": time.time()}


class _UF:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def run(log=print, max_wallets=250, pause=0.3, _post=None):
    root, nodes, excluded = _network()
    cache = _j(CACHE)
    wallets = [a for a in nodes if a not in excluded][:max_wallets]
    if root and root not in wallets:
        wallets.insert(0, root)
    for a in wallets:
        if time.time() - cache.get(a, {}).get("ts", 0) < TTL:
            continue
        try:
            cache[a] = facts(a, _post)
        except Exception as e:
            log(f"operators: {a[:10]}.. skipped ({e})")
            continue
        if pause:
            time.sleep(pause)
    with open(CACHE, "w", encoding="utf-8") as f:
        json.dump(cache, f)

    uf, links = _UF(), []
    by_key, by_dom = {}, {}
    for a in wallets:
        fct = cache.get(a) or {}
        act = fct.get("activator")
        if act and act not in excluded:
            uf.union(a, act)
            links.append({"a": act, "b": a, "why": "activation", "detail": f"{act[:8]}.. created {a[:8]}.."})
        if fct.get("regular_key"):
            by_key.setdefault(fct["regular_key"], []).append(a)
        if fct.get("domain"):
            by_dom.setdefault(fct["domain"], []).append(a)
    for k, ws in by_key.items():
        for w in ws[1:]:
            uf.union(ws[0], w)
            links.append({"a": ws[0], "b": w, "why": "regular_key", "detail": f"both signed by key {k[:10]}.."})
        if len(ws) == 1:
            uf.union(ws[0], k)
            links.append({"a": k, "b": ws[0], "why": "regular_key", "detail": f"signs for {ws[0][:8]}.."})
    for dmn, ws in by_dom.items():
        for w in ws[1:]:
            uf.union(ws[0], w)
            links.append({"a": ws[0], "b": w, "why": "domain", "detail": f"same Domain '{dmn}'"})

    members = {}
    for a in set(uf.p):
        members.setdefault(uf.find(a), set()).add(a)
    groups = []
    for rep, ws in members.items():
        if len(ws) < 2:
            continue
        ws = sorted(ws, key=lambda x: (x != root, x))
        groups.append({"wallets": ws, "links": [l for l in links if l["a"] in ws and l["b"] in ws],
                       "has_root": root in ws})
    groups.sort(key=lambda g: (not g["has_root"], -len(g["wallets"])))
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    wallet_group = {}
    for i, g in enumerate(groups):
        g["id"] = f"Operator {letters[i % 26]}{'' if i < 26 else i // 26}"
        g["name"] = g["id"] + (" (scam wallet's group)" if g["has_root"] else "")
        for w in g["wallets"]:
            wallet_group[w] = g["id"]
    out = {"built": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "wallets_checked": len(wallets),
           "groups": groups, "wallet_group": wallet_group}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    log(f"operators: {len(groups)} group(s) across {len(wallet_group)} wallet(s)")
    return out


def load():
    return _j(OUT)


if __name__ == "__main__":
    r = run()
    for g in r["groups"]:
        print(f"{g['name']}: {len(g['wallets'])} wallets")
        for l in g["links"][:8]:
            print(f"   {l['why']:11} {l['detail']}")
