"""Who is behind an unlabeled XRPL account? Free attribution, no paid data.

For every cash-out point the explorers couldn't name, gather evidence from the
public ledger and the web, and grade it:

  verified   the account's Domain field names a site whose
             /.well-known/xrp-ledger.toml lists this address (two-way proof,
             the XRPL standard for "this account belongs to us")
  likely     strong behavior: most of its outgoing XRP sweeps into ONE labeled
             exchange, or it was activated by a labeled exchange AND requires
             destination tags; or Bithomp has a username for it
  hint       weaker clues worth showing an officer (claimed domain without a
             toml, custodial flags, heavy fan-in)

    python -m scam_investigator.attribution          # attribute all unknowns now
Output: attribution.json, cached 7 days per address. Bithomp (optional): put a
free non-commercial key in config.json "bithomp_token" (5 req/min; we pace it).
Nothing here ever relabels a wallet silently: every claim carries its evidence.
"""
import json
import time
import urllib.request
from collections import Counter
from datetime import datetime

OUT = "attribution.json"
TTL = 7 * 86400
LSF_REQUIRE_DEST_TAG = 0x00020000
# Full-history public servers first (free; Ripple runs s2 as full history).
RPC = ["https://s2.ripple.com:51234/", "https://xrplcluster.com/", "https://s1.ripple.com:51234/"]
UA = {"User-Agent": "ScamHunter/1.0 (+https://github.com/designbycone-create/crypto-scam-tracer)"}


def _rpc(method, params, _post=None):
    if _post:
        return _post(method, params)
    body = json.dumps({"method": method, "params": [params]}).encode()
    last = None
    for url in RPC:
        try:
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", **UA})
            with urllib.request.urlopen(req, timeout=20) as r:
                res = json.loads(r.read()).get("result", {})
            if res.get("status") == "error" and res.get("error") != "actNotFound":
                last = res.get("error")
                continue
            return res
        except Exception as e:
            last = e
    raise ConnectionError(f"XRPL RPC failed: {last}")


def _http_text(url, limit=200_000, _get=None):
    if _get:
        return _get(url)
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read(limit).decode("utf-8", "replace")


# ---------------------------------------------------------------- domain ----

def domain_of(info):
    d = (info or {}).get("Domain")
    if not d:
        return None
    try:
        return bytes.fromhex(d).decode("utf-8", "replace").strip().lower().rstrip("/")
    except ValueError:
        return None


def toml_lists(domain, addr, _get=None):
    """True if https://<domain>/.well-known/xrp-ledger.toml lists addr."""
    host = domain.replace("https://", "").replace("http://", "").split("/")[0]
    if not host or "." not in host:
        return False
    try:
        txt = _http_text(f"https://{host}/.well-known/xrp-ledger.toml", _get=_get)
    except Exception:
        return False
    return addr in txt


# -------------------------------------------------------------- behavior ----

def outflows(addr, limit=200, _post=None):
    """Recent outgoing XRP payments: [(destination, xrp)]."""
    r = _rpc("account_tx", {"account": addr, "ledger_index_min": -1, "ledger_index_max": -1,
                            "limit": limit, "forward": False}, _post)
    out = []
    for t in r.get("transactions", []):
        tx = t.get("tx_json") or t.get("tx") or {}
        meta = t.get("meta") or {}
        if tx.get("TransactionType") != "Payment" or tx.get("Account") != addr:
            continue
        amt = meta.get("delivered_amount", tx.get("Amount"))
        if isinstance(amt, str) and meta.get("TransactionResult") == "tesSUCCESS":
            out.append((tx.get("Destination"), int(amt) / 1e6))
    return out


def activator(addr, _post=None):
    r = _rpc("account_tx", {"account": addr, "ledger_index_min": -1, "ledger_index_max": -1,
                            "limit": 5, "forward": True}, _post)
    for t in r.get("transactions", []):
        tx = t.get("tx_json") or t.get("tx") or {}
        if tx.get("TransactionType") == "Payment" and tx.get("Destination") == addr:
            return tx.get("Account")
    return None


def _known_labels():
    """address -> label from everything we already know (maps + labels.json + cache)."""
    k = {}
    for path in ("scam_network.json", "network_map.json"):
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            for a, n in d.get("nodes", {}).items():
                if n.get("label"):
                    k[a] = n["label"]
            for e in d.get("endpoints", []):
                if e.get("label"):
                    k.setdefault(e.get("address"), e["label"])
        except Exception:
            pass
    try:
        from .trace import load_labels
        k.update({a: v for a, v in load_labels().items() if not a.startswith("_")})
    except Exception:
        pass
    return k


def _xrpscan(addr):
    try:
        from .trace import xrpscan_name
        n, d = xrpscan_name(addr)
        return f"{n} {('(' + d + ')') if d else ''}".strip() if n else None
    except Exception:
        return None


def _bithomp(addr, token):
    req = urllib.request.Request(f"https://bithomp.com/api/v2/address/{addr}?username=true&service=true",
                                 headers={"x-bithomp-token": token, **UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        d = json.loads(r.read())
    svc = d.get("service") or {}
    return (svc.get("name") if isinstance(svc, dict) else None) or d.get("username")


def _brand(label):
    """'Binance (11)' -> 'Binance'."""
    return (label or "").split("(")[0].strip()


# ---------------------------------------------------------------- attribute --

def attribute(addr, known=None, bithomp_token=None, _post=None, _get=None, label_lookup=None):
    known = known if known is not None else _known_labels()
    look = label_lookup or (lambda a: known.get(a) or _xrpscan(a))
    ev, name, conf = [], None, None
    info = (_rpc("account_info", {"account": addr, "ledger_index": "validated"}, _post) or {}).get("account_data") or {}
    flags = int(info.get("Flags") or 0)
    custodial = bool(flags & LSF_REQUIRE_DEST_TAG)
    if custodial:
        ev.append("requires a destination tag (custodial: one wallet, many customer accounts)")

    dom = domain_of(info)
    if dom:
        if toml_lists(dom, addr, _get):
            name, conf = dom, "verified"
            ev.append(f"Domain field '{dom}' and {dom}/.well-known/xrp-ledger.toml lists this address (two-way verified)")
        else:
            ev.append(f"Domain field claims '{dom}' (not confirmed by an xrp-ledger.toml)")
            name, conf = dom, "hint"

    if bithomp_token and conf != "verified":
        try:
            b = _bithomp(addr, bithomp_token)
            time.sleep(12.5)          # free tier: 5 req/min
            if b:
                name, conf = b, "likely"
                ev.append(f"Bithomp names this account '{b}'")
        except Exception as e:
            ev.append(f"(Bithomp lookup failed: {str(e)[:60]})")

    try:
        outs = outflows(addr, _post=_post)
    except Exception:
        outs = []
    if outs:
        total = sum(x for _, x in outs) or 1
        by_dest = Counter()
        for d, x in outs:
            by_dest[d] += x
        dest, amt = by_dest.most_common(1)[0]
        share = amt / total
        dl = look(dest)
        if dl and share >= 0.6 and conf not in ("verified", "likely"):
            name, conf = _brand(dl), "likely"
            ev.append(f"sweeps {share:.0%} of its outgoing XRP ({amt:,.0f} of {total:,.0f}) to {dl} ({dest})")
        elif dl:
            ev.append(f"largest outflow destination: {dl} ({share:.0%})")
        ev.append(f"{len(by_dest)} distinct destinations in last {len(outs)} outgoing payments")

    try:
        act = activator(addr, _post=_post)
    except Exception:
        act = None
    if act:
        al = look(act)
        if al:
            ev.append(f"activated (first funded) by {al} ({act})")
            if custodial and conf is None:
                name, conf = _brand(al), "likely"
        else:
            ev.append(f"activated by {act}")

    if name and conf is None:
        conf = "hint"
    return {"address": addr, "name": name, "confidence": conf or "unknown", "evidence": ev,
            "checked": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "ts": time.time()}


def load():
    try:
        with open(OUT, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def unknowns():
    """Cash-out points (and custodial nodes) that no explorer could name."""
    out = []
    for path in ("network_map.json", "scam_network.json"):
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            continue
        for ep in d.get("endpoints", []):
            if not ep.get("label") and ep.get("address") not in out:
                out.append(ep["address"])
    return out


def run(addresses=None, log=print, _post=None, _get=None, pause=0.5):
    try:
        import scamconfig
        token = (scamconfig.get("bithomp_token") or "").strip()
    except Exception:
        token = ""
    cache = load()
    known = _known_labels()
    todo = [a for a in (addresses or unknowns()) if time.time() - cache.get(a, {}).get("ts", 0) > TTL]
    for a in todo:
        try:
            cache[a] = attribute(a, known, token or None, _post=_post, _get=_get)
            r = cache[a]
            log(f"attribution: {a[:10]}.. -> {r['name'] or '?'} [{r['confidence']}]")
        except Exception as e:
            log(f"attribution: {a[:10]}.. failed ({e})")
        if pause:
            time.sleep(pause)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=1)
    return cache


if __name__ == "__main__":
    res = run()
    for a, r in res.items():
        print(f"{r['confidence']:9} {a}  {r['name'] or ''}")
        for e in r["evidence"]:
            print(f"            - {e}")
