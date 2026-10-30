"""Threat intel: flagged scam wallets and sites BEYOND your own case.

Pulls free, public, maintained datasets once a day into a local index the
whole Desk can check against (claim checker, graph, Intel page):

  ScamSniffer scam-database  addresses + phishing domains (GPL-3.0, 7-day delay)
  MetaMask eth-phishing-detect  phishing domains
  OFAC SDN crypto addresses  sanctioned wallets (BTC, ETH, TRX, ...)
  Your own cases              the scam network(s) and incident addresses you track

Plus on-demand links for any address: Chainabuse (TRM; note its public API
does not cover the XRP Ledger), Bithomp's XRPL fraud flags, explorers.
Data is fetched at runtime from the publishers and never redistributed here.

    python -m responder.intel refresh
    python -m responder.intel check <address-or-domain>
"""
import json
import os
import sys
import time
import urllib.request
from datetime import datetime

INDEX = "intel_index.json"
REFRESH = 24 * 3600
UA = {"User-Agent": "ScamHunter/1.0 (+https://github.com/designbycone-create/crypto-scam-tracer)"}

SOURCES = {
    "scamsniffer_addresses": {"name": "ScamSniffer address blacklist", "kind": "address",
        "url": "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json",
        "home": "https://github.com/scamsniffer/scam-database", "license": "GPL-3.0 (data, 7-day delay)"},
    "scamsniffer_domains": {"name": "ScamSniffer phishing domains", "kind": "domain",
        "url": "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json",
        "home": "https://github.com/scamsniffer/scam-database", "license": "GPL-3.0 (data, 7-day delay)"},
    "metamask_domains": {"name": "MetaMask phishing list", "kind": "domain",
        "url": "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json",
        "home": "https://github.com/MetaMask/eth-phishing-detect", "license": "see publisher"},
    "ofac_eth": {"name": "OFAC sanctioned (ETH/EVM)", "kind": "address",
        "url": "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.json",
        "home": "https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses", "license": "public (US Treasury)"},
    "ofac_btc": {"name": "OFAC sanctioned (BTC)", "kind": "address",
        "url": "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_XBT.json",
        "home": "https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses", "license": "public (US Treasury)"},
    "ofac_trx": {"name": "OFAC sanctioned (TRON)", "kind": "address",
        "url": "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_TRX.json",
        "home": "https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses", "license": "public (US Treasury)"},
}


def _fetch(url, _get=None):
    if _get:
        return _get(url)
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def _flatten(data, kind):
    """Pull address/domain strings out of whatever shape a list uses."""
    out = set()
    if isinstance(data, dict):
        if kind == "domain" and "blacklist" in data:      # MetaMask config.json
            data = data["blacklist"]
        else:
            data = list(data.keys()) + [v for v in data.values() if isinstance(v, (list, str))]
    stack = [data]
    while stack:
        x = stack.pop()
        if isinstance(x, str):
            s = x.strip()
            if s:
                out.add(s.lower() if (kind == "domain" or s.startswith("0x")) else s)
        elif isinstance(x, list):
            stack.extend(x)
        elif isinstance(x, dict):
            stack.extend(x.values())
    return out


def _own_case():
    out = {}
    for path in ("scam_network.json", "network_map.json"):
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            continue
        if d.get("root"):
            out[d["root"]] = "your case: scam wallet"
        for a, n in d.get("nodes", {}).items():
            role = str(n.get("role", ""))
            if "intermediate" in role or "hop" in role:
                out.setdefault(a, "your case: laundering wallet")
    try:
        from . import incident
        for r in incident.load()["addresses"]:
            k = r["address"].lower() if r["chain"] == "ethereum" else r["address"]
            out.setdefault(k, f"incident: {r.get('label') or 'attacker'}")
    except Exception:
        pass
    return out


def refresh(force=False, log=print, _get=None):
    idx = load()
    if not force and time.time() - idx.get("ts", 0) < REFRESH and idx.get("addresses"):
        return idx
    addresses, domains, meta = {}, {}, {}
    for key, src in SOURCES.items():
        try:
            items = _flatten(_fetch(src["url"], _get), src["kind"])
            bucket = addresses if src["kind"] == "address" else domains
            for it in items:
                bucket.setdefault(it, []).append(key)
            meta[key] = {**src, "count": len(items), "updated": datetime.now().strftime("%Y-%m-%d %H:%M"), "ok": True}
        except Exception as e:
            old = (idx.get("sources") or {}).get(key, {})
            meta[key] = {**src, "count": old.get("count", 0), "updated": old.get("updated"), "ok": False, "error": str(e)[:120]}
            for it, ks in (idx.get("addresses", {}) if src["kind"] == "address" else idx.get("domains", {})).items():
                if key in ks:
                    (addresses if src["kind"] == "address" else domains).setdefault(it, []).append(key)
            log(f"intel: {src['name']} unavailable ({e})")
    idx = {"ts": time.time(), "built": datetime.now().strftime("%Y-%m-%d %H:%M"), "sources": meta,
           "addresses": addresses, "domains": domains}
    tmp = INDEX + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(idx, f)
    os.replace(tmp, INDEX)
    log(f"intel: {len(addresses):,} flagged addresses, {len(domains):,} flagged domains")
    return idx


_cache = {"mtime": None, "idx": {}}


def load():
    try:
        m = os.path.getmtime(INDEX)
        if _cache["mtime"] != m:
            with open(INDEX, encoding="utf-8") as f:
                _cache["idx"] = json.load(f)
            _cache["mtime"] = m
        return _cache["idx"]
    except Exception:
        return {}


def check(q):
    """Look up an address or domain. Returns list of (source name, detail)."""
    q = (q or "").strip()
    if not q:
        return []
    idx = load()
    src = idx.get("sources", {})
    hits = []
    own = _own_case()
    key = q.lower() if (q.startswith("0x") or "." in q) else q
    if key in own:
        hits.append(("Your cases", own[key]))
    for s in idx.get("addresses", {}).get(key, []):
        hits.append((src.get(s, {}).get("name", s), "listed"))
    if "." in q:
        dom = key.replace("https://", "").replace("http://", "").split("/")[0]
        parts = dom.split(".")
        for i in range(len(parts) - 1):
            d = ".".join(parts[i:])
            for s in idx.get("domains", {}).get(d, []):
                hits.append((src.get(s, {}).get("name", s), f"domain {d} listed"))
    return hits


def links_for(q):
    q = (q or "").strip()
    out = [("Chainabuse reports", f"https://www.chainabuse.com/address/{q}")]
    if q.startswith("r"):
        out += [("Bithomp (fraud flags)", f"https://bithomp.com/explorer/{q}"),
                ("XRPScan", f"https://xrpscan.com/account/{q}")]
    elif q.startswith("0x"):
        out += [("Etherscan", f"https://etherscan.io/address/{q}")]
    elif q.startswith("T"):
        out += [("Tronscan", f"https://tronscan.org/#/address/{q}")]
    return out


if __name__ == "__main__":
    if sys.argv[1:2] == ["refresh"]:
        refresh(force=True)
    elif sys.argv[1:2] == ["check"] and len(sys.argv) > 2:
        print(check(sys.argv[2]) or "not found in any loaded list")
    else:
        print(__doc__)
