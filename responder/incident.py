"""Incident mode: respond to a hack or a new scam fast.

    python -m responder.incident add "paste text with addresses..." --label "Exchange X hack"
    python -m responder.incident list
    python -m responder.incident feeds     # pull addresses from configured public feeds

Pasted text can be anything (a tweet, an incident post, a list): addresses are
extracted with checksum validation.
  * XRPL addresses go into incident.json; the wallet watcher picks them up on
    its next restart and alerts the moment any of them sends to an exchange
    (destination tag) -- critical alert to every channel.
  * Other chains (ETH/EVM, Tron, Bitcoin) are added as seeds of the multi-chain
    tracer, which follows them and drafts issuer/exchange freeze requests.

Public feeds: list URLs of plain-text / JSON address lists in config.json
"incident_feeds": ["https://.../addresses.txt"]. Every address found is added
with the feed URL as its source.
"""
import argparse
import json
import os
import time
import urllib.request
from datetime import datetime

from .addresses import extract

FILE = "incident.json"
MC_MAP = "mc_map.json"


def load():
    try:
        with open(FILE, encoding="utf-8-sig") as f:
            d = json.load(f)
    except Exception:
        d = {}
    d.setdefault("addresses", [])
    d.setdefault("incidents", [])
    return d


def save(d):
    tmp = FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=1)
    os.replace(tmp, FILE)


def xrpl_watch_list():
    """{address: label} for the wallet watcher."""
    return {a["address"]: f"INCIDENT: {a.get('label') or 'attacker'}"
            for a in load()["addresses"] if a["chain"] == "xrpl" and a.get("active", True)}


def _seed_multichain(chain, addr, after_epoch=None):
    try:
        with open(MC_MAP, encoding="utf-8") as f:
            m = json.load(f)
    except Exception:
        m = {"nodes": {}, "edges": [], "endpoints": [], "handoffs": [], "freeze_ops": [], "seeds": []}
    seeds = m.setdefault("seeds", [])
    if any(s[0] == chain and str(s[1]).lower() == addr.lower() for s in seeds):
        return False
    seeds.append([chain, addr, after_epoch])
    tmp = MC_MAP + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(m, f, indent=2, default=str)
    os.replace(tmp, MC_MAP)
    return True


def add(text, label="", source="pasted", since_hours=72):
    """Extract + register addresses. Returns list of newly added (chain, address)."""
    d = load()
    have = {(a["chain"], a["address"].lower()) for a in d["addresses"]}
    found = extract(text)
    new = []
    after = int(time.time() - since_hours * 3600) if since_hours else None
    for chain, addr in found:
        if (chain, addr.lower()) in have:
            continue
        rec = {"chain": chain, "address": addr, "label": label, "source": source,
               "added": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "active": True}
        d["addresses"].append(rec)
        if chain != "xrpl":
            rec["seeded_multichain"] = _seed_multichain(chain, addr, after)
        new.append((chain, addr))
    if label and label not in [i["label"] for i in d["incidents"]]:
        d["incidents"].append({"label": label, "opened": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    save(d)
    return new


def pull_feeds(log=print):
    try:
        import scamconfig
        feeds = scamconfig.get("incident_feeds") or []
    except Exception:
        feeds = []
    total = []
    for url in feeds:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ScamHunter/1.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
                text = r.read(5_000_000).decode("utf-8", "replace")
            new = add(text, label=f"feed: {url[:60]}", source=url)
            if new:
                log(f"incident feed {url[:60]}: +{len(new)} address(es)")
            total += new
        except Exception as e:
            log(f"incident feed {url[:60]} failed: {e}")
    return total


def main():
    p = argparse.ArgumentParser(prog="responder.incident")
    sub = p.add_subparsers(dest="cmd", required=True)
    a_ = sub.add_parser("add")
    a_.add_argument("text")
    a_.add_argument("--label", default="")
    sub.add_parser("list")
    sub.add_parser("feeds")
    a = p.parse_args()
    if a.cmd == "add":
        new = add(a.text, a.label)
        print(f"Added {len(new)} address(es):")
        for c, x in new:
            print(f"  {c:9} {x}")
        if any(c == "xrpl" for c, _ in new):
            print("XRPL addresses are watched after the Desk restarts the wallet watcher (automatic within ~1 min).")
    elif a.cmd == "list":
        for r in load()["addresses"]:
            print(f"  {r['chain']:9} {r['address']}  {r.get('label', '')}")
    else:
        print(f"{len(pull_feeds())} new address(es) from feeds")


if __name__ == "__main__":
    main()
