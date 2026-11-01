"""Same-day list of hijacked / drainer domains and drainer addresses.

Public lists lag (ScamSniffer's free data is 7 days behind). When an incident
post names compromised sites ("12 DeFi front-ends serving Step Drainer"),
paste it here and every Desk check flags those domains immediately.

    python -m shield.compromised add "pickle.finance, flap.sh ..." --label "Step Drainer, Oct 30"
"""
import json
import os
import re
import sys
from datetime import datetime

FILE = "compromised.json"
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
_SKIP = {"x.com", "twitter.com", "t.co", "theblock.co", "github.com", "medium.com"}


def load():
    try:
        with open(FILE, encoding="utf-8-sig") as f:
            d = json.load(f)
    except Exception:
        d = {}
    d.setdefault("domains", {})
    d.setdefault("addresses", {})
    return d


def save(d):
    tmp = FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=1)
    os.replace(tmp, FILE)


def add(text, label="", source="pasted"):
    """Extract domains (and EVM/other addresses) from text. Returns (new_domains, new_addresses)."""
    d = load()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    nd, na = [], []
    for m in _DOMAIN.finditer(text or ""):
        dom = m.group(0).lower().strip(".")
        if dom in _SKIP or dom.replace(".", "").isdigit():
            continue
        if dom not in d["domains"]:
            d["domains"][dom] = {"label": label, "added": now, "source": source, "status": "compromised"}
            nd.append(dom)
    try:
        from responder.addresses import extract
        for chain, a in extract(text or ""):
            k = a.lower() if a.startswith("0x") else a
            if k not in d["addresses"]:
                d["addresses"][k] = {"chain": chain, "label": label, "added": now, "source": source}
                na.append(a)
    except Exception:
        pass
    save(d)
    return nd, na


def mark_clean(domain, note="team confirmed clean"):
    d = load()
    if domain in d["domains"]:
        d["domains"][domain].update({"status": "cleared", "cleared": datetime.now().strftime("%Y-%m-%d %H:%M"), "note": note})
        save(d)


def check_domain(q):
    dom = (q or "").lower().replace("https://", "").replace("http://", "").split("/")[0].strip(".")
    d = load()["domains"]
    parts = dom.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in d and d[cand].get("status") == "compromised":
            v = d[cand]
            return f"{cand} reported compromised ({v.get('label') or 'incident'}, added {v.get('added')})"
    return None


def check_address(a):
    v = load()["addresses"].get(a.lower() if a.startswith("0x") else a)
    return f"listed in incident '{v.get('label') or 'incident'}' ({v.get('added')})" if v else None


if __name__ == "__main__":
    if sys.argv[1:2] == ["add"]:
        lbl = sys.argv[sys.argv.index("--label") + 1] if "--label" in sys.argv else ""
        print(add(sys.argv[2], lbl))
    else:
        print(json.dumps(load(), indent=1))
