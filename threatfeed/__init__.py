"""Known attack campaigns, delivered with every signed release.

threatfeed/campaigns.json is part of the repository, so it is covered by the release signature:
a user gets new campaigns the same way they get new code, and nobody can slip addresses into
it without the maintainer's key. Local, same-day additions still go in compromised.json.

    from threatfeed import campaign_for_address, campaign_for_host
    campaign_for_address("19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW")   -> campaign dict or None
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FILE = os.path.join(HERE, "campaigns.json")
_cache = {"mtime": None, "data": None}


def _key(a):
    from responder.addresses import is_bch
    a = (a or "").strip()
    if a.lower().startswith("bitcoincash:"):
        a = a.split(":", 1)[1]
    return a.lower() if a[:2].lower() == "0x" or is_bch(a) else a


def campaigns():
    try:
        m = os.path.getmtime(FILE)
        if _cache["mtime"] != m:
            with open(FILE, encoding="utf-8") as f:
                _cache["data"] = json.load(f).get("campaigns", [])
            _cache["mtime"] = m
    except Exception:
        _cache["data"] = _cache["data"] or []
    return _cache["data"]


def addresses():
    """{normalised address: (campaign, entry)}"""
    out = {}
    for c in campaigns():
        for e in c.get("addresses", []):
            out[_key(e["address"])] = (c, e)
    return out


def campaign_for_address(a):
    hit = addresses().get(_key(a))
    return hit[0] if hit else None


def campaign_for_host(host):
    """Campaign whose infrastructure includes this host (or a parent domain of it), or this IP."""
    h = (host or "").lower().strip().strip(".")
    for c in campaigns():
        if h in c.get("ips", []):
            return c
        for d in c.get("domains", []):
            if h == d or h.endswith("." + d):
                return c
    return None


def scan_text(text):
    """Campaign markers found in a piece of JavaScript/HTML: [(campaign name, marker)]."""
    import hashlib
    t = text or ""
    low = t.lower()
    digest = hashlib.sha256(t.encode("utf-8", "replace")).hexdigest()
    hits = []
    for c in campaigns():
        if digest in c.get("script_sha256", []):
            hits.append((c["name"], "file matches a known malicious script (SHA-256)"))
        for m in c.get("domains", []) + c.get("script_markers", []):
            if m.lower() in low:
                hits.append((c["name"], m))
    return list(dict.fromkeys(hits))


def seed_tracer(log=print):
    """Add every campaign address on a chain the tracer follows to incident mode, so the tracer
    watches it for cash-outs and drafts freeze requests. Idempotent: safe to call at every start."""
    from responder import incident
    from responder.addresses import TRACEABLE
    added = []
    for c in campaigns():
        if c.get("trace") is False:
            continue        # warn-only list (e.g. hundreds of laundering wallets): checked before you send, not traced
        text = " ".join(e["address"] for e in c.get("addresses", []) if e["chain"] in TRACEABLE)
        if text:
            import time
            from datetime import datetime
            try:   # follow money from a day before the campaign began, not the address's whole past
                start = datetime.strptime(c.get("first_seen", ""), "%Y-%m-%d").timestamp() - 86400
                hours = max(1, int((time.time() - start) / 3600))
            except ValueError:
                hours = None
            added += incident.add(text, label=f"{c['name']} (campaign feed)", source="threatfeed", since_hours=hours)
    if added:
        log(f"campaign feed: now tracing {len(added)} attacker address(es)")
    return added


def describe(c):
    return f"{c['name']} ({c.get('kind', 'attack campaign')}, first seen {c.get('first_seen')})"
