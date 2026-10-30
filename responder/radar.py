"""Post-incident scam radar (Certificate Transparency).

Every HTTPS site needs a certificate, and every certificate is published in
public Certificate Transparency logs -- usually BEFORE the scam site is
promoted. After a big hack, "refund / compensation / claim" sites appear within
hours. This queries crt.sh (a free CT search) for brand + lure combinations,
rotating through them a few per cycle, and records new lookalike domains.

    python -m responder.radar            # one rotation now
Config (optional, config.json):
  "radar_brands":   ["binance", "xrp", "ripple", ...]   extra brands to watch
  "radar_keywords": ["swell", ...]                        extra lure words
Output: radar.json   Report links: Chainabuse, Google Safe Browsing, Netcraft.
"""
import json
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

OUT = "radar.json"
BRANDS = ["binance", "xrp", "ripple", "rlusd", "coinbase", "kraken", "robinhood", "mexc", "kucoin", "bybit", "xumm", "xaman"]
LURES = ["refund", "compensation", "claim", "recovery", "reimburse", "airdrop", "giveaway", "reward", "return", "support"]
REPORT_LINKS = [("Report to Chainabuse", "https://www.chainabuse.com/report"),
                ("Report to Google Safe Browsing", "https://safebrowsing.google.com/safebrowsing/report_phish/"),
                ("Report to Netcraft", "https://report.netcraft.com/report")]
PER_CYCLE = 6
MAX_AGE_DAYS = 30


def _cfg(k):
    try:
        import scamconfig
        return scamconfig.get(k) or []
    except Exception:
        return []


def combos():
    brands = list(dict.fromkeys(BRANDS + [b.lower() for b in _cfg("radar_brands")]))
    lures = list(dict.fromkeys(LURES + [k.lower() for k in _cfg("radar_keywords")]))
    out = []
    for b in brands:
        for l in lures:
            out.append(f"%{b}%{l}%")
            out.append(f"%{l}%{b}%")
    return out


def load():
    try:
        with open(OUT, encoding="utf-8") as f:
            d = json.load(f)
    except Exception:
        d = {}
    d.setdefault("domains", {})
    d.setdefault("cursor", 0)
    return d


def _crtsh(q, _get=None):
    if _get:
        return _get(q)
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": q, "output": "json", "exclude": "expired"})
    req = urllib.request.Request(url, headers={"User-Agent": "ScamHunter/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read() or b"[]")


def score(domain):
    d = domain.lower()
    b = [x for x in BRANDS + [y.lower() for y in _cfg("radar_brands")] if x in d]
    l = [x for x in LURES + [y.lower() for y in _cfg("radar_keywords")] if x in d]
    s = (2 if b else 0) + (2 if l else 0) + (1 if d.startswith("xn--") or ".xn--" in d else 0)
    s += 1 if d.rsplit(".", 1)[-1] in ("xyz", "top", "click", "site", "online", "live", "app", "info", "net", "org", "vip", "io") else 0
    return s, b, l


def rotate(log=print, per_cycle=PER_CYCLE, _get=None, pause=3):
    d = load()
    cs = combos()
    new = []
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=MAX_AGE_DAYS)
    for i in range(per_cycle):
        q = cs[(d["cursor"] + i) % len(cs)]
        try:
            rows = _crtsh(q, _get)
        except Exception as e:
            log(f"radar: crt.sh {q} failed ({e})")
            continue
        for r in rows or []:
            try:
                nb = datetime.strptime(r.get("not_before", "")[:19], "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                continue
            if nb < cutoff:
                continue
            for name in str(r.get("name_value", "")).split("\n"):
                name = name.strip().lstrip("*.").lower()
                if not name or name in d["domains"]:
                    continue
                s, b, l = score(name)
                if s < 4:
                    continue
                d["domains"][name] = {"first_seen": datetime.now().strftime("%Y-%m-%d %H:%M"),
                                      "cert_not_before": nb.strftime("%Y-%m-%d %H:%M"),
                                      "brands": b, "lures": l, "score": s, "crt_id": r.get("id"),
                                      "query": q, "status": "new"}
                new.append(name)
        if pause:
            time.sleep(pause)
    d["cursor"] = (d["cursor"] + per_cycle) % len(cs)
    d["last_run"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    d["combos"] = len(cs)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=1)
    if new:
        log(f"radar: {len(new)} new lookalike domain(s): {', '.join(new[:5])}")
    return new


def first_cert(domain, _get=None):
    """Earliest certificate date for a domain (how new is this site?)."""
    rows = _crtsh(domain, _get) or []
    dates = []
    for r in rows:
        try:
            dates.append(datetime.strptime(r.get("not_before", "")[:19], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            pass
    return min(dates) if dates else None


if __name__ == "__main__":
    print(rotate())
