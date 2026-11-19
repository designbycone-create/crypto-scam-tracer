"""Threat map feeds: fetch, cache, normalise, and count by country -- with each source's license.

Every item becomes {id, src, layer, title, detail, url, time (UTC, ISO), cc (ISO2 or None), family}.
Items are kept 30 days in threatmap_items.json. "Rising" compares the last 24 hours with the
average day of the 7 days before it.

Sources (each can be switched off in config.json under "threatmap_sources": {"<id>": false}):
  news   FBI IC3 alerts and security-news headlines (title + link only, never article text)
  kev    CISA Known Exploited Vulnerabilities (public domain)
  feodo  abuse.ch Feodo Tracker botnet servers (CC0) -- country included
  threatfox / urlhaus  abuse.ch, with the user's own Auth-Key, non-commercial use only
Nothing here is sent anywhere except the request to each source.
"""
import hashlib
import html
import json
import os
import re
import time
import urllib.request
from datetime import datetime, timedelta, timezone

from threatmap import geo

ITEMS = "threatmap_items.json"
STATE = "threatmap_state.json"
KEEP_DAYS = 30
UA = {"User-Agent": "ScamHunter-ThreatDesk/1.0 (free scam-victim tool; github.com/designbycone-create/crypto-scam-tracer)"}
GET = None          # test hook: f(url, headers, data) -> bytes

LAYERS = {"news": "News & alerts", "botnet": "Botnet servers", "malware": "Malware sites & files", "exploited": "Exploited flaws"}
SOURCES = [
    # id, name, layer, every (seconds), license / terms, link, needs abuse.ch key
    ("ic3", "FBI IC3 public alerts", "news", 3600, "US government work (public domain)", "https://www.ic3.gov/PSA", False),
    ("record", "The Record (Recorded Future News)", "news", 3600, "RSS headline + link only", "https://therecord.media", False),
    ("bleeping", "BleepingComputer", "news", 3600, "RSS headline + link only", "https://www.bleepingcomputer.com", False),
    ("krebs", "Krebs on Security", "news", 3600, "RSS headline + link only", "https://krebsonsecurity.com", False),
    ("kev", "CISA Known Exploited Vulnerabilities", "exploited", 6 * 3600, "US government work (public domain)",
     "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", False),
    ("feodo", "abuse.ch Feodo Tracker", "botnet", 6 * 3600, "CC0", "https://feodotracker.abuse.ch", False),
    ("threatfox", "abuse.ch ThreatFox", "botnet", 3 * 3600, "abuse.ch terms: not-for-profit use, your own key",
     "https://threatfox.abuse.ch", True),
    ("urlhaus", "abuse.ch URLhaus", "malware", 3 * 3600, "abuse.ch terms: not-for-profit use, your own key", "https://urlhaus.abuse.ch", True),
]
RSS = {"ic3": "https://www.ic3.gov/PSA/RSS", "record": "https://therecord.media/feed",
       "bleeping": "https://www.bleepingcomputer.com/feed/", "krebs": "https://krebsonsecurity.com/feed/"}
GEO_ATTRIBUTION = ("IP address to country by DB-IP (https://db-ip.com), CC BY 4.0. Map: Natural Earth (public domain) via "
                   "world-atlas (ISC); country codes: i18n-iso-countries (MIT).")


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _get(url, headers=None, data=None, timeout=40):
    if GET:
        return GET(url, headers or {}, data)
    import nettls
    req = urllib.request.Request(url, headers={**UA, **(headers or {})}, data=data)
    with urllib.request.urlopen(req, timeout=timeout, context=nettls.context()) as r:
        return r.read()


def _id(*parts):
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def enabled():
    try:
        with open("config.json", encoding="utf-8-sig") as f:
            sw = json.load(f).get("threatmap_sources") or {}
    except Exception:
        sw = {}
    return {s[0] for s in SOURCES if sw.get(s[0], True) is not False}


# ---------------------------------------------------------------- parsers ----

def _rss_date(s):
    from email.utils import parsedate_to_datetime
    try:
        return parsedate_to_datetime(s.strip()).astimezone(timezone.utc)
    except Exception:
        return _now()


def parse_rss(src, raw):
    """Title, link and date only. The article text is never stored or shown."""
    txt = raw.decode("utf-8", "replace")
    out = []
    for item in re.findall(r"<item\b.*?</item>", txt, re.S)[:40]:
        g = lambda tag: (re.search(rf"<{tag}\b[^>]*>(.*?)</{tag}>", item, re.S) or [None, ""])[1]
        title = html.unescape(re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", g("title"), flags=re.S)).strip()
        link = html.unescape(re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", g("link"), flags=re.S)).strip()
        if not title:
            continue
        ccs = geo.countries_in(title)
        out.append({"id": _id(src, link or title), "src": src, "layer": "news", "title": title[:200], "detail": "",
                    "url": link if link.startswith("https://") or link.startswith("http://") else "", "time": _iso(_rss_date(g("pubDate"))),
                    "cc": ccs[0] if ccs else None, "ccs": ccs[:4], "family": _family(title)})
    return out


FAMILIES = ["ClickFix", "Lumma", "Vidar", "RedLine", "AsyncRAT", "Mirai", "Emotet", "QakBot", "IcedID", "Remcos", "AgentTesla", "Raccoon",
            "StealC", "Rhadamanthys", "LockBit", "BlackCat", "ALPHV", "Akira", "Qilin", "Medusa", "Cl0p", "Scattered Spider",
            "Lazarus", "pig butchering", "drainer", "phishing", "ransomware", "infostealer", "botnet", "zero-day", "deepfake"]


ALIAS = {"phish": "phishing", "stealer": "infostealer", "zero day": "zero-day", "0-day": "zero-day", "wallet drainer": "drainer"}


def _family(text):
    low = (text or "").lower()
    for f in FAMILIES:
        if re.search(r"(?<![a-z])" + re.escape(f.lower()), low):
            return f
    for a, f in ALIAS.items():
        if re.search(r"(?<![a-z])" + re.escape(a), low):
            return f
    return None


def parse_kev(raw, since_days=KEEP_DAYS):
    d = json.loads(raw)
    cut = (_now() - timedelta(days=since_days)).date().isoformat()
    out = []
    for v in d.get("vulnerabilities") or []:
        if (v.get("dateAdded") or "") < cut:
            continue
        rw = v.get("knownRansomwareCampaignUse") == "Known"
        out.append({"id": _id("kev", v["cveID"]), "src": "kev", "layer": "exploited",
                    "title": f"{v['cveID']}: {v.get('vendorProject', '')} {v.get('product', '')} flaw is being exploited",
                    "detail": (v.get("vulnerabilityName") or "") + (" | used by ransomware gangs" if rw else ""),
                    "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}", "time": v["dateAdded"] + "T12:00:00Z", "cc": None,
                    "family": "ransomware" if rw else None})
    return out


def parse_feodo(raw):
    out = []
    for r in json.loads(raw):
        ls = (r.get("last_online") or r.get("first_seen") or "")[:10]
        out.append({"id": _id("feodo", r.get("ip_address"), r.get("port")), "src": "feodo", "layer": "botnet",
                    "title": f"{r.get('malware') or 'Botnet'} control server ({r.get('status', 'unknown')})",
                    "detail": f"{r.get('ip_address')}:{r.get('port')} on {r.get('as_name') or 'unknown network'}",
                    "url": "https://feodotracker.abuse.ch/browse/host/" + str(r.get("ip_address")),
                    "time": (ls or _now().date().isoformat()) + "T00:00:00Z", "cc": r.get("country") or None, "family": r.get("malware")})
    return out


def _abuse_time(s):
    try:
        return _iso(datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc))
    except Exception:
        return _iso(_now())


def parse_threatfox(raw, data_dir="."):
    d = json.loads(raw)
    out = []
    for r in d.get("data") or []:
        if r.get("ioc_type") not in ("ip:port", "domain", "url"):
            continue                                     # file hashes have no place on a map
        ioc = r.get("ioc") or ""
        cc = geo.country_of_ip(ioc.split(":")[0], data_dir) if r.get("ioc_type") == "ip:port" else None
        fam = r.get("malware_printable") or "Unknown malware"
        out.append({"id": _id("threatfox", r.get("id")), "src": "threatfox", "layer": "botnet" if r.get("threat_type") == "botnet_cc" else "malware",
                    "title": f"{fam}: {r.get('threat_type_desc') or r.get('threat_type')}"[:160],
                    "detail": f"{r.get('ioc_type')} reported {str(r.get('first_seen') or '')[:16]}", "url": f"https://threatfox.abuse.ch/ioc/{r.get('id')}/",
                    "time": _abuse_time(r.get("first_seen") or ""), "cc": cc, "family": None if fam == "Unknown malware" else fam})
    return out


def parse_urlhaus(raw, data_dir="."):
    d = json.loads(raw)
    out = []
    for r in d.get("urls") or []:
        host = r.get("host") or ""
        cc = geo.country_of_ip(host, data_dir) if re.fullmatch(r"[\d.]+", host) else None
        tags = r.get("tags") or []
        out.append({"id": _id("urlhaus", r.get("id")), "src": "urlhaus", "layer": "malware",
                    "title": f"Malware download site ({r.get('url_status', 'unknown')})" + (f": {tags[0]}" if tags else ""),
                    "detail": f"{r.get('threat') or 'malware'} on a {'server address' if cc else 'website'}",
                    "url": r.get("urlhaus_reference") or "", "time": _abuse_time(r.get("date_added") or ""), "cc": cc,
                    "family": tags[0] if tags else None})
    return out


# ---------------------------------------------------------------- refresh + store ----

_cache = {"m": None, "items": []}


def load_items():
    """Kept in memory; re-read only when the file changes (the map asks every minute)."""
    try:
        m = os.path.getmtime(ITEMS)
    except OSError:
        return []
    if _cache["m"] != m:
        try:
            with open(ITEMS, encoding="utf-8") as f:
                _cache.update(m=m, items=json.load(f))
        except Exception:
            return _cache["items"]
    return _cache["items"]


def _state():
    try:
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(path, obj):
    with open(path + ".tmp", "w", encoding="utf-8") as f:
        json.dump(obj, f)
    os.replace(path + ".tmp", path)


def refresh(force=False, log=print, data_dir="."):
    """Fetch each enabled source whose interval has passed. One failing source never stops the others."""
    from shield import abusech
    st = _state()
    key = abusech.key()
    on = enabled()
    new_items = []
    try:
        geo.refresh_dbip(data_dir, log=log)
    except Exception as ex:
        log(f"threat map: DB-IP check failed: {ex}")
    for sid, name, layer, every, lic, link, needs_key in SOURCES:
        s = st.setdefault(sid, {})
        if sid not in on:
            s.update(status="off")
            continue
        if needs_key and not key:
            s.update(status="needs your abuse.ch key (Online Defense > Malware & link check)")
            continue
        if not force and time.time() - s.get("fetched", 0) < every:
            continue
        try:
            if sid in RSS:
                items = parse_rss(sid, _get(RSS[sid]))
            elif sid == "kev":
                items = parse_kev(_get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
            elif sid == "feodo":
                items = parse_feodo(_get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", {"Auth-Key": key} if key else {}))
            elif sid == "threatfox":
                items = parse_threatfox(_get("https://threatfox-api.abuse.ch/api/v1/", {"Auth-Key": key, "Content-Type": "application/json"},
                                             json.dumps({"query": "get_iocs", "days": 1}).encode()), data_dir)
            elif sid == "urlhaus":
                items = parse_urlhaus(_get("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/", {"Auth-Key": key}), data_dir)
            else:
                items = []
            new_items += items
            s.update(fetched=time.time(), status="ok", count=len(items), error=None)
        except Exception as ex:
            code = getattr(ex, "code", None)
            s.update(fetched=time.time(), status="error",
                     error=(f"refused (HTTP {code})" if code in (401, 403) else f"HTTP {code}" if code else str(ex)[:120]))
            log(f"threat map: {name} failed: {s['error']}")
    if new_items:
        merged = {i["id"]: i for i in load_items()}
        for i in new_items:
            merged[i["id"]] = i
        cut = _iso(_now() - timedelta(days=KEEP_DAYS))
        _save(ITEMS, sorted((i for i in merged.values() if i["time"] >= cut), key=lambda i: i["time"], reverse=True))
    _save(STATE, st)
    return len(new_items)


# ---------------------------------------------------------------- what the map shows ----

def summary(window_hours=24, layers=None):
    items = load_items()
    now = _now()
    since = _iso(now - timedelta(hours=window_hours))
    layers = set(layers or LAYERS)
    win = [i for i in items if i["time"] >= since and i["layer"] in layers]
    by_cc, by_fam, by_layer = {}, {}, {}
    for i in win:
        for cc in (i.get("ccs") or ([i["cc"]] if i.get("cc") else [])):
            c = by_cc.setdefault(cc, {"n": 0, "layers": {}})
            c["n"] += 1
            c["layers"][i["layer"]] = c["layers"].get(i["layer"], 0) + 1
        if i.get("family"):
            by_fam[i["family"]] = by_fam.get(i["family"], 0) + 1
        by_layer[i["layer"]] = by_layer.get(i["layer"], 0) + 1
    rising = _rising(items, now, layers)
    st = _state()
    return {"generated": _iso(now), "window_hours": window_hours, "total": len(win), "unlocated": sum(1 for i in win if not i.get("cc")),
            "countries": by_cc, "families": sorted(by_fam.items(), key=lambda kv: -kv[1])[:10], "layers": by_layer,
            "rising": rising, "items": win[:300],
            "sources": [{"id": s[0], "name": s[1], "license": s[4], "link": s[5], "status": (st.get(s[0]) or {}).get("status", "not fetched yet"),
                         "error": (st.get(s[0]) or {}).get("error"), "count": (st.get(s[0]) or {}).get("count")} for s in SOURCES],
            "attribution": GEO_ATTRIBUTION}


def _rising(items, now, layers):
    """Countries and malware families clearly above their own normal: last 24h >= 3 and >= 2x the 7-day daily average."""
    d0 = _iso(now - timedelta(hours=24))
    d7 = _iso(now - timedelta(days=8))
    cur, base = {}, {}
    for i in items:
        if i["layer"] not in layers or i["layer"] == "exploited":
            continue
        keys = [("country", c) for c in (i.get("ccs") or ([i["cc"]] if i.get("cc") else []))] + ([("family", i["family"])] if i.get("family") else [])
        bucket = cur if i["time"] >= d0 else base if i["time"] >= d7 else None
        if bucket is None:
            continue
        for k in keys:
            bucket[k] = bucket.get(k, 0) + 1
    out = []
    for k, n in cur.items():
        avg = base.get(k, 0) / 7
        if n >= 3 and n >= 2 * max(avg, 0.5):
            out.append({"kind": k[0], "key": k[1], "now": n, "usual": round(avg, 1), "x": round(n / max(avg, 0.5), 1)})
    return sorted(out, key=lambda r: (-r["x"], -r["now"]))[:12]
