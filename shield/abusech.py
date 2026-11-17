"""abuse.ch lookups (by the Swiss non-profit abuse.ch, run with Spamhaus):
  * MalwareBazaar: is this file (by its SHA-256 fingerprint) known malware?
  * URLhaus: is this link, or its site, known for spreading malware?
  * ThreatFox: is this site or address a known indicator of attack?

Terms (https://abuse.ch/terms-of-use/): free for not-for-profit use by authenticated users under
fair use; commercial use may need a paid subscription. So:
  * each person uses their OWN free Auth-Key (https://auth.abuse.ch/), stored encrypted in
    config.json as "abusech_key" -- ScamHunter never ships or shares one;
  * every lookup is one item you asked about; nothing is downloaded in bulk or harvested.

Privacy: a file is looked up by its fingerprint only (the file never leaves your computer). A link
you check is sent to abuse.ch.
"""
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request

MB = "https://mb-api.abuse.ch/api/v1/"
UH_URL = "https://urlhaus-api.abuse.ch/v1/url/"
UH_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
TF = "https://threatfox-api.abuse.ch/api/v1/"
UA = "ScamHunter/1.0 (free scam-victim tool; github.com/designbycone-create/crypto-scam-tracer)"
POST = None          # test hook: f(url, data:bytes, headers:dict) -> dict


def key():
    try:
        import securestore
        with open("config.json", encoding="utf-8-sig") as f:
            return securestore.reveal(json.load(f).get("abusech_key")) or ""
    except Exception:
        return ""


def key_id():
    k = key()
    return hashlib.sha256(k.encode()).hexdigest()[:8] if k else None


def save_key(k):
    """Store the user's own Auth-Key (encrypted). Returns its short ID, never the key."""
    import securestore
    k = (k or "").strip()
    try:
        with open("config.json", encoding="utf-8-sig") as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    if k:
        cfg["abusech_key"] = k
    else:
        cfg.pop("abusech_key", None)
    securestore.save(cfg, "config.json")
    return key_id()


def _post(url, data, as_json=False):
    k = key()
    if not k:
        return None
    hdr = {"Auth-Key": k, "User-Agent": UA}
    body = json.dumps(data).encode() if as_json else urllib.parse.urlencode(data).encode()
    if as_json:
        hdr["Content-Type"] = "application/json"
    try:
        if POST:
            return POST(url, body, hdr)
        with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=hdr), timeout=20) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as ex:
        return {"query_status": f"http_{ex.code}"}
    except Exception as ex:
        return {"query_status": "error", "error": str(ex)[:120]}


def _status_problem(d):
    s = (d or {}).get("query_status", "")
    if s in ("http_401", "http_403", "unknown_auth_key", "invalid_auth_key"):
        return "abuse.ch didn't accept your Auth-Key (check it on the Malware & link check page)"
    if s.startswith("http_") or s == "error":
        return "couldn't reach abuse.ch just now"
    return None


def file_hash(sha256):
    """{'checked', 'known', 'detail'}"""
    d = _post(MB, {"query": "get_info", "hash": sha256})
    if d is None:
        return {"checked": False, "known": None, "detail": "MalwareBazaar not checked (add your free abuse.ch key to use it)"}
    p = _status_problem(d)
    if p:
        return {"checked": False, "known": None, "detail": p}
    if d.get("query_status") == "ok" and d.get("data"):
        x = d["data"][0]
        fam = x.get("signature") or ", ".join(x.get("tags") or []) or "malware"
        return {"checked": True, "known": True, "detail": f"MalwareBazaar knows this exact file as malware ({fam}), first seen {str(x.get('first_seen', ''))[:10]}."}
    return {"checked": True, "known": False, "detail": "Not in MalwareBazaar's database of known malware files (new malware may not be there yet)."}


def url(u):
    """{'checked', 'known', 'detail'} for a link (URLhaus by exact URL, then by site; ThreatFox by site)."""
    if not key():
        return {"checked": False, "known": None, "detail": "abuse.ch not checked (add your free abuse.ch key to use it)"}
    host = (urllib.parse.urlsplit(u if "://" in u else "http://" + u).hostname or "").lower()
    d = _post(UH_URL, {"url": u})
    p = _status_problem(d)
    if p:
        return {"checked": False, "known": None, "detail": p}
    if d.get("query_status") == "ok":
        st = d.get("url_status") or "unknown"
        return {"checked": True, "known": True, "detail": f"URLhaus lists this exact link as spreading malware ({d.get('threat') or 'malware'}; currently {st})."}
    if host:
        h = _post(UH_HOST, {"host": host}) or {}
        if h.get("query_status") == "ok" and int(h.get("url_count") or 0) > 0:
            online = sum(1 for x in h.get("urls") or [] if x.get("url_status") == "online")
            return {"checked": True, "known": True, "detail": f"URLhaus has {h['url_count']} malware link(s) on {host} ({online} still online)."}
        t = _post(TF, {"query": "search_ioc", "search_term": host}, as_json=True) or {}
        if t.get("query_status") == "ok" and t.get("data"):
            x = t["data"][0]
            return {"checked": True, "known": True, "detail": f"ThreatFox lists {host} as attack infrastructure ({x.get('malware_printable') or x.get('threat_type') or 'malware'})."}
    return {"checked": True, "known": False, "detail": "Not on abuse.ch's malware lists (URLhaus, ThreatFox). New sites may not be there yet."}
