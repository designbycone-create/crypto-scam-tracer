"""PatchPulse (patchpulsehq.com): website exposure monitoring for people who own a website.

PatchPulse is a separate, paid product from FPH LLC. None of its code is in this repository, and nothing here
unlocks or replaces a PatchPulse license.

Today the Desk only shows PatchPulse as "coming soon" with a link (RELEASED = False): no connection is attempted
and nothing is sent anywhere. The connector below is built and tested but stays off until a signed Desk update
sets RELEASED = True when PatchPulse launches. Then, for someone who has bought PatchPulse and runs it on this
computer, the Desk:
  * READS each website's status from PatchPulse's own local API (GET /api/health, GET /api/sites), using an API
    key the owner creates in PatchPulse (Settings) and types into the Desk once, at the computer. The key is
    sealed with Windows account protection like the Desk's other keys, and never printed or logged;
  * shows the result in plain words on the "My website" page, and
  * sends one alert per new critical finding through the Desk's usual alerts.
It never changes anything in PatchPulse, and it only talks to PatchPulse on this computer (loopback), so the
key never crosses a network.
"""
import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import securestore

RELEASED = False                      # flipped in a signed Desk update when PatchPulse goes on sale
NAME = "PatchPulse"
SITE = "https://patchpulsehq.com"
DEFAULT_URL = "http://127.0.0.1:8765"
CFG = "config.json"
TIMEOUT = 4
LOOPBACK = ("127.0.0.1", "localhost", "::1")
SEVERITY = ["critical", "high", "medium", "low"]   # PatchPulse's own levels, worst first
HTTP = None                           # test hook: f(url, headers) -> (status, bytes)


# ------------------------------------------------------------------ settings ----
def _cfg():
    try:
        with open(CFG, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return {}


def settings():
    return securestore.reveal_config(_cfg()).get("patchpulse") or {}


def _store(pp):
    cfg = securestore.reveal_config(_cfg())
    if pp:
        cfg["patchpulse"] = pp
    else:
        cfg.pop("patchpulse", None)
    securestore.save(cfg, CFG)


def local_url(url):
    """The PatchPulse address, or None if it isn't plain http(s) on this computer (fail closed)."""
    url = (url or DEFAULT_URL).strip().rstrip("/")
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError:
        return None
    if u.scheme not in ("http", "https") or (u.hostname or "").lower() not in LOOPBACK or u.path not in ("", "/") \
            or u.query or u.fragment or u.username or u.password:
        return None
    return url if port is None or 0 < port < 65536 else None


# ------------------------------------------------------------------ talking to PatchPulse ----
def _get(url, token=None):
    headers = {"Accept": "application/json", "User-Agent": "ScamHunter-Desk"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if HTTP:
        return HTTP(url, headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # loopback only: never via a proxy
    try:
        with opener.open(urllib.request.Request(url, headers=headers), timeout=TIMEOUT) as r:
            return r.status, r.read(2_000_000)
    except urllib.error.HTTPError as ex:
        return ex.code, b""


def _json(b):
    try:
        return json.loads(b.decode("utf-8"))
    except Exception:
        return None


def worst(counts):
    for s in SEVERITY:
        if (counts or {}).get(s):
            return s
    return None


PLAIN = {"critical": ("stop", "Needs attention now"), "high": ("caution", "Needs attention"),
         "medium": ("caution", "Worth a look"), "low": ("ok", "Minor tips only"), None: ("ok", "All clear")}


def summary(pp=None):
    """What the Desk shows. state: off | not_connected | bad_address | not_running | bad_key | unlicensed | ok | error."""
    if not RELEASED:
        return {"state": "off"}
    pp = settings() if pp is None else pp
    if not pp.get("token"):
        return {"state": "not_connected"}
    base = local_url(pp.get("url"))
    if not base:
        return {"state": "bad_address"}
    try:
        st, body = _get(base + "/api/health")
        if st != 200 or not (_json(body) or {}).get("ok"):
            return {"state": "not_running"}
        version = _json(body).get("version")
        st, body = _get(base + "/api/sites", pp["token"])
    except Exception:
        return {"state": "not_running"}
    if st == 401:
        return {"state": "bad_key"}
    data = _json(body) if st == 200 else None
    if not isinstance(data, dict):
        return {"state": "error", "message": f"PatchPulse answered with code {st}"}
    if data.get("license_state") != "active":
        return {"state": "unlicensed", "message": data.get("license_message") or "", "version": version}
    sites = []
    for s in data.get("sites") or []:
        w = worst(s.get("counts"))
        lvl, words = PLAIN.get(w, PLAIN[None])
        if s.get("status") == "down":
            lvl, words = "stop", "Website is down"
        sites.append({"id": s.get("id"), "label": s.get("label") or s.get("url"), "url": s.get("url"),
                      "level": lvl, "words": words, "worst": w, "top": (s.get("top") or {}).get("title"),
                      "last_scan_at": s.get("last_scan_at"), "error": s.get("error")})
    order = {"stop": 0, "caution": 1, "ok": 2}
    sites.sort(key=lambda x: order.get(x["level"], 3))
    return {"state": "ok", "version": version, "plan": data.get("plan"), "sites": sites, "base": base}


def connect(url, token):
    """Check the address and key against PatchPulse, then save them (key sealed). Returns None or why not."""
    if not RELEASED:
        return "PatchPulse isn't available yet."
    base = local_url(url)
    if not base:
        return "Use PatchPulse's address on this computer, like http://127.0.0.1:8765."
    token = (token or "").strip()
    if not token.startswith("ppk_") or len(token) < 20 or any(c.isspace() for c in token):
        return "That doesn't look like a PatchPulse API key (it starts with ppk_). Make one in PatchPulse > Settings."
    r = summary({"url": base, "token": token})
    if r["state"] == "not_running":
        return "PatchPulse isn't answering at that address. Start PatchPulse, then try again."
    if r["state"] == "bad_key":
        return "PatchPulse didn't accept that key. Make a new one in PatchPulse > Settings and paste it here."
    if r["state"] not in ("ok", "unlicensed"):
        return "PatchPulse answered in a way the Desk doesn't understand. Nothing was saved."
    _store({"url": base, "token": token, "connected_at": time.strftime("%Y-%m-%d %H:%M")})
    return None


def disconnect():
    _store(None)


# ------------------------------------------------------------------ alerts ----
def new_alerts(s, seen):
    """(title, message, key) for each critical or down site not alerted before. seen: set of keys, updated."""
    out = []
    for site in (s.get("sites") or []) if s.get("state") == "ok" else []:
        if site["level"] != "stop":
            continue
        key = f"patchpulse:{site['id']}:{site['words']}:{site.get('top') or ''}"
        if key in seen:
            continue
        seen.add(key)
        out.append((f"Your website needs attention: {site['label']}",
                    f"{site['words']}" + (f": {site['top']}" if site.get("top") else "") + ". Open PatchPulse for the fix.",
                    key))
    return out


def run(stop_evt, interval=900, log=print):
    """Background watcher: does nothing (no network) unless RELEASED and connected."""
    seen = set()
    while not stop_evt.is_set():
        if RELEASED and settings().get("token"):
            try:
                import alerts
                for title, msg, key in new_alerts(summary(), seen):
                    alerts.send(title, msg, critical=True, key=key)
            except Exception as ex:
                log(f"(PatchPulse check skipped: {type(ex).__name__})")
        stop_evt.wait(interval)
