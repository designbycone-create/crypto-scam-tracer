"""The Desk's pairing with your Worker and your phone, kept in config.json under "relay" (secrets sealed).

    relay: {worker, admin_key, channel, desk_token, phone_token, key, paired_at}

The QR code the phone scans holds the Worker address, the channel, the phone's token and the
encryption key. It's shown once, on this computer only, and never logged or saved anywhere else.
"""
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.request

import securestore

CFG = "config.json"
WORKER_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "worker", "relay")
WORKER_NAME = "scamhunter-relay"
POST = None          # test hook: f(url, headers, body) -> (status, bytes)
GET = None           # test hook: f(url) -> (status, bytes)
RUN = subprocess.run  # test hook


def _cfg():
    try:
        with open(CFG, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return {}


def load():
    return (securestore.reveal_config(_cfg()).get("relay") or {})


def _store(relay):
    cfg = securestore.reveal_config(_cfg())
    cfg["relay"] = relay
    securestore.save(cfg, CFG)


def worker_ok(url):
    return bool(re.fullmatch(r"https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", (url or "").rstrip("/").lower()))


def _post(url, headers, body):
    if POST:
        return POST(url, headers, body)
    import nettls
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "ScamHunter-ThreatDesk/1.0", **headers})
    try:
        with urllib.request.urlopen(req, timeout=20, context=nettls.context()) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as ex:
        return ex.code, ex.read()


def key_id(secret):
    """Short fingerprint to show instead of a secret."""
    return hashlib.sha256((secret or "").encode()).hexdigest()[:8]


# ---------------------------------------------------------------- Worker setup ----

def set_worker(url):
    url = (url or "").strip().rstrip("/").lower()
    if not worker_ok(url):
        return "That isn't an https:// address (it looks like https://scamhunter-relay.<your-name>.workers.dev)."
    st, body = _get_health(url)
    if st != 200:
        return f"No ScamHunter relay answered at that address ({st})."
    r = load()
    r["worker"] = url
    r.setdefault("admin_key", secrets.token_urlsafe(36))
    _store(r)
    return None


def _get(url):
    if GET:
        return GET(url)
    import nettls
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "ScamHunter-ThreatDesk/1.0"}), timeout=15,
                                    context=nettls.context()) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as ex:
        return ex.code, ex.read()


def _get_health(url):
    try:
        st, body = _get(url + "/health")
        j = json.loads(body or b"{}")
        return (st if j.get("service") == "scamhunter-relay" else 404), j
    except Exception as ex:
        return str(ex)[:60], {}


def health():
    r = load()
    if not r.get("worker"):
        return None
    st, j = _get_health(r["worker"])
    return {"reachable": st == 200, "configured": bool(j.get("configured")), "status": st}


def wrangler():
    """Command to run wrangler (npx), or None if Node.js isn't installed."""
    npx = shutil.which("npx.cmd") or shutil.which("npx")
    return [npx, "--yes", "wrangler@4"] if npx else None


def install_admin_key():
    """Give the Worker its admin key: piped straight into `wrangler secret put` (never typed, shown or logged)."""
    r = load()
    w = wrangler()
    if not w:
        return "Node.js isn't installed (it provides the npx command that talks to Cloudflare)."
    if not r.get("admin_key"):
        r["admin_key"] = secrets.token_urlsafe(36)
        _store(r)
    kw = {"creationflags": 0x08000000} if os.name == "nt" else {}
    p = RUN(w + ["secret", "put", "ADMIN_KEY", "--name", WORKER_NAME], input=r["admin_key"] + "\n", capture_output=True, text=True,
            cwd=WORKER_DIR, timeout=180, **kw)
    if p.returncode != 0:
        tail = (p.stderr or p.stdout or "").strip().splitlines()[-1:] or [""]
        return "Cloudflare didn't accept the key: " + tail[0].replace(r["admin_key"], "***")[:200]
    return None


def deploy_worker():
    """Deploy worker/relay with the user's own Cloudflare login (they approve the login in their browser)."""
    w = wrangler()
    if not w:
        return None, "Node.js isn't installed (it provides the npx command that talks to Cloudflare)."
    kw = {"creationflags": 0x08000000} if os.name == "nt" else {}
    p = RUN(w + ["deploy"], capture_output=True, text=True, cwd=WORKER_DIR, timeout=300, **kw)
    out = (p.stdout or "") + (p.stderr or "")
    m = re.search(r"https://[a-z0-9.-]+\.workers\.dev", out)
    if p.returncode != 0 or not m:
        tail = out.strip().splitlines()[-1:] or [""]
        return None, "Deploying didn't finish: " + tail[0][:200]
    return m.group(0), None


# ---------------------------------------------------------------- pairing ----

def pair():
    """Create a fresh channel for the phone; returns (qr_text, None) or (None, why not). Replaces any old pairing."""
    r = load()
    if not r.get("worker") or not r.get("admin_key"):
        return None, "Set up your Worker first."
    if r.get("channel"):
        unpair(quiet=True)
        r = load()
    new = {"channel": secrets.token_hex(16), "desk_token": secrets.token_urlsafe(32), "phone_token": secrets.token_urlsafe(32),
           "key": base64.b64encode(os.urandom(32)).decode()}
    body = json.dumps({"channel": new["channel"], "desk_hash": hashlib.sha256(new["desk_token"].encode()).hexdigest(),
                       "phone_hash": hashlib.sha256(new["phone_token"].encode()).hexdigest()}).encode()
    st, resp = _post(r["worker"] + "/register", {"Authorization": "Bearer " + r["admin_key"]}, body)
    if st == 401:
        return None, "The Worker doesn't have this Desk's admin key yet (step 2)."
    if st != 200:
        return None, f"The Worker refused the pairing ({st})."
    r.update(new, paired_at=time.strftime("%Y-%m-%d %H:%M"))
    _store(r)
    return qr_text(r), None


def qr_text(r):
    payload = {"u": r["worker"], "c": r["channel"], "t": r["phone_token"], "k": r["key"]}
    return "shtd1:" + base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")


def unpair(quiet=False):
    r = load()
    if r.get("channel") and r.get("worker") and r.get("admin_key"):
        try:
            _post(r["worker"] + "/unregister", {"Authorization": "Bearer " + r["admin_key"]}, json.dumps({"channel": r["channel"]}).encode())
        except Exception:
            pass
    for k in ("channel", "desk_token", "phone_token", "key", "paired_at"):
        r.pop(k, None)
    _store(r)
    return None


def paired():
    r = load()
    return bool(r.get("worker") and r.get("channel") and r.get("desk_token") and r.get("key"))
