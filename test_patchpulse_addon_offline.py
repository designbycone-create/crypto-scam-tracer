"""Offline tests for the PatchPulse add-on (addons/): off until launch, read-only, loopback-only, key sealed.

Run: python test_patchpulse_addon_offline.py
"""
import json
import os
import shutil
import sys
import tempfile
import threading

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

import securestore  # noqa: E402
from addons import patchpulse as pp, web  # noqa: E402
from relay import policy  # noqa: E402

ok = fail = 0


def check(name, cond):
    global ok, fail
    if cond:
        ok += 1
    else:
        fail += 1
        print("FAIL:", name)


tmp = tempfile.mkdtemp()
os.chdir(tmp)
securestore.BACKEND = (lambda b: b"S" + b[::-1], lambda b: b[1:][::-1])      # fake sealing, as in the other tests
TOKEN = "ppk_" + "A" * 43
calls = []


def fake(sites=None, license="active", health=True, key_ok=True, status=200):
    def http(url, headers):
        calls.append((url, dict(headers)))
        if url.endswith("/api/health"):
            return (200, json.dumps({"ok": True, "version": "1.4.0"}).encode()) if health else (503, b"")
        if url.endswith("/api/sites"):
            if headers.get("Authorization") != "Bearer " + TOKEN or not key_ok:
                return 401, b""
            return status, json.dumps({"sites": sites or [], "license_state": license, "license_message": "Your license expired.",
                                       "plan": "starter"}).encode()
        return 404, b""
    return http


def boom(url, headers):
    raise AssertionError("no network while PatchPulse isn't released")


# ---- 1. shipped state: off, link only, no network at all
check("shipped switched off", pp.RELEASED is False)
pp.HTTP = boom
check("summary off", pp.summary() == {"state": "off"})
html = web.page()
check("coming soon shown", "Coming soon" in html and "https://patchpulsehq.com" in html)
check("says it's separate and paid", "separate, paid product" in html and "stays free" in html)
check("no connect form before launch", "api_key" not in html and "<form" not in html)
check("connect refused before launch", pp.connect("http://127.0.0.1:8765", TOKEN) == "PatchPulse isn't available yet.")
check("post before launch just shows the page", "Coming soon" in web.post({"do": ["connect"], "api_key": [TOKEN]}))
check("nothing saved before launch", not os.path.exists("config.json"))
stop = threading.Event()
t = threading.Thread(target=pp.run, args=(stop, 0.01)); t.start(); stop.wait(0.1); stop.set(); t.join(2)
check("watcher idle before launch", not t.is_alive())

# ---- 2. after launch (simulated)
pp.RELEASED = True
pp.HTTP = fake()
check("not connected yet", pp.summary()["state"] == "not_connected")
check("connect form shown", "name=api_key" in web.page() and "patchpulsehq.com" in web.page())

# loopback only
for bad in ("http://example.com:8765", "http://10.0.0.5:8765", "http://127.0.0.1.evil.com", "http://user:pw@127.0.0.1:8765",
            "ftp://127.0.0.1", "http://127.0.0.1:8765/api", "http://127.0.0.1:8765?x=1", "http://127.0.0.1:99999"):
    check(f"refuses {bad}", pp.local_url(bad) is None)
check("accepts loopback", pp.local_url("http://127.0.0.1:8765/") == "http://127.0.0.1:8765")
check("accepts localhost https", pp.local_url("https://localhost:9443") == "https://localhost:9443")
check("default address", pp.local_url("") == pp.DEFAULT_URL)

# key checks
check("bad key shape refused", "ppk_" in pp.connect("http://127.0.0.1:8765", "hello"))
pp.HTTP = fake(health=False)
check("not running refused", "isn't answering" in pp.connect("http://127.0.0.1:8765", TOKEN))
pp.HTTP = fake(key_ok=False)
check("wrong key refused", "didn't accept" in pp.connect("http://127.0.0.1:8765", TOKEN))
check("nothing saved after refusals", not os.path.exists("config.json"))

# connect
sites = [
    {"id": 1, "url": "https://shop.example", "label": "My shop", "status": "ok", "counts": {"medium": 2}, "top": {"title": "WordPress out of date"}, "last_scan_at": "2026-11-24 10:00"},
    {"id": 2, "url": "https://blog.example", "label": "Blog", "status": "ok", "counts": {"critical": 1, "low": 3}, "top": {"title": "PHP 8.1 has an exploited flaw"}},
    {"id": 3, "url": "https://old.example", "label": "Old site", "status": "down", "counts": {}},
    {"id": 4, "url": "https://ok.example", "label": "Clean", "status": "ok", "counts": {"low": 1}},
]
pp.HTTP = fake(sites)
calls.clear()
check("connect ok", pp.connect("http://127.0.0.1:8765", TOKEN) is None)
raw = open("config.json").read()
check("key sealed on disk", TOKEN not in raw and securestore.PREFIX in raw)
check("key readable back", pp.settings().get("token") == TOKEN)
check("only GETs to the two read routes", {u.rsplit("/", 1)[1] for u, _ in calls} <= {"health", "sites"})
check("key sent only to /api/sites", all(("Authorization" in h) == u.endswith("/api/sites") for u, h in calls))

s = pp.summary()
check("summary ok", s["state"] == "ok" and s["plan"] == "starter")
check("worst first", [x["label"] for x in s["sites"]][:2] == ["Blog", "Old site"] and s["sites"][-1]["label"] == "Clean")
by = {x["label"]: x for x in s["sites"]}
check("critical words", by["Blog"]["words"] == "Needs attention now" and by["Blog"]["level"] == "stop")
check("down words", by["Old site"]["words"] == "Website is down" and by["Old site"]["level"] == "stop")
check("medium words", by["My shop"]["words"] == "Worth a look")
check("low only is ok", by["Clean"]["level"] == "ok")
html = web.page()
check("page lists sites", "My shop" in html and "Needs attention now" in html and "Open PatchPulse" in html)
check("key never on the page", TOKEN not in html and TOKEN not in web.post({"do": ["connect"], "api_key": [TOKEN], "url": ["http://127.0.0.1:8765"]}))

# alerts: one per critical site, once
seen = set()
a1 = pp.new_alerts(s, seen)
check("two alerts (critical + down)", len(a1) == 2 and all("needs attention" in t for t, _, _ in a1))
check("no repeat", pp.new_alerts(pp.summary(), seen) == [])
s2 = pp.summary(); s2["sites"][0]["top"] = "A new exploited flaw"
check("new finding alerts again", len(pp.new_alerts(s2, seen)) == 1)

# other states
pp.HTTP = fake(sites, license="expired")
check("unlicensed", pp.summary()["state"] == "unlicensed" and "expired" in web.page())
pp.HTTP = fake(sites, key_ok=False)
check("revoked key", pp.summary()["state"] == "bad_key")
pp.HTTP = fake(sites, status=500)
check("server error labelled", pp.summary()["state"] == "error")
pp.HTTP = fake(sites, health=False)
check("not running", pp.summary()["state"] == "not_running")

# disconnect
pp.HTTP = fake(sites)
web.post({"do": ["disconnect"]})
check("disconnect removes key", "patchpulse" not in json.load(open("config.json")) and pp.summary()["state"] == "not_connected")

# ---- 3. the phone app
check("phone can read the page", policy.check("GET", "/website") is None)
check("phone can't connect", policy.check("POST", "/website", b"do=connect&api_key=" + TOKEN.encode(),
                                          "application/x-www-form-urlencoded") is not None)
check("phone can't disconnect", policy.check("POST", "/website", b"do=disconnect", "application/x-www-form-urlencoded") is not None)
check("menu has My website", "/website" in open(os.path.join(ROOT, "deskui", "shell.py")).read())

os.chdir(ROOT)
shutil.rmtree(tmp, ignore_errors=True)
print(f"{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
