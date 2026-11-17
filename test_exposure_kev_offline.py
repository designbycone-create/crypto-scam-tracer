"""Offline tests: exposure check ranks flaws attackers are using now (CISA KEV), uses checked
certificates for its lookups, and the weekly re-check alerts only on something new.
    python test_exposure_kev_offline.py
"""
import json, os, shutil, sys, tempfile
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
WORK = tempfile.mkdtemp(prefix="sh_kev_")
os.chdir(WORK)
ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []
from shield import exposure as X  # noqa: E402

IP = "8.8.4.4"
KEVJ = {"catalogVersion": "2026.11.13", "vulnerabilities": [
    {"cveID": "CVE-2024-3400", "vendorProject": "Palo Alto Networks", "product": "PAN-OS", "vulnerabilityName": "command injection",
     "knownRansomwareCampaignUse": "Known", "dateAdded": "2024-04-12"},
    {"cveID": "CVE-2023-1111", "vendorProject": "Acme", "product": "Cam", "vulnerabilityName": "x", "knownRansomwareCampaignUse": "Unknown", "dateAdded": "2023-01-01"}]}
db = {"ip": IP, "ports": [443, 3389], "cpes": [], "hostnames": [], "tags": [], "vulns": ["CVE-2024-3400", "CVE-2020-9999"]}
calls = []
def fake(url):
    calls.append(url)
    if "ipify" in url: return IP
    if "internetdb" in url: return json.dumps(db)
    if "cisa.gov" in url: return json.dumps(KEVJ)
    return "<title>Login</title>"
X.GET = fake
res = X.check()
crit = [i for i in res["items"] if i.get("cve") == "CVE-2024-3400"]
r.append(ok(crit and crit[0]["severity"] == "critical" and "ransomware" in crit[0]["advice"] and res["worst"] == "critical",
            "a flaw on CISA's actively-exploited list is CRITICAL, with ransomware use named"))
r.append(ok(res["kev_hits"] == ["CVE-2024-3400"] and res["kev_checked"] and not any(i.get("cve") == "CVE-2020-9999" for i in res["items"]),
            "flaws not on the list aren't escalated"))
html = X.page(res)
r.append(ok("1 of them are on CISA" in html and "attackers are using" in html.lower(), "page explains which flaws are being used now"))
n = len([c for c in calls if "cisa.gov" in c]); X.check()
r.append(ok(len([c for c in calls if "cisa.gov" in c]) == n, "CISA's catalog is downloaded at most once a day (cached)"))
c = json.load(open(X.KEV_CACHE)); c["fetched"] = 0; json.dump(c, open(X.KEV_CACHE, "w"))
X.GET = lambda u: (_ for _ in ()).throw(OSError("offline")) if "cisa.gov" in u else fake(u)
res2 = X.check()
r.append(ok(res2["kev_hits"] == ["CVE-2024-3400"], "CISA unreachable: the last saved catalog is used"))
os.remove(X.KEV_CACHE)
res3 = X.check()
r.append(ok(not res3["kev_hits"] and not res3["kev_checked"] and "Couldn't load CISA" in X.page(res3),
            "never fetched and unreachable: said plainly, not shown as 'none exploited'"))
X.GET = fake

# certificate checks: lookups verified, only your own device pages aren't
src = open(os.path.join(ROOT, "shield", "exposure.py")).read()
look = src[src.index("def _get(") : src.index("def _get_device(")]
r.append(ok("CERT_NONE" not in look and "create_default_context()" in look and "_get_device(f\"{scheme}://{ip}" in src
            and src.count("_get_device(") == 2, "address / InternetDB / CISA lookups check certificates; only device pages skip it"))

# weekly re-check: alert only on new
alerts = []
al = lambda title, msg, critical: alerts.append((title, msg, critical))
X.watch(log=lambda *_: None, alert=al)
r.append(ok(len(alerts) == 1 and alerts[0][2] and "CVE-2024-3400" in alerts[0][1] and "Remote Desktop" in alerts[0][1], "first weekly check alerts on what's open"))
X.watch(log=lambda *_: None, alert=al)
r.append(ok(len(alerts) == 1, "same findings next week: no repeat alert"))
db["ports"].append(5900)
X.watch(log=lambda *_: None, alert=al)
r.append(ok(len(alerts) == 2 and "VNC" in alerts[1][1] and "Remote Desktop" not in alerts[1][1], "a newly opened service alerts (only the new one)"))
json.dump({"exposure_watch": False}, open("config.json", "w"))
r.append(ok(X.watch(log=lambda *_: None, alert=al) is None and len(alerts) == 2, "can be turned off (exposure_watch: false)"))
os.remove("config.json")
from deskui import data
fd = [e for e in data.feed() if e["href"] == "/exposure"]
r.append(ok(fd and fd[0]["sec"] == "defense" and any(e["lvl"] == "stop" for e in fd), "results appear in the Online Defense feed"))

# the responder runs it at most weekly
from responder import daemon
ran = []
X.watch = lambda **k: ran.append(1)
daemon.job_exposure("http://127.0.0.1:8787")
r.append(ok(not ran, "responder skips the check when the last one is under a week old"))
st = json.load(open(X.STATE)); st["checked"] = "2026-01-01 00:00:00"; json.dump(st, open(X.STATE, "w"))
daemon.job_exposure("http://127.0.0.1:8787")
r.append(ok(ran == [1], "and runs it when the last check is older"))

os.chdir(ROOT)
shutil.rmtree(WORK, ignore_errors=True)
print(f"{sum(r)}/{len(r)} passed"); sys.exit(0 if all(r) else 1)
