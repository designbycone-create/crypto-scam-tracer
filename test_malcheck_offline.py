"""Offline tests: Malware & link check (Windows Defender status/scans, file checks, link checks,
abuse.ch lookups with the user's own encrypted key). Defender and abuse.ch are stand-ins here,
replaying responses seen on a real Windows PC and in abuse.ch's API documentation.
    python test_malcheck_offline.py
"""
import hashlib, json, os, shutil, sys, tempfile, zipfile
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
WORK = tempfile.mkdtemp(prefix="sh_mal_")
os.chdir(WORK)
ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []
import securestore as S
S.BACKEND = (lambda b: b"SEALED1" + bytes(x ^ 0x5a for x in b), lambda b: bytes(x ^ 0x5a for x in b[7:]))
from shield import defender as D, abusech as A, malcheck as M  # noqa: E402

STATUS = {"AMServiceEnabled": True, "AntivirusEnabled": True, "RealTimeProtectionEnabled": True, "IsTamperProtected": True,
          "AntivirusSignatureAge": 0, "AntivirusSignatureLastUpdated": "/Date(1794889826000)/", "QuickScanAge": 1, "FullScanAge": 4294967295,
          "AMRunningMode": "Normal"}
DET = [{"when": "/Date(1794000000000)/", "name": "Trojan:Win32/Wacatac.B!ml", "sev": 5, "where": "file:_C:\\Users\\you\\Downloads\\setup_tool.exe", "handled": True}]
EVIL = b"pretend malware bytes"
calls = []
def run(args, env, timeout):
    calls.append((args, env))
    if args[0] == "powershell":
        cmd = args[-1]
        if "Get-MpComputerStatus" in cmd: return 0, json.dumps(STATUS)
        if "Get-MpThreatDetection" in cmd: return 0, json.dumps(DET[0])
        if "Get-AuthenticodeSignature" in cmd: return 0, json.dumps({"status": "NotSigned", "signer": None})
    if "-ScanType" in args and args[args.index("-ScanType") + 1] == "3":
        p = args[args.index("-File") + 1]
        return (2, "Scanning ... found 1 threats.\nThreat                  : Trojan:Win32/Test") if open(p, "rb").read() == EVIL else (0, "found no threats")
    if "-ScanType" in args: return 0, ""
    return 1, ""
D.RUN = run
D.mpcmdrun = lambda: "MpCmdRun.exe"

s = D.status()
r.append(ok(s["ok"] and s["on"] and s["realtime"] and s["tamper"] and s["full_age"] is None and s["sig_updated"].startswith("2026-11-"),
            "Defender status read (on, real-time, tamper protected, definitions date, full scan never)"))
r.append(ok([p[0] for p in s["problems"]] == ["info"] and "never been run" in s["problems"][0][1], "healthy Defender: only the 'never had a full scan' note"))
STATUS.update(RealTimeProtectionEnabled=False, AntivirusSignatureAge=9)
s2 = D.status()
r.append(ok(s2["problems"][0][0] == "stop" and "Real-time protection is OFF" in s2["problems"][0][1] and any("9 days old" in p[1] for p in s2["problems"]),
            "real-time off = DANGER; old definitions = caution"))
STATUS.update(RealTimeProtectionEnabled=True, AntivirusSignatureAge=0)
d = D.detections()
r.append(ok(d and d[0]["name"].startswith("Trojan") and d[0]["severity"] == "severe" and d[0]["handled"], "recently caught threats listed"))
r.append(ok(not any(a[0] == "powershell" and ("Set-Mp" in a[-1] or "Add-MpPreference" in a[-1] or "Remove-Mp" in a[-1]) for a, _ in calls),
            "never changes Defender settings (only reads status and runs scans)"))

dl = os.path.join(WORK, "Downloads"); os.makedirs(dl)
M.downloads_dir = lambda: dl
w = lambda n, b: open(os.path.join(dl, n), "wb").write(b)
w("invoice.pdf.exe", b"MZ fake program")
w("photo.jpg", b"\xff\xd8 picture")
w("setup_tool.exe", EVIL)
with zipfile.ZipFile(os.path.join(dl, "docs.zip"), "w") as z:
    z.writestr("statement.pdf.js", "x")
w("name" + " " * 6 + ".pdf.scr", b"MZ")

res = M.check_file(os.path.join(dl, "invoice.pdf.exe"))
r.append(ok(res["level"] == "stop" and any("pretends to be a .pdf" in t for _, t in res["findings"]), "invoice.pdf.exe: DANGER, the double-extension trick is explained"))
r.append(ok(any("isn't digitally signed" in t for _, t in res["findings"]) or os.name != "nt", "unsigned program noted (Windows)"))
res = M.check_file(os.path.join(dl, "setup_tool.exe"))
r.append(ok(res["level"] == "stop" and any("Windows Defender found a threat" in t for _, t in res["findings"]), "Defender detection = DANGER"))
r.append(ok(any(a[0] == "MpCmdRun.exe" and a[a.index("-File") + 1].endswith("setup_tool.exe") and "-DisableRemediation" not in a for a, _ in calls),
            "Defender scans the actual file and is allowed to quarantine it"))
real_sha = M._sha256
def _blocked(p):
    raise OSError(22, "Invalid argument")
M._sha256 = _blocked
res = M.check_file(os.path.join(dl, "photo.jpg"))
M._sha256 = real_sha
r.append(ok(res["level"] == "stop" and "blocked this file" in res["findings"][0][1], "a file Windows blocks mid-check = DANGER, not a crash"))
res = M.check_file(os.path.join(dl, "photo.jpg"))
r.append(ok(res["level"] == "ok" and any("not checked (add your free abuse.ch key" in t for _, t in res["findings"]), "clean picture, no key: nothing bad found, says MalwareBazaar wasn't checked"))
res = M.check_file(os.path.join(dl, "docs.zip"))
r.append(ok(res["level"] == "caution" and any("statement.pdf.js" in t for _, t in res["findings"]), "zip containing a script: be careful, names it"))
res = M.check_file(os.path.join(dl, "name" + " " * 6 + ".pdf.scr"))
r.append(ok(res["level"] == "stop", "name padded with spaces to hide '.scr': DANGER"))
r.append(ok(M.check_file(os.path.join(dl, "nope.exe"))["findings"][0][1] == "That file wasn't found.", "missing file handled"))
html = M._result(M.check_file(os.path.join(dl, "photo.jpg")), "file")
r.append(ok("isn&#x27;t a guarantee" in html and "safe" not in html.lower(), "never says 'safe'; 'nothing bad found' comes with 'isn't a guarantee'"))

# abuse.ch with the user's own key (stored encrypted)
r.append(ok(A.key_id() is None, "no key yet"))
kid = A.save_key("my-abuse-ch-key-123")
raw = open("config.json").read()
r.append(ok(kid == hashlib.sha256(b"my-abuse-ch-key-123").hexdigest()[:8] and "my-abuse-ch-key-123" not in raw and A.key() == "my-abuse-ch-key-123",
            "key saved encrypted; only its short ID is shown"))
sent = []
EVIL_SHA = hashlib.sha256(EVIL).hexdigest()
def post(url, body, hdr):
    sent.append((url, body, hdr))
    if hdr.get("Auth-Key") != "my-abuse-ch-key-123": return {"query_status": "http_401"}
    if "mb-api" in url:
        return {"query_status": "ok", "data": [{"signature": "RedLineStealer", "first_seen": "2026-10-01 10:00:00"}]} if EVIL_SHA.encode() in body else {"query_status": "hash_not_found"}
    if url.endswith("/url/"):
        return {"query_status": "ok", "url_status": "online", "threat": "malware_download"} if b"evil-download" in body else {"query_status": "no_results"}
    if url.endswith("/host/"):
        return {"query_status": "ok", "url_count": 3, "urls": [{"url_status": "online"}, {"url_status": "offline"}]} if b"bad-host.example" in body else {"query_status": "no_results"}
    if "threatfox" in url:
        return {"query_status": "ok", "data": [{"malware_printable": "Lumma Stealer"}]} if b"c2.example" in body else {"query_status": "no_result"}
    return {"query_status": "no_results"}
A.POST = post
res = M.check_file(os.path.join(dl, "setup_tool.exe"))
r.append(ok(any("RedLineStealer" in t for _, t in res["findings"]), "MalwareBazaar recognises a known malware file by fingerprint"))
r.append(ok(all(EVIL not in b for _, b, _ in sent) and any(EVIL_SHA.encode() in b for _, b, _ in sent), "only the fingerprint is sent, never the file"))
r.append(ok(M.check_file(os.path.join(dl, "photo.jpg"))["level"] == "ok" and any("Not in MalwareBazaar" in t for _, t in M.check_file(os.path.join(dl, "photo.jpg"))["findings"]),
            "unknown file: 'not in MalwareBazaar', with the 'new malware may not be there yet' caveat"))
lk = M.check_link("http://evil-download.example/payload.exe")
r.append(ok(lk["level"] == "stop" and any("URLhaus lists this exact link" in t for _, t in lk["findings"]), "URLhaus-listed link: DANGER"))
r.append(ok(M.check_link("https://bad-host.example/x")["level"] == "stop", "site with URLhaus malware links: DANGER"))
r.append(ok(any("Lumma" in t for _, t in M.check_link("c2.example/login")["findings"]), "ThreatFox-listed site named"))
pp = M.check_link("https://paypal-account-verify.top/login")
r.append(ok(pp["level"] == "stop" and any("isn't paypal's website" in t for _, t in pp["findings"]), "look-alike PayPal link: DANGER even if abuse.ch doesn't know it"))
r.append(ok(M.check_link("https://www.irs.gov/")["level"] == "ok", "an ordinary site: nothing bad found"))
A.save_key("wrong")
r.append(ok(any("didn't accept your Auth-Key" in t for _, t in M.check_link("https://www.irs.gov/")["findings"]), "a wrong key is reported plainly"))
A.save_key("my-abuse-ch-key-123")

# page and Desk wiring
page = M.page()
r.append(ok("Windows Defender" in page and "invoice.pdf.exe" in page and "Key ID" in page and "my-abuse-ch-key" not in page, "page: Defender, recent downloads, key ID (never the key)"))
out = M.post({"do": "file", "i": "0"})
r.append(ok("Result for" in out, "checking a download from the list works"))
out = M.post({"do": "file", "i": "99"})
r.append(ok("no longer in the list" in out, "a stale download number is refused"))
r.append(ok("DANGER" in M.post({"do": "link", "url": "http://evil-download.example/payload.exe"}), "link form works"))
r.append(ok("quick" in M.post({"do": "quickscan"}).lower(), "quick scan can be started"))
from deskui import shell, data
src = open(os.path.join(ROOT, "desk.py"), encoding="utf-8").read()
r.append(ok(shell.section_for("/malware")[0] == "defense" and src.count('"/malware"') == 2, "in the Online Defense tab with GET and POST routes"))
r.append(ok(any(x["href"] == "/malware" for x in data.feed()) and not any("evil-download" in x["detail"] + x["title"] for x in data.feed()),
            "checks appear in the live feed by result only (no file names or links)"))

os.chdir(ROOT)
shutil.rmtree(WORK, ignore_errors=True)
print(f"{sum(r)}/{len(r)} passed"); sys.exit(0 if all(r) else 1)
