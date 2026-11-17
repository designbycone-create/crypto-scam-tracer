"""Offline tests: the Desk's tabs (every page in exactly one section, same header everywhere),
the Overview / section pages, the live data feed, and the status-file fix.
    python test_desk_tabs_offline.py
"""
import json, os, shutil, sys, tempfile, threading, time, urllib.request, urllib.error
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
WORK = tempfile.mkdtemp(prefix="sh_tabs_")
os.chdir(WORK)
ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []

from deskui import shell, data  # noqa: E402

# --- every page belongs to exactly one section
paths = [p for _, _, _, groups in shell.SECTIONS for _, pages in groups for p, _, _ in pages]
r.append(ok(len(paths) == len(set(paths)), "no page is filed under two sections"))
src = open(os.path.join(ROOT, "desk.py"), encoding="utf-8").read()
r.append(ok(all(f'"{p}"' in src for p in paths), "every page in the tabs has a route in the Desk"))
r.append(ok(shell.section_for("/prescreen")[0] == "crypto" and shell.section_for("/numbercheck")[0] == "phone"
            and shell.section_for("/agentguard")[0] == "defense" and shell.section_for("/update")[0] == "settings",
            "pages land in the right tab (crypto / phone / defense / settings)"))

# --- header placement
w = shell.wrap("<!doctype html><html><head><style>x</style></head><body class=a><h1>Hi</h1></body></html>", "/msgcheck")
r.append(ok(w.index("id=sh-shell") > w.index("<body class=a>") and w.index("id=sh-shell") < w.index("<h1>"), "header goes right after <body>"))
w2 = shell.wrap("<!doctype html><meta charset=utf-8><style>b</style><h2>Checking</h2>", "/prescreen")
r.append(ok(w2.index("id=sh-shell") > w2.index("</style>") and w2.index("id=sh-shell") < w2.index("<h2>"), "pages without <body> still get the header"))
r.append(ok(shell.wrap("<html><body>packet</body></html>", "/kit/_case/officer_packet.html") == "<html><body>packet</body></html>",
            "printable officer packets stay clean (no header)"))
r.append(ok(shell.wrap(w, "/msgcheck").count("id=sh-shell") == 1, "never added twice"))
h = shell.header("/numbercheck")
r.append(ok("sh-tab on' href='/phone'" in h and "sh-pill on' href='/numbercheck'" in h and "/msgcheck" in h and "/prescreen" not in h,
            "Phone tab shows only its own pages, with the current one highlighted"))

# --- data: noise filtered, duplicates collapsed, UTC converted, sensitive text never logged
with open("mc_events.log", "w") as f:
    f.write("[2026-11-17 06:40:57] no change\n" * 50 + "[2026-11-16 18:56:54] CHANGE: +302 nodes\n")
with open("prescreen_log.jsonl", "w") as f:
    f.write(json.dumps({"time": "2026-11-17 03:00:37 UTC", "address": "0x08723392ed15743cc38513c4925f5e6be5c17243", "chain": "ethereum",
                        "verdict": "STOP", "findings": ["OFAC sanctioned"]}) + "\n")
with open("netwatch_events.log", "w") as f:
    f.write("[2026-11-16 21:50:33] cash-out: 4724 XRP -> KuCoin\n" * 5)
fd = data.feed()
r.append(ok(not any("no change" in x["detail"] for x in fd) and any("+302" in x["detail"] for x in fd), "'no change' noise is left out of the feed"))
r.append(ok(sum(1 for x in fd if "KuCoin" in x["detail"]) == 1, "the same event logged five times shows once"))
pre = next(x for x in fd if x["title"].startswith("Address checked"))
from datetime import datetime, timezone
want = datetime(2026, 11, 17, 3, 0, 37, tzinfo=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
r.append(ok(pre["t"] == want and pre["lvl"] == "stop" and "OFAC" in pre["detail"], "address checks: UTC time shown in local time, STOP with its reason"))
data.note("phone", "stop", "Message checked: LIKELY SCAM", "gift_cards", "/msgcheck")
r.append(ok(any(x["title"] == "Message checked: LIKELY SCAM" for x in data.feed()), "Desk checks appear in the feed"))

# --- corrupted status file (two copies glued together) is still read; an unreadable one is not called healthy
with open("desk_status.json", "w") as f:
    f.write(json.dumps({"services": {"Responder": {"alive": True}, "Wallet watcher": {"alive": False}}}) + '"Wallet watcher": {"alive": true}}}')
s = data.services()
r.append(ok(s["total"] == 2 and s["down"] == ["Wallet watcher"], "a status file with a second copy glued on is read correctly"))
os.remove("desk_status.json")
from deskui import pages
r.append(ok("WATCHER STATUS UNKNOWN" in pages.JS and "s.total>0" in pages.JS, "no status file: the page says UNKNOWN, never 'all systems live'"))

# --- the Desk status writer: reproduce the collision that corrupted the file on Matt's PC.
# Writer 1 has opened the file and is about to write a SHORT status; meanwhile writer 2 writes a LONG one.
import desk
real_dump, fired = json.dump, []
def slow_dump(obj, f, *a, **k):
    if not fired:
        fired.append(1)
        t = threading.Thread(target=lambda: (desk._state.update({f"svc{i}": {"alive": True, "started": "2026-11-16 21:50:22"} for i in range(8)}),
                                             desk._write_status()))
        t.start(); t.join(0.5)
        obj = {"updated": "short", "services": {}}
        real_dump(obj, f, *a, **k)
        t.join(5)
        return
    return real_dump(obj, f, *a, **k)
desk._state.clear()
json.dump = slow_dump
try:
    desk._write_status()
finally:
    json.dump = real_dump
try:
    json.load(open(desk.STATUS_FILE)); good = True
except ValueError:
    good = False
r.append(ok(good, "two status writes colliding (short + long) leave a readable file"))

# --- the real server: pages, header everywhere, live.json only for the Desk itself
with open("config.json", "w") as f:
    json.dump({"scam_wallet": "rwW2ExampleWallet"}, f)
from http.server import ThreadingHTTPServer
srv = ThreadingHTTPServer(("127.0.0.1", 0), desk.Handler)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
def get(p, host=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{p}", headers={"Host": host} if host else {})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as ex:
        return ex.code, ""
bad = []
for p in ["/", "/case", "/crypto", "/phone", "/defense", "/settings", "/numbercheck", "/msgcheck", "/prescreen", "/shield",
          "/clipguard", "/exposure", "/agentguard", "/extension", "/sitewatch", "/evidence", "/requests", "/alerts", "/update"]:
    code, body = get(p)
    if code != 200 or body.count("id=sh-shell") != 1:
        bad.append((p, code, body.count("id=sh-shell")))
r.append(ok(not bad, f"every page loads with exactly one header {bad or ''}"))
code, body = get("/live.json?days=7")
d = json.loads(body) if code == 200 else {}
r.append(ok(code == 200 and {"phone", "crypto", "defense", "feed", "services"} <= set(d), "live.json gives every section's numbers"))
r.append(ok(get("/live.json", host="evil.example")[0] == 403, "live.json refuses a page served from another host name (DNS rebinding)"))
code, body = get("/")
r.append(ok("window.__D=" in body and "<\\/" not in body.split("window.__D=")[1][:0] and "Live map" in body, "Overview has the map and its data built in"))
code, body = get("/case")
r.append(ok("<h1>My case</h1>" in body and "<div class=nav" not in body, "My case page keeps its content, old one-line menu removed"))
srv.shutdown()

os.chdir(ROOT)
shutil.rmtree(WORK, ignore_errors=True)
print(f"{sum(r)}/{len(r)} passed"); sys.exit(0 if all(r) else 1)
