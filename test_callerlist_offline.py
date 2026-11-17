"""Offline tests: FTC reported-calls list (fetching, rating, export for the phone) and the shared phone rules.
    python test_callerlist_offline.py
"""
import gzip, json, os, shutil, subprocess, sys, tempfile
from datetime import date
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
WORK = tempfile.mkdtemp(prefix="sh_calls_")
os.chdir(WORK)
from shield import callerlist as C  # noqa: E402

ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []
KEY = "SECRETKEY123456"
calls = []

def row(num, day, subject="Imposters - Government", robo="Y"):
    return {"attributes": {"company-phone-number": num, "created-date": f"{day} 10:00:00", "subject": subject,
                           "recorded-message-or-robocall": robo}}

def fake(url):
    calls.append(url)
    from urllib.parse import urlparse, parse_qs
    q = parse_qs(urlparse(url).query)
    day = q["created_date_from"][0].strip('"')[:10]
    off = int(q["offset"][0])
    if day == "2026-11-15":
        rows = [row("8335551234", day)] * 50 if off == 0 else [row("8335551234", day)] * 7 + [row("2025550199", day, "Home improvement", "N")]
        rows += [{"attributes": {"company-phone-number": "06/10/2026", "created-date": "20261235", "subject": "x"}}]   # malformed row, as the real API returns
        return {"data": rows if off <= 50 else []}
    if day == "2026-11-14":
        return {"data": [row("2025550199", day, "Home improvement", "N"), row("+1 (909) 555-0100", day, "Warranties")] if off == 0 else []}
    return {"data": []}

C.GET = fake
lst = C.update(days=3, api_key=KEY, log=lambda *_: None, today=date(2026, 11, 16))
n = lst["numbers"]
r.append(ok(n["8335551234"]["n"] == 57, "pages followed until the API runs out (57 reports over 2 pages)"))
r.append(ok("06/10/2026" not in json.dumps(n) and len(n) == 3, "malformed API rows skipped"))
r.append(ok(n["9095550100"]["n"] == 1, "+1 and punctuation normalised"))
r.append(ok(lst["days"] == 3 and lst["to"] == "2026-11-15", "window covers yesterday back 3 days (today isn't complete)"))
r.append(ok(all('created_date_from=%222026-11-' in u for u in calls), "queries use the API's quoted date filter"))
before = len(calls)
C.update(days=3, api_key=KEY, log=lambda *_: None, today=date(2026, 11, 16))
r.append(ok(len(calls) == before, "days already fetched aren't fetched again"))
c1 = C.check("(833) 555-1234")
r.append(ok(c1["level"] == "high" and c1["robocall"] and "57 times" in c1["headline"], "heavily reported impostor number: high"))
r.append(ok(C.check("202-555-0199")["level"] == "low" and C.rate({"n": 4, "robo": 0, "subjects": {"Home improvement": 4}}, 30)["level"] == "medium",
            "sales-call subject stays low/medium"))
r.append(ok(C.rate({"n": 4, "robo": 0, "subjects": {"Imposters - Government": 4}}, 30)["level"] == "high", "a few reports + impostor subject: high"))
r.append(ok(C.rate({"n": 1, "robo": 1, "subjects": {"Imposters - Government": 1}}, 30)["level"] == "low", "never high on a single report"))
r.append(ok(not C.check("555-1234")["ok"], "non-US / short numbers refused"))
try:
    C.GET = lambda u: (_ for _ in ()).throw(OSError(f"HTTP 429 for {u}"))
    os.remove(os.path.join(C.DAILY_DIR, "2026-11-15.json"))
    C.update(days=3, api_key=KEY, log=lambda *_: None, today=date(2026, 11, 16))
    r.append(ok(False, "API failure raises"))
except RuntimeError as ex:
    r.append(ok(KEY not in str(ex) and "***" in str(ex), "the API key never appears in an error message"))
C.GET = fake
C.update(days=3, api_key=KEY, log=lambda *_: None, today=date(2026, 11, 16))
info = C.export("callers.json.gz")
pub = json.loads(gzip.open("callers.json.gz").read())
r.append(ok(info["numbers"] == 3 and pub["n"]["8335551234"][0] == 57 and pub["s"][pub["n"]["8335551234"][2]] == "Imposters - Government",
            "compact phone list exported (counts and subjects)"))
r.append(ok("Reported 57 times" in C.post({"number": "8335551234"}), "Desk number-check page shows the result"))

# the phone app's rules are the Desk's rules
os.chdir(ROOT)
chk = subprocess.run([sys.executable, "tools/export_mobile_rules.py", "--check"], capture_output=True, text=True)
r.append(ok(chk.returncode == 0, "phone app rules + parity sample are up to date with the Desk checker (" + chk.stdout.strip() + ")"))
shutil.rmtree(WORK, ignore_errors=True)
print(f"{sum(r)}/{len(r)} passed"); sys.exit(0 if all(r) else 1)
