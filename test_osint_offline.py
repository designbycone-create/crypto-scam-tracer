"""Offline tests for "Look up a scammer" (Maigret + SpiderFoot). Both tools are simulated.

Run: python test_osint_offline.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from osinttools import runner, web  # noqa: E402

ok = fail = 0


def check(name, cond):
    global ok, fail
    if cond:
        ok += 1
    else:
        fail += 1
        print("FAIL:", name)


REPORT = {
    "GitHub": {"url_user": "https://github.com/scam_amy", "is_similar": False,
               "status": {"status": "Claimed", "url": "https://github.com/scam_amy",
                          "ids": {"fullname": "Amy <b>Lee</b>", "location": "Phnom Penh", "uid": "123", "image": "https://x/y.png"}}},
    "Instagram": {"url_user": "https://instagram.com/scam_amy", "is_similar": True, "status": {"status": "Claimed", "url": "https://instagram.com/scam_amy"}},
    "Reddit": {"status": {"status": "Available", "url": "https://reddit.com/u/scam_amy"}},
    "Weird": {"status": {"status": "Claimed", "url": "javascript:alert(1)"}},
}
calls = []


def fake_run(args, **kw):
    calls.append(args)
    folder = args[args.index("--folderoutput") + 1]
    with open(os.path.join(folder, f"report_{args[1]}_simple.json"), "w") as f:
        json.dump(REPORT, f)
    return subprocess.CompletedProcess(args, 0, "", "")


tmp = tempfile.mkdtemp()
old = os.getcwd()
os.chdir(tmp)
home_exe = os.path.join(tmp, "maigret.exe")
open(home_exe, "w").close()
with open("config.json", "w") as f:
    json.dump({"osint_tools": {"maigret": home_exe}}, f)
try:
    # ---------- usernames ----------
    for bad in ("", "-rf", "--help", "a;b", "a b", "x", "a" * 41, "$(calc)", "../etc"):
        jid, why = runner.start_maigret(bad, wait=True)
        check(f"bad username refused: {bad!r}", jid is None and why)
    check("no process started for bad input", calls == [])

    runner.RUN = fake_run
    jid, why = runner.start_maigret("@scam_amy", wait=True)
    check("maigret job done", why is None and next(j for j in runner.jobs() if j["id"] == jid)["status"] == "done")
    a = calls[-1]
    check("arguments as a list, username after the program", a[0] == home_exe and a[1] == "scam_amy" and "--top-sites" in a)
    check("json report requested", a[a.index("--json") + 1] == "simple")
    r = runner.results(jid)
    sites = [i["site"] for i in r["items"]]
    check("only claimed accounts with web links", sites == ["GitHub", "Instagram"])
    check("possible matches marked", r["items"][1]["maybe"] is True and r["items"][0]["maybe"] is False)
    check("details kept, ids/images dropped", r["items"][0]["details"] == {"fullname": "Amy <b>Lee</b>", "location": "Phnom Penh"})
    txt = runner.ic3_text(next(j for j in runner.jobs() if j["id"] == jid), r)
    check("IC3 text lists profiles + caution", "https://github.com/scam_amy" in txt and "does not prove" in txt and "(possible match)" in txt)

    runner.RUN = lambda args, **kw: subprocess.CompletedProcess(args, 2, "", "boom: site list broken")
    jid2, _ = runner.start_maigret("someone", wait=True)
    j2 = next(j for j in runner.jobs() if j["id"] == jid2)
    check("no report = error with the reason", j2["status"] == "error" and "boom" in j2["error"])

    def slow(args, **kw):
        raise subprocess.TimeoutExpired(args, 1)
    runner.RUN = slow
    jid3, _ = runner.start_maigret("someone2", wait=True)
    check("timeout labelled", "longer than" in next(j for j in runner.jobs() if j["id"] == jid3)["error"])
    runner.RUN = fake_run

    # a Maigret run left 'running' by a restart is marked interrupted
    js = runner._load()
    js.append({"id": "aaaaaaaaaaaa", "tool": "maigret", "target": "ghost", "kind": "username", "started": "2026-11-18 20:00",
               "status": "running", "error": None, "count": None})
    runner._save(js)
    g = next(j for j in runner.jobs() if j["id"] == "aaaaaaaaaaaa")
    check("interrupted maigret job", g["status"] == "error" and "restarted" in g["error"])

    check("results id must be a job id", runner.results("../config") is None and runner.results("..\\x") is None)

    # ---------- SpiderFoot ----------
    sent = []
    states = iter(["STARTING", "RUNNING", "FINISHED"])
    ROWS = [["2026-11-18", "support@fake-exchange.com", "x", "sfp_dnsresolve", 0, "ROOT"],
            ["2026-11-18", "fake-exchange.com", "x", "sfp_email", 0, "DOMAIN_NAME"],
            ["2026-11-18", "fake-exchange.com", "x", "sfp_other", 0, "DOMAIN_NAME"],
            ["2026-11-18", "&lt;script&gt;alert(1)&lt;/script&gt;", "x", "sfp_pastebin", 0, "LEAKSITE_URL"],
            ["2026-11-18", "huge raw blob", "x", "sfp_whois", 0, "RAW_RIR_DATA"],
            ["2026-11-18", "Hosting Co", "x", "sfp_ipinfo", 0, "PROVIDER_HOSTING"],
            "garbage"]

    def sf(url, data=None):
        sent.append((url, data))
        if url.endswith("/ping"):
            return json.dumps(["SUCCESS", "4.0.0"]).encode()
        if url.endswith("/startscan"):
            return json.dumps(["SUCCESS", "SCAN1"]).encode()
        if "/scanstatus" in url:
            return json.dumps(["n", "t", "c", "s", "e", next(states, "FINISHED"), {}]).encode()
        if "/scaneventresults" in url:
            return json.dumps(ROWS).encode()
        if "/stopscan" in url:
            return b"[]"
        raise AssertionError(url)
    runner.GET = sf
    runner.SF_POLL = 0
    check("spiderfoot detected", runner.spiderfoot_status()[0])
    jid4, why = runner.start_spiderfoot("support@fake-exchange.com", wait=True)
    check("spiderfoot job done", why is None and next(j for j in runner.jobs() if j["id"] == jid4)["status"] == "done")
    start = next(d for u, d in sent if u.endswith("/startscan"))
    check("passive modules only", start["usecase"] == "passive" and start["modulelist"] == "" and start["typelist"] == "")
    check("talks only to this computer", all(u.startswith("http://127.0.0.1:5001/") for u, _ in sent))
    items = runner.results(jid4)["items"]
    types = [i["type"] for i in items]
    check("ROOT and raw blobs skipped", "ROOT" not in types and "RAW_RIR_DATA" not in types)
    check("duplicates merged", types.count("DOMAIN_NAME") == 1)
    check("friendly labels", any(i["label"] == "Hosting providers" for i in items))
    check("SpiderFoot escaping undone (page escapes once)", any(i["data"] == "<script>alert(1)</script>" for i in items))

    def target_sent(t):
        sent.clear()
        global states
        states = iter(["FINISHED"])
        jid, why = runner.start_spiderfoot(t, wait=True)
        return (next((d["scantarget"] for u, d in sent if u.endswith("/startscan")), None), why)
    check("US phone gets +1", target_sent("(251) 555-0100")[0] == "+12515550100")
    check("intl phone kept", target_sent("+44 20 7946 0000")[0] == "+442079460000")
    check("phone without country code refused", target_sent("555 0100 22")[0] is None)
    check("name quoted", target_sent("John Smith")[0] == '"John Smith"')
    check("username quoted", target_sent("scam_amy")[0] == '"scam_amy"')
    check("domain lower-cased", target_sent("Fake-Exchange.COM")[0] == "fake-exchange.com")
    for bad in ("-x", "a;b|c", "<script>", "http://evil/?q=1&x=2"):
        check(f"bad target refused: {bad!r}", target_sent(bad)[0] is None)

    with open("config.json", "w") as f:
        json.dump({"osint_tools": {"maigret": home_exe, "spiderfoot_url": "http://203.0.113.5:5001"}}, f)
    sent.clear()
    jidx, why = runner.start_spiderfoot("bob@example.com", wait=True)
    check("SpiderFoot elsewhere refused (fail closed)", jidx is None and "isn't on this computer" in why and not sent)
    with open("config.json", "w") as f:
        json.dump({"osint_tools": {"maigret": home_exe}}, f)

    def down(url, data=None):
        raise OSError("connection refused")
    runner.GET = down
    n = len(runner.jobs())
    jidy, why = runner.start_spiderfoot("bob@example.com", wait=True)
    check("SpiderFoot not running: clear message, no job", jidy is None and "isn't running" in why and len(runner.jobs()) == n)
    runner.GET = sf

    # ---------- page ----------
    js = runner._load()
    js.append({"id": "bbbbbbbbbbbb", "tool": "maigret", "target": "<img src=x onerror=alert(1)>", "kind": "username",
               "started": "2026-11-18 20:00", "status": "done", "error": None, "count": 0})
    runner._save(js)
    h = web.page(show=jid)
    check("results shown", "https://github.com/scam_amy" in h and "For your IC3 report" in h)
    check("details escaped", "Amy <b>Lee</b>" not in h and "Amy &lt;b&gt;Lee&lt;/b&gt;" in h)
    check("targets escaped", "<img src=x" not in web.page())
    h2 = web.page(show=jid4)
    check("spiderfoot results escaped", "<script>alert(1)</script>" not in h2 and "&lt;script&gt;" in h2)
    check("leads-not-proof warning", "leads, not proof" in h)
    check("passive notice", "Passive only" in web.page())
    out = web.post({"do": "maigret", "target": "--help"})
    check("post with plain strings", "look like a username" in out)
    out = web.post({"do": "delete", "id": jid})
    check("delete", runner.results(jid) is None and all(j["id"] != jid for j in runner.jobs()))
    runner.GET = None
finally:
    os.chdir(old)
    shutil.rmtree(tmp, ignore_errors=True)

# ---------- wiring ----------
from deskui import shell  # noqa: E402
check("Investigate tab lists it", any(p == "/lookup" for _, _, _, groups in shell.SECTIONS for g, pages in groups for p, _, _ in pages))
src = open(os.path.join(ROOT, "desk.py"), encoding="utf-8").read()
check("desk routes", src.count('path == "/lookup"') == 2)
from freezekit import share_web  # noqa: E402
check("lookups never shared", share_web._private("lookups/jobs.json") and share_web._private("lookups/abc.json"))

print(f"osint: {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
