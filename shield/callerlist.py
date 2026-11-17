"""Reported scam / robocall numbers from the FTC, for warning people before they answer.

Source: the FTC's Do Not Call "reported calls" data (the caller number, date, subject and
robocall flag of every unwanted call consumers report), through the FTC's official API
(https://api.ftc.gov/v0/dnc-complaints). Phone carriers use the same data for call blocking.
The FTC does not verify reports, and scammers spoof innocent people's numbers, so a number is
only flagged by HOW MANY separate reports it has, and how recently -- never on one report.

The API needs a free key from https://api.data.gov/signup/ (config.json "ftc_api_key", or the
FTC_API_KEY environment variable). The key is never printed or logged.

    python -m shield.callerlist update [--days 30]   # fetch new days, rebuild the list
    python -m shield.callerlist check 8335551234      # what's known about a number
    python -m shield.callerlist export out.json.gz    # compact list for the phone app

Files: callers_daily/YYYY-MM-DD.json (one file per day of reports, kept WINDOW days),
callers.json (the merged list).
"""
import gzip
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta

API = "https://api.ftc.gov/v0/dnc-complaints"
WINDOW = 30                 # days of reports kept in the list
PAGE = 50                   # the API's maximum page size
DAILY_DIR = "callers_daily"
LIST = "callers.json"
UA = {"User-Agent": "ScamHunter/1.0 (scam-call warning list; github.com/designbycone-create/crypto-scam-tracer)"}
GET = None                  # test hook: f(url) -> dict

# How a number is rated. Reports are unverified, so the bar rises with the claim.
LEVELS = [(10, "high", "Reported {n} times in the last {d} days"),
          (3, "medium", "Reported {n} times in the last {d} days"),
          (1, "low", "Reported once or twice in the last {d} days")]
# subjects the FTC uses that point to fraud rather than sales calls
FRAUD_SUBJECTS = re.compile(r"imposter|impostor|government|social security|irs|medicare|bank|computer|tech|warranty|"
                            r"prize|sweepstakes|lottery|debt|loan|grant|charit|crypto|investment|utility|police|"
                            r"family|kidnap|romance", re.I)


def key():
    k = os.environ.get("FTC_API_KEY")
    if not k:
        try:
            with open("config.json", encoding="utf-8-sig") as f:
                k = json.load(f).get("ftc_api_key")
        except Exception:
            k = None
    return k


def norm(number):
    """US 10-digit number, or None. Accepts +1, dashes, spaces, parentheses."""
    d = re.sub(r"\D", "", str(number or ""))
    if len(d) == 11 and d[0] == "1":
        d = d[1:]
    return d if len(d) == 10 and d[0] in "23456789" and d[3] in "23456789" else None


class RateLimited(RuntimeError):
    """The FTC refused because the key's hourly request allowance is used up (HTTP 429)."""


def _get(url):
    if GET:
        return GET(url)
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return json.loads(r.read())


def fetch_day(day, api_key, log=print, max_pages=600):
    """All reports created on one day -> {number: {"n", "robo", "subjects": {..}}}."""
    out, offset, pages = {}, 0, 0
    d = day.isoformat()
    while pages < max_pages:
        q = urllib.parse.urlencode({"api_key": api_key, "items_per_page": PAGE, "offset": offset,
                                    "created_date_from": f'"{d} 00:00:00"', "created_date_to": f'"{d} 23:59:59"'})
        try:
            data = _get(f"{API}?{q}").get("data") or []
        except urllib.error.HTTPError as ex:
            if ex.code == 429:
                wait = ex.headers.get("Retry-After") if ex.headers else None
                raise RateLimited(f"FTC refused: the API key's hourly request allowance is used up"
                                  + (f" (resets in about {int(wait) // 60} min)" if str(wait or "").isdigit() else "")) from None
            raise RuntimeError(f"FTC API failed on {d} at offset {offset}: HTTP {ex.code}") from None
        except Exception as ex:
            msg = str(ex).replace(api_key, "***")                 # never let the key reach a log
            raise RuntimeError(f"FTC API failed on {d} at offset {offset}: {msg}") from None
        pages += 1
        for row in data:
            a = row.get("attributes") or {}
            num = norm(a.get("company-phone-number"))
            created = str(a.get("created-date") or "")
            if not num or not created.startswith(d):               # the API returns some malformed rows: skip them
                continue
            e = out.setdefault(num, {"n": 0, "robo": 0, "subjects": {}})
            e["n"] += 1
            e["robo"] += a.get("recorded-message-or-robocall") == "Y"
            s = (a.get("subject") or "").strip()[:80]
            if s:
                e["subjects"][s] = e["subjects"].get(s, 0) + 1
        if len(data) < PAGE:
            break
        offset += PAGE
    log(f"FTC reports {d}: {sum(e['n'] for e in out.values())} reports, {len(out)} numbers, {pages} page(s)")
    return out


def update(days=WINDOW, api_key=None, log=print, today=None, max_new_days=10):
    """Fetch days not fetched yet (newest first, a few per run so the free key's hourly limit holds),
    drop days older than the window, rebuild the list.
    If the FTC says the hourly allowance is used up, stop asking (retrying can't succeed), keep the
    days already saved, and build the list from them; the rest are fetched on a later run.
    The list records how many days it covers, so it never claims more than it has."""
    api_key = api_key or key()
    if not api_key:
        raise RuntimeError("no FTC API key: get a free one at https://api.data.gov/signup/ and save it as ftc_api_key")
    os.makedirs(DAILY_DIR, exist_ok=True)
    today = today or date.today()
    wanted = [today - timedelta(days=i) for i in range(1, days + 1)]      # yesterday back; today isn't complete yet
    have = {f[:-5] for f in os.listdir(DAILY_DIR) if f.endswith(".json")}
    fetched = 0
    for d in wanted:
        if d.isoformat() in have or fetched >= max_new_days:
            continue
        try:
            rows = fetch_day(d, api_key, log)
        except RateLimited as ex:
            log(f"{ex}. Kept the days already downloaded; the rest come on a later run.")
            break
        tmp = os.path.join(DAILY_DIR, d.isoformat() + ".json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rows, f)
        os.replace(tmp, os.path.join(DAILY_DIR, d.isoformat() + ".json"))
        fetched += 1
    keep = {d.isoformat() for d in wanted}
    for f in os.listdir(DAILY_DIR):
        if f.endswith(".json") and f[:-5] not in keep:
            os.remove(os.path.join(DAILY_DIR, f))
    return build(days)


def build(days=WINDOW):
    merged = {}
    files = sorted(f for f in os.listdir(DAILY_DIR) if f.endswith(".json")) if os.path.isdir(DAILY_DIR) else []
    for f in files:
        day = f[:-5]
        with open(os.path.join(DAILY_DIR, f), encoding="utf-8") as fh:
            rows = json.load(fh)
        for num, e in rows.items():
            m = merged.setdefault(num, {"n": 0, "robo": 0, "subjects": {}, "last": day, "first": day})
            m["n"] += e["n"]
            m["robo"] += e["robo"]
            m["last"] = max(m["last"], day)
            m["first"] = min(m["first"], day)
            for s, c in e["subjects"].items():
                m["subjects"][s] = m["subjects"].get(s, 0) + c
    lst = {"source": "FTC Do Not Call reported calls (api.ftc.gov), unverified consumer reports",
           "days": len(files), "from": files[0][:-5] if files else None, "to": files[-1][:-5] if files else None,
           "built": datetime.now().strftime("%Y-%m-%d %H:%M"), "numbers": merged}
    tmp = LIST + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(lst, f)
    os.replace(tmp, LIST)
    return lst


def load():
    try:
        with open(LIST, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"numbers": {}, "days": 0}


def rate(e, days):
    """{"level", "headline", "subject", "robocall", "fraud"} for one list entry."""
    if not e:
        return {"level": "none", "headline": "No reports in the FTC data we have", "subject": None, "robocall": False, "fraud": False}
    top = max(e["subjects"].items(), key=lambda kv: kv[1])[0] if e["subjects"] else None
    fraud = bool(top and FRAUD_SUBJECTS.search(top))
    for floor, level, text in LEVELS:
        if e["n"] >= floor:
            if fraud and level == "medium":
                level = "high"              # several reports AND an impostor / fraud subject
            return {"level": level, "headline": text.format(n=e["n"], d=days), "subject": top,
                    "robocall": e["robo"] * 2 >= e["n"], "fraud": fraud}
    return {"level": "none", "headline": "", "subject": None, "robocall": False, "fraud": False}


def check(number, lst=None):
    n = norm(number)
    if not n:
        return {"ok": False, "error": "That isn't a US phone number (10 digits)."}
    lst = lst or load()
    e = lst.get("numbers", {}).get(n)
    r = rate(e, lst.get("days") or WINDOW)
    r.update({"ok": True, "number": n, "reports": (e or {}).get("n", 0), "last": (e or {}).get("last"),
              "list_days": lst.get("days", 0), "list_to": lst.get("to")})
    return r


def export(path, lst=None, min_reports=1):
    """Compact list for the phone: {"to":..,"days":..,"n":{number:[reports,robo,subject_code,last_day_offset]},"s":[subjects]}."""
    lst = lst or load()
    subjects, idx, n = [], {}, {}
    to = datetime.strptime(lst["to"], "%Y-%m-%d").date() if lst.get("to") else date.today()
    for num, e in lst.get("numbers", {}).items():
        if e["n"] < min_reports:
            continue
        top = max(e["subjects"].items(), key=lambda kv: kv[1])[0] if e["subjects"] else ""
        if top not in idx:
            idx[top] = len(subjects)
            subjects.append(top)
        age = (to - datetime.strptime(e["last"], "%Y-%m-%d").date()).days
        n[num] = [e["n"], e["robo"], idx[top], age]
    data = {"v": 1, "source": lst.get("source"), "to": lst.get("to"), "days": lst.get("days"), "s": subjects, "n": n}
    raw = json.dumps(data, separators=(",", ":")).encode()
    with gzip.open(path, "wb") if path.endswith(".gz") else open(path, "wb") as f:
        f.write(raw)
    return {"numbers": len(n), "bytes": os.path.getsize(path)}


# ---------------------------------------------------------------- Desk page /numbercheck ----

def page(number="", result=None):
    import html
    e = lambda s: html.escape(str(s if s is not None else ""), quote=True)
    lst = load()
    status = (f"List: {lst.get('days', 0)} days of FTC reports up to {e(lst.get('to'))}, {len(lst.get('numbers', {})):,} numbers."
              if lst.get("days") else "The FTC list hasn't been downloaded yet. It needs a free api.data.gov key (ftc_api_key in config.json).")
    res = ""
    if result:
        if not result.get("ok"):
            res = f"<div class='box medium'>{e(result['error'])}</div>"
        else:
            color = {"high": "stop", "medium": "caution", "low": "info", "none": "info"}[result["level"]]
            res = (f"<div class='box {color}'><b style='font-size:24px'>{e(result['headline'] or 'No reports found')}</b>"
                   + (f"<br>Most reported as: {e(result['subject'])}" if result.get("subject") else "")
                   + ("<br>Most reports say it was a recorded message (robocall)." if result.get("robocall") else "")
                   + "</div><p>Reports are from people who got calls and are not verified by the FTC. Scammers also fake real people's "
                     "numbers, so a reported number may belong to someone innocent. No reports doesn't mean a call is safe.</p>")
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Check a phone number</title><style>body{{font:20px/1.5 Segoe UI,Arial,sans-serif;max-width:860px;margin:24px auto;padding:0 16px;color:#111}}
input{{font-size:22px;padding:8px;width:260px}}button{{font-size:20px;padding:8px 18px}}.box{{border:2px solid #ddd;border-radius:10px;padding:14px;margin:14px 0}}
.stop{{background:#fdecee;border-color:#b00020}}.caution{{background:#fff8e6;border-color:#f2b01e}}.info{{background:#eef3fb;border-color:#9bb}}
.hint{{color:#444;font-size:16px}}</style></head><body><p><a href="/">&larr; Desk</a></p><h1>Has this phone number been reported?</h1>
<form method=post action=/numbercheck><input name=number value="{e(number)}" placeholder="(555) 123-4567"> <button>Check</button></form>{res}
<p class=hint>{status}</p></body></html>"""


def post(form):
    num = form.get("number", "")
    return page(num, check(num))


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["update"]:
        days = int(a[a.index("--days") + 1]) if "--days" in a else WINDOW
        lst = update(days)
        print(f"{lst['days']} days, {len(lst['numbers'])} numbers")
    elif a[:1] == ["check"] and len(a) > 1:
        print(json.dumps(check(a[1]), indent=1))
    elif a[:1] == ["export"] and len(a) > 1:
        print(export(a[1]))
    else:
        print(__doc__)
