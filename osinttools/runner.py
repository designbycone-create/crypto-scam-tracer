"""Start Maigret / SpiderFoot lookups in the background, keep their status, read their results.

Jobs live in lookups/jobs.json; each finished job's results in lookups/<id>.json.
"""
import json
import os
import re
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

DIR = "lookups"
JOBS = os.path.join(DIR, "jobs.json")
_lock = threading.RLock()
_threads = {}
MAIGRET_TOP = 500
MAIGRET_LIMIT = 20 * 60          # seconds
SF_LIMIT = 3 * 3600
SF_POLL = 15
RUN = subprocess.run              # test hook
GET = None                        # test hook: f(url, data=None) -> bytes

USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{1,39}")
SF_TARGET = re.compile(r"[\w@.+:()\-\" ']{3,100}")


# ---------------------------------------------------------------- settings ----

def _cfg():
    try:
        with open("config.json", encoding="utf-8-sig") as f:
            return json.load(f).get("osint_tools") or {}
    except Exception:
        return {}


def maigret_path():
    p = _cfg().get("maigret")
    if p and os.path.isfile(p):
        return p
    home = os.path.expanduser("~")
    for cand in (os.path.join(home, "osint", "maigret-venv", "Scripts", "maigret.exe"),
                 os.path.join(home, "osint", "maigret-venv", "bin", "maigret")):
        if os.path.isfile(cand):
            return cand
    return None


def spiderfoot_url():
    """Only a SpiderFoot on this computer is used (fail closed on anything else)."""
    u = (_cfg().get("spiderfoot_url") or "http://127.0.0.1:5001").rstrip("/")
    host = urllib.parse.urlsplit(u).hostname or ""
    return u if host in ("127.0.0.1", "localhost", "::1") else None


def _http(url, data=None, timeout=30):
    if GET:
        return GET(url, data)
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def spiderfoot_status():
    """(ok, text) -- is SpiderFoot running and answering on this computer?"""
    u = spiderfoot_url()
    if not u:
        return False, "the SpiderFoot address in config.json isn't on this computer, so it isn't used"
    try:
        r = json.loads(_http(u + "/ping", timeout=5))
        return (True, f"SpiderFoot {r[1]} is running") if r and r[0] == "SUCCESS" else (False, "SpiderFoot answered oddly")
    except Exception as ex:
        return False, f"SpiderFoot isn't running at {u} ({str(ex)[:60]})"


# ---------------------------------------------------------------- jobs ----

def _load():
    try:
        with open(JOBS, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save(jobs):
    os.makedirs(DIR, exist_ok=True)
    with open(JOBS + ".tmp", "w", encoding="utf-8") as f:
        json.dump(jobs, f, indent=1)
    os.replace(JOBS + ".tmp", JOBS)


def _update(jid, **kw):
    with _lock:
        jobs = _load()
        for j in jobs:
            if j["id"] == jid:
                j.update(kw)
        _save(jobs)


def jobs():
    with _lock:
        js = _load()
    for j in js:      # a Maigret run can't survive a Desk restart; a SpiderFoot scan keeps running inside SpiderFoot
        if j["status"] == "running" and j["id"] not in _threads:
            if j["tool"] == "maigret":
                _update(j["id"], status="error", error="interrupted when the Desk restarted; start it again")
                j.update(status="error", error="interrupted when the Desk restarted; start it again")
            elif j.get("sf_id"):
                _start_thread(j["id"], _sf_poll, j["id"])
    return sorted(js, key=lambda j: j["started"], reverse=True)


def results(jid):
    if not re.fullmatch(r"[0-9a-f]{12}", jid or ""):
        return None
    try:
        with open(os.path.join(DIR, jid + ".json"), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _new(tool, target, kind):
    jid = os.urandom(6).hex()
    with _lock:
        js = _load()
        js.append({"id": jid, "tool": tool, "target": target, "kind": kind, "started": time.strftime("%Y-%m-%d %H:%M"),
                   "status": "running", "error": None, "count": None})
        _save(js)
    return jid


def _start_thread(key, fn, *args):
    t = threading.Thread(target=fn, args=args, daemon=True)
    _threads[key] = t
    t.start()


def _finish(jid, items, extra=None):
    os.makedirs(DIR, exist_ok=True)
    with open(os.path.join(DIR, jid + ".json"), "w", encoding="utf-8") as f:
        json.dump({"items": items, **(extra or {})}, f, indent=1)
    _update(jid, status="done", count=len(items), finished=time.strftime("%Y-%m-%d %H:%M"))


# ---------------------------------------------------------------- Maigret ----

def start_maigret(username, wait=False):
    """(job id, None) or (None, why not)."""
    u = (username or "").strip().lstrip("@")
    if not USERNAME.fullmatch(u):
        return None, "That doesn't look like a username (letters, numbers, dot, dash or underscore; 2 to 40 characters)."
    exe = maigret_path()
    if not exe:
        return None, "Maigret isn't installed where the Desk looks for it (see the setup notes on this page)."
    jid = _new("maigret", u, "username")
    if wait:
        _maigret(jid, exe, u)
    else:
        _start_thread(jid, _maigret, jid, exe, u)
    return jid, None


def parse_maigret(report):
    out = []
    for site, r in (report or {}).items():
        st = (r or {}).get("status") or {}
        if st.get("status") != "Claimed":
            continue
        ids = st.get("ids") or {}
        details = {k: ids[k] for k in ("fullname", "location", "created_at", "bio", "company", "website") if ids.get(k)}
        url = st.get("url") or r.get("url_user") or ""
        if not url.startswith(("https://", "http://")):
            continue
        out.append({"site": site, "url": url, "details": details, "maybe": bool(r.get("is_similar"))})
    return sorted(out, key=lambda x: (x["maybe"], x["site"].lower()))


def _maigret(jid, exe, user):
    try:
        with tempfile.TemporaryDirectory() as tmp:
            args = [exe, user, "--json", "simple", "--folderoutput", tmp, "--top-sites", str(MAIGRET_TOP),
                    "--timeout", "15", "--retries", "0", "--no-progressbar", "--no-color"]
            kw = {"creationflags": 0x08000000} if os.name == "nt" else {}          # no console window
            p = RUN(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=MAIGRET_LIMIT, **kw)
            rep = os.path.join(tmp, f"report_{user}_simple.json")
            if not os.path.exists(rep):
                raise RuntimeError(f"Maigret finished without a report (exit {p.returncode}): {(p.stderr or p.stdout or '')[-150:].strip()}")
            with open(rep, encoding="utf-8") as f:
                items = parse_maigret(json.load(f))
        _finish(jid, items, {"tool_note": f"Maigret, top {MAIGRET_TOP} sites"})
    except subprocess.TimeoutExpired:
        _update(jid, status="error", error=f"took longer than {MAIGRET_LIMIT // 60} minutes and was stopped")
    except Exception as ex:
        _update(jid, status="error", error=str(ex)[:200])
    finally:
        _threads.pop(jid, None)


# ---------------------------------------------------------------- SpiderFoot ----

def target_kind(t):
    t = t.strip().strip('"').strip()
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", t):
        return "email"
    if re.fullmatch(r"\+?[\d\s().-]{7,20}", t) and sum(c.isdigit() for c in t) >= 7:
        return "phone"
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", t):
        return "IP address"
    if re.fullmatch(r"([a-z0-9-]+\.)+[a-z]{2,}", t.lower()):
        return "domain"
    if re.fullmatch(r"[A-Za-z][A-Za-z.'-]*( [A-Za-z][A-Za-z.'-]*){1,3}", t):
        return "name"
    if USERNAME.fullmatch(t):
        return "username"
    return None


def start_spiderfoot(target, wait=False):
    t = (target or "").strip()
    kind = target_kind(t)
    if t.startswith("-") or not SF_TARGET.fullmatch(t) or not kind:
        return None, ("SpiderFoot needs an email address, phone number, website or domain, IP address, username, "
                      "or a person's full name.")
    t = t.strip().strip('"').strip()
    if kind == "phone":
        digits = re.sub(r"\D", "", t)
        if t.startswith("+"):
            t = "+" + digits
        elif len(digits) == 10:
            t = "+1" + digits                     # a US number without the country code
        elif len(digits) == 11 and digits.startswith("1"):
            t = "+" + digits
        else:
            return None, "Add the country code to that phone number, e.g. +44 20 7946 0000."
    elif kind in ("username", "name"):
        t = f'"{t}"'                              # SpiderFoot's own way of saying "this is a username / a person's name"
    elif kind == "domain":
        t = t.lower()
    ok, why = spiderfoot_status()
    if not ok:
        return None, why[0].upper() + why[1:] + "."
    u = spiderfoot_url()
    try:
        r = json.loads(_http(u + "/startscan", {"scanname": f"ScamHunter lookup {time.strftime('%Y-%m-%d %H:%M')}", "scantarget": t,
                                                 "modulelist": "", "typelist": "", "usecase": "passive"}, timeout=120))
    except Exception as ex:
        return None, f"SpiderFoot refused the scan: {str(ex)[:100]}"
    if not r or r[0] != "SUCCESS":
        return None, f"SpiderFoot refused the scan: {r[1] if r and len(r) > 1 else 'no reason given'}"
    jid = _new("spiderfoot", t, kind)
    _update(jid, sf_id=r[1])
    if wait:
        _sf_poll(jid)
    else:
        _start_thread(jid, _sf_poll, jid)
    return jid, None


LABELS = {"EMAILADDR": "Email addresses", "EMAILADDR_GENERIC": "Email addresses (generic)", "PHONE_NUMBER": "Phone numbers",
          "HUMAN_NAME": "Names", "USERNAME": "Usernames", "ACCOUNT_EXTERNAL_OWNED": "Accounts on other sites",
          "SOCIAL_MEDIA": "Social media profiles", "INTERNET_NAME": "Host names", "DOMAIN_NAME": "Domains",
          "AFFILIATE_DOMAIN_NAME": "Related domains", "CO_HOSTED_SITE": "Sites on the same server", "IP_ADDRESS": "IP addresses",
          "NETBLOCK_OWNER": "Network owners", "BGP_AS_OWNER": "Network (AS) owners", "PHYSICAL_ADDRESS": "Physical addresses",
          "COUNTRY_NAME": "Countries", "DOMAIN_REGISTRAR": "Registrars", "DOMAIN_WHOIS": "Registration records",
          "EMAILADDR_COMPROMISED": "Emails seen in data breaches", "PHONE_NUMBER_COMPROMISED": "Phone numbers seen in breaches",
          "MALICIOUS_INTERNET_NAME": "Host names on blocklists", "MALICIOUS_IPADDR": "IP addresses on blocklists",
          "BLACKLISTED_INTERNET_NAME": "Host names on blocklists", "BLACKLISTED_IPADDR": "IP addresses on blocklists",
          "MALICIOUS_EMAILADDR": "Emails on blocklists", "MALICIOUS_PHONE_NUMBER": "Phone numbers on blocklists",
          "LEAKSITE_URL": "Mentions on paste / leak sites", "LINKED_URL_EXTERNAL": "Linked websites", "SSL_CERTIFICATE_ISSUED": "Certificates",
          "WEBSERVER_TECHNOLOGY": "Web technology", "PROVIDER_HOSTING": "Hosting providers", "PROVIDER_MAIL": "Email providers",
          "PROVIDER_TELCO": "Phone carriers", "BITCOIN_ADDRESS": "Bitcoin addresses", "ETHEREUM_ADDRESS": "Ethereum addresses"}
SKIP = re.compile(r"^(ROOT|RAW_.*|.*_RAW|SEARCH_ENGINE_WEB_CONTENT|TARGET_WEB_CONTENT.*|HTTP_CODE|WEBSERVER_HTTPHEADERS|"
                  r"WEBSERVER_BANNER|DNS_TEXT|DNS_SPF|SSL_CERTIFICATE_RAW|DOMAIN_WHOIS)$")


def parse_spiderfoot(rows):
    """[{type, label, data, module}] -- deduplicated, raw blobs left out (they stay in SpiderFoot)."""
    out, seen = [], set()
    for row in rows or []:
        if not isinstance(row, list) or len(row) < 4:
            continue
        etype, data, module = str(row[-1]), str(row[1]), str(row[3])
        if SKIP.match(etype) or (etype, data) in seen:
            continue
        seen.add((etype, data))
        out.append({"type": etype, "label": LABELS.get(etype, etype.replace("_", " ").capitalize()), "data": data[:300],
                    "module": module.replace("sfp_", "")})
    return sorted(out, key=lambda x: (x["label"], x["data"].lower()))


def _sf_poll(jid):
    import html as _h
    try:
        u = spiderfoot_url()
        j = next((x for x in _load() if x["id"] == jid), None)
        if not j or not u:
            raise RuntimeError("SpiderFoot is no longer on this computer")
        sid, t0 = j["sf_id"], time.time()
        while True:
            st = json.loads(_http(u + "/scanstatus?id=" + urllib.parse.quote(sid)))
            state = st[5] if st and len(st) > 5 else "UNKNOWN"
            _update(jid, sf_state=state)
            if state in ("FINISHED", "ABORTED") or state.startswith("ERROR"):
                break
            if time.time() - t0 > SF_LIMIT:
                _http(u + "/stopscan?id=" + urllib.parse.quote(sid))
                state = "ABORTED"
                break
            time.sleep(SF_POLL)
        rows = json.loads(_http(u + "/scaneventresults?id=" + urllib.parse.quote(sid) + "&eventType=ALL"))
        items = parse_spiderfoot(rows)
        for it in items:
            it["data"] = _h.unescape(it["data"])                 # SpiderFoot html-escapes its JSON; the page escapes again
        if state.startswith("ERROR") and not items:
            raise RuntimeError(f"SpiderFoot reported {state}")
        _finish(jid, items, {"tool_note": "SpiderFoot, passive modules", "sf_state": state, "sf_id": sid})
    except Exception as ex:
        _update(jid, status="error", error=str(ex)[:200])
    finally:
        _threads.pop(jid, None)


def stop(jid):
    j = next((x for x in _load() if x["id"] == jid), None)
    if j and j["tool"] == "spiderfoot" and j["status"] == "running" and spiderfoot_url():
        try:
            _http(spiderfoot_url() + "/stopscan?id=" + urllib.parse.quote(j["sf_id"]))
            return True
        except Exception:
            return False
    return False


def delete(jid):
    with _lock:
        js = [j for j in _load() if j["id"] != jid]
        _save(js)
    try:
        os.remove(os.path.join(DIR, jid + ".json"))
    except OSError:
        pass


# ---------------------------------------------------------------- for the IC3 report ----

def ic3_text(job, res):
    lines = [f"Lookup of {job['kind']} \"{job['target']}\" with {res.get('tool_note', job['tool'])} on {job.get('finished') or job['started']}."]
    if job["tool"] == "maigret":
        lines.append("Public accounts using this username (a shared username does not prove it is the same person):")
        for i in res["items"]:
            d = ", ".join(f"{k}: {v}" for k, v in i["details"].items())
            lines.append(f"- {i['site']}: {i['url']}" + (" (possible match)" if i["maybe"] else "") + (f" [{d}]" if d else ""))
    else:
        lines.append("Public records linked to it (passive search of public sources; leads, not proof):")
        cur = None
        for i in res["items"]:
            if i["label"] != cur:
                cur = i["label"]
                lines.append(f"{cur}:")
            lines.append(f"- {i['data']}")
    return "\n".join(lines)
