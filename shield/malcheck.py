"""Malware & link check: is Windows Defender on and current; check a download before opening it;
check a link before clicking it.

A file is checked on this computer (Windows Defender, the file's type and name tricks, who signed
it, where Windows says it was downloaded from) and, with your free abuse.ch key, by its SHA-256
fingerprint against MalwareBazaar (the file itself never leaves your computer). A link is checked
for scam signs on this computer, against ScamHunter's attack lists, and, with the key, against
URLhaus and ThreatFox.

Results never say a file or link is "safe": only what was found, and what wasn't.
"""
import hashlib
import html
import os
import re
import urllib.parse
import zipfile

from shield import abusech, defender

EXEC = {".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".iso", ".img",
        ".vhd", ".vhdx", ".jar", ".com", ".pif", ".cpl", ".msc", ".reg", ".dll", ".appx", ".msix", ".apk", ".url", ".chm", ".xll"}
ARCHIVE = {".zip", ".rar", ".7z", ".tar", ".gz", ".cab"}
DOCS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mp3", ".csv"}
e = lambda s: html.escape(str(s if s is not None else ""), quote=True)


def downloads_dir():
    return os.path.join(os.path.expanduser("~"), "Downloads")


def recent_downloads(n=15):
    d = downloads_dir()
    try:
        files = [os.path.join(d, f) for f in os.listdir(d)]
    except OSError:
        return []
    files = [f for f in files if os.path.isfile(f)]
    files.sort(key=lambda f: os.path.getmtime(f), reverse=True)
    return files[:n]


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def origin(path):
    """Where Windows recorded the file came from (the 'Mark of the Web' saved with downloads)."""
    if os.name != "nt":
        return {}
    try:
        with open(path + ":Zone.Identifier", encoding="utf-8", errors="replace") as f:
            txt = f.read()
    except OSError:
        return {}
    out = {}
    for k in ("ZoneId", "HostUrl", "ReferrerUrl"):
        m = re.search(rf"^{k}=(.*)$", txt, re.M)
        if m:
            out[k] = m.group(1).strip()
    return out


def check_file(path):
    """{'path', 'name', 'level': stop|caution|ok, 'findings': [(level, text)], 'sha256'}"""
    f = []
    if not os.path.isfile(path):
        return {"path": path, "name": os.path.basename(path), "level": "caution", "findings": [("caution", "That file wasn't found.")], "sha256": None}
    name = os.path.basename(path)
    low = name.lower().rstrip(". ")
    ext = os.path.splitext(low)[1]
    sha = _sha256(path)
    # name tricks
    parts = low.split(".")
    if len(parts) >= 3 and "." + parts[-1] in EXEC and "." + parts[-2] in DOCS:
        f.append(("stop", f"The name pretends to be a .{parts[-2]} but it's really a program (.{parts[-1]}). This is a classic trick."))
    elif re.search(r"\s{3,}", name) or "\u202e" in name:
        f.append(("stop", "The file name hides its real ending (extra spaces or reversed text). This is a trick to disguise a program."))
    if ext in EXEC:
        f.append(("caution", f"This is a program or script ({ext}). Only open it if you were expecting it from a source you trust."))
    if ext == ".zip":
        try:
            with zipfile.ZipFile(path) as z:
                inner = [n for n in z.namelist() if os.path.splitext(n.lower())[1] in EXEC]
            if inner:
                f.append(("caution", f"The zip contains program(s): {', '.join(os.path.basename(i) for i in inner[:3])}."))
        except (zipfile.BadZipFile, OSError):
            pass
    # where it came from
    o = origin(path)
    if o.get("HostUrl"):
        host = (urllib.parse.urlsplit(o["HostUrl"]).hostname or "").lower()
        lk = link_findings(o["HostUrl"], online=True)
        bad = [x for x in lk if x[0] == "stop"]
        f.append(("stop" if bad else "info", f"Downloaded from {host}." + (" " + bad[0][1] if bad else "")))
    # who signed it
    if ext in (".exe", ".msi", ".dll", ".sys", ".ps1", ".msix", ".appx", ".cab") and os.name == "nt":
        sig = defender.signature(path)
        if sig.get("status") == "Valid":
            cn = re.search(r"CN=\"?([^,\"]+)", sig.get("signer") or "")
            f.append(("info", f"Digitally signed by {cn.group(1) if cn else 'a known publisher'} (signature valid). That says who made it, not that it's harmless."))
        elif sig.get("status") in ("HashMismatch", "NotTrusted"):
            f.append(("stop", "Its digital signature is broken or untrusted: the program may have been altered."))
        elif ext in (".exe", ".msi"):
            f.append(("caution", "The program isn't digitally signed, so there's no way to tell who made it."))
    # Windows Defender
    d = defender.scan_file(path)
    f.append(("stop" if d["threat"] else ("ok" if d["ran"] else "info"), d["detail"]))
    # MalwareBazaar by fingerprint
    mb = abusech.file_hash(sha)
    f.append(("stop" if mb["known"] else ("ok" if mb["checked"] else "info"), mb["detail"]))
    lv = "stop" if any(x[0] == "stop" for x in f) else "caution" if any(x[0] == "caution" for x in f) else "ok"
    return {"path": path, "name": name, "level": lv, "findings": f, "sha256": sha}


def link_findings(u, online=True):
    from shield import msgcheck
    f = []
    for w, why in msgcheck.check_link(u):
        f.append(("stop" if w >= 4 else "caution", why))
    if online:
        a = abusech.url(u)
        f.append(("stop" if a["known"] else ("ok" if a["checked"] else "info"), a["detail"]))
    return f


def check_link(u):
    u = (u or "").strip()
    if not u:
        return {"url": u, "level": "caution", "findings": [("caution", "Paste a link to check.")]}
    if not re.match(r"https?://", u, re.I):
        u = "http://" + u
    f = link_findings(u)
    if not any(x[0] in ("stop", "caution") for x in f):
        f.insert(0, ("ok", "No scam signs found in the link itself."))
    lv = "stop" if any(x[0] == "stop" for x in f) else "caution" if any(x[0] == "caution" for x in f) else "ok"
    return {"url": u, "level": lv, "findings": f}


# ---------------------------------------------------------------- page ----

CSS = ("body{font:20px/1.5 'Segoe UI',Arial,sans-serif;max-width:980px;margin:0 auto;padding:0 16px 40px;color:#111}"
       "h1{font-size:30px}h2{font-size:24px;margin:26px 0 8px}.card{border:2px solid #ddd;border-radius:12px;padding:14px 16px;margin:12px 0}"
       ".stop{background:#fdecee;border-color:#b00020}.caution{background:#fff8e6;border-color:#f2b01e}.ok{background:#e9f7ef;border-color:#2e7d32}"
       ".info{background:#eef3fb;border-color:#9bb}button{font-size:19px;padding:9px 18px;border-radius:10px;cursor:pointer}"
       ".go{background:#0b6b3a;color:#fff;border:0}input[type=text],input[type=password]{font-size:19px;padding:9px;width:100%;box-sizing:border-box}"
       "code{background:#f2f2f2;padding:2px 6px;border-radius:5px;word-break:break-all}.small{font-size:16px;color:#444}"
       "li{margin:6px 0}table{border-collapse:collapse;width:100%}td{border-bottom:1px solid #ddd;padding:8px;vertical-align:middle}")
HEAD = {"stop": "DANGER", "caution": "BE CAREFUL", "ok": "NOTHING BAD FOUND"}
ICON = {"stop": "&#9940;", "caution": "&#9888;&#65039;", "ok": "&#9989;", "info": "&#8505;&#65039;"}


def _result(r, what):
    items = "".join(f"<li>{ICON.get(l, '')} {e(t)}</li>" for l, t in r["findings"])
    head = HEAD[r["level"]]
    tail = ("Don't open it. Delete it and empty the Recycle Bin." if r["level"] == "stop" and what == "file" else
            "Don't click it, and don't type anything into that site." if r["level"] == "stop" else
            "Nothing bad was found, but that isn't a guarantee: new malware and new scam sites aren't on any list yet. "
            "If you weren't expecting it, don't open it." if r["level"] == "ok" else
            "Only go ahead if you were expecting it and trust where it came from.")
    return f"<div class='card {r['level']}'><b>{head}</b><ul>{items}</ul><p><b>{e(tail)}</b></p></div>"


def page(msg="", file_result=None, link_result=None):
    out = [f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
           f"<title>Malware &amp; link check</title><style>{CSS}</style>"
           + ("<meta http-equiv=refresh content=10>" if defender.quick_scan_state()["running"] else "") + "</head><body>",
           "<h1>Malware &amp; link check</h1>",
           "<p>Check a download before you open it, or a link before you click it. Files are checked on this computer. "
           "Only a file's fingerprint (never the file), the web address it was downloaded from, and links you check go to abuse.ch, "
           "and only if you've added your free key below.</p>"]
    if msg:
        out.append(f"<div class='card caution'>{e(msg)}</div>")
    # Defender
    s = defender.status()
    out.append("<h2>Windows Defender</h2>")
    if not s.get("ok"):
        out.append(f"<div class='card caution'>{e(s.get('why'))}</div>")
    else:
        worst = "stop" if any(p[0] == "stop" for p in s["problems"]) else "caution" if any(p[0] == "caution" for p in s["problems"]) else "ok"
        lines = [f"Antivirus: <b>{'ON' if s['on'] else 'OFF'}</b> &middot; real-time protection: <b>{'ON' if s['realtime'] else 'OFF'}</b>"
                 f" &middot; tamper protection: <b>{'ON' if s['tamper'] else 'OFF'}</b>",
                 f"Virus definitions updated {e(s['sig_updated'])}"
                 + (f" ({s['sig_age_days']} day(s) old)" if isinstance(s.get("sig_age_days"), int) else ""),
                 "Last quick scan: " + ("never" if s["quick_age"] is None else f"{s['quick_age']} day(s) ago")
                 + " &middot; last full scan: " + ("never" if s["full_age"] is None else f"{s['full_age']} day(s) ago")]
        probs = "".join(f"<li>{ICON[l]} {e(t)}</li>" for l, t in s["problems"])
        q = defender.quick_scan_state()
        qbit = (f"<p><b>Quick scan running</b> (started {e(q['started'])}). This page refreshes by itself.</p>" if q["running"] else
                (f"<p><b>{e(q['result'])}</b></p>" if q.get("result") else "")
                + "<form method=post><input type=hidden name=do value=quickscan><button class=go>Run a quick scan now</button>"
                  " <span class=small>A few minutes. You can keep using the computer.</span></form>")
        out.append(f"<div class='card {worst}'>{'<br>'.join(lines)}" + (f"<ul>{probs}</ul>" if probs else "") + qbit + "</div>")
        det = defender.detections()
        if det:
            rows = "".join(f"<tr><td>{e(d['when'])}</td><td><b>{e(d['name'])}</b> {e(d['severity'])}<div class=small>{e(d['where'])}</div></td>"
                           f"<td>{'handled' if d['handled'] else '<b>needs attention</b>'}</td></tr>" for d in det)
            out.append(f"<details class=card><summary><b>Recently caught by Defender ({len(det)})</b></summary><table>{rows}</table>"
                       "<p class=small>Details and options: Windows Security &rarr; Virus &amp; threat protection &rarr; Protection history.</p></details>")
    # file
    out.append("<h2>Check a download</h2>")
    if file_result:
        out.append(f"<p>Result for <code>{e(file_result['name'])}</code>:</p>" + _result(file_result, "file"))
    rec = recent_downloads()
    if rec:
        rows = "".join(f"<tr><td>{e(os.path.basename(p))}<div class=small>{e(_age(p))}</div></td><td style='width:1%'>"
                       f"<form method=post style=margin:0><input type=hidden name=do value=file><input type=hidden name=i value={i}>"
                       "<button>Check</button></form></td></tr>" for i, p in enumerate(rec))
        out.append(f"<div class=card><b>Your most recent downloads</b><table>{rows}</table></div>")
    out.append("<form method=post class=card><input type=hidden name=do value=file><label>Or a file anywhere on this computer (paste its full path):"
               "<input type=text name=path placeholder='C:\\Users\\you\\Desktop\\invoice.pdf'></label><button class=go>Check this file</button></form>")
    # link
    out.append("<h2>Check a link</h2>")
    if link_result:
        out.append(f"<p>Result for <code>{e(link_result['url'])}</code>:</p>" + _result(link_result, "link"))
    out.append("<form method=post class=card><input type=hidden name=do value=link><label>Paste the link (don't click it first):"
               "<input type=text name=url placeholder='https://...'></label><button class=go>Check this link</button></form>")
    # key
    kid = abusech.key_id()
    out.append("<h2>abuse.ch lookups</h2><div class=card>"
               + (f"Your abuse.ch key is set (Key ID <code>{kid}</code>, stored encrypted)." if kid else
                  "<b>Optional, free:</b> adds checks against abuse.ch's databases of known malware files (MalwareBazaar) and "
                  "malware links (URLhaus, ThreatFox). Make a free account at <code>https://auth.abuse.ch/</code>, copy your Auth-Key, "
                  "and paste it here. Free for personal, not-for-profit use.")
               + "<form method=post><input type=hidden name=do value=key><label>" + ("Replace" if kid else "Your Auth-Key") +
               ":<input type=password name=key autocomplete=off></label><button>Save key</button>"
               + (" <button name=clear value=1>Remove key</button>" if kid else "") + "</form></div>")
    out.append("</body></html>")
    return "".join(out)


def _age(p):
    import time
    m = os.path.getmtime(p)
    d = (time.time() - m) / 86400
    return "today" if d < 1 else f"{int(d)} day(s) ago"


def post(form):
    do = form.get("do")
    if do == "quickscan":
        return page("" if defender.quick_scan_start() else "A quick scan is already running, or Windows Defender isn't available.")
    if do == "file":
        if form.get("i") is not None and form.get("i") != "":
            rec = recent_downloads()
            try:
                p = rec[int(form["i"])]
            except (ValueError, IndexError):
                return page("That download is no longer in the list.")
        else:
            p = os.path.expanduser((form.get("path") or "").strip().strip('"'))
            if not p:
                return page("Paste the full path of the file to check.")
        r = check_file(p)
        _note("file", r["level"])
        return page(file_result=r)
    if do == "link":
        r = check_link(form.get("url"))
        _note("link", r["level"])
        return page(link_result=r)
    if do == "key":
        kid = abusech.save_key("" if form.get("clear") else form.get("key"))
        return page(f"abuse.ch key saved (Key ID {kid})." if kid else "abuse.ch key removed.")
    return page()


def _note(kind, level):
    try:
        from deskui import data
        word = {"stop": "DANGER", "caution": "be careful", "ok": "nothing bad found"}[level]
        data.note("defense", {"ok": "ok"}.get(level, level), f"{'Download' if kind == 'file' else 'Link'} checked: {word}", "", "/malware")
    except Exception:
        pass
