"""Settings > Share ScamHunter: give the program to someone else without giving them your case.

Your case lives only in files on this computer that are never part of the program (your settings,
victim details, freeze requests, logs, evidence). Two ways to share:
  1. Send the one-line install command: they get a fresh, signed copy straight from GitHub.
  2. Make a share copy (a zip in your Downloads): built ONLY from the files listed in the signed
     release, checked against your own case details before it's written, and it refuses if any
     appear. Nothing else in this folder can get in.
"""
import html
import json
import os
import time
import zipfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = "https://github.com/designbycone-create/crypto-scam-tracer"
CMD = "irm https://raw.githubusercontent.com/designbycone-create/crypto-scam-tracer/stable/install.ps1 | iex"
e = lambda s: html.escape(str(s if s is not None else ""), quote=True)
PRIVATE = [("config.json", "your settings and keys (keys are also encrypted to your Windows account)"),
           ("victim.json", "your name, contact details, IC3 number and the scam's details"),
           ("submissions.json, freeze_kits/", "freeze requests and what you've sent to exchanges"),
           ("evidence_store/, evidence_bundles/", "your evidence"),
           ("prescreen_log.jsonl, desk_activity.jsonl", "what you've checked"),
           ("*.log, network and map files", "watcher history about your case")]

INSTALL_CMD = """@echo off
rem ScamHunter Threat Desk - install from this share copy (no download needed)
set SCAMHUNTER_FROM=%~dp0
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
pause
"""


def _release():
    try:
        with open(os.path.join(HERE, "RELEASE.json"), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


CORE_PRIVATE = ("config.json", "victim.json", "submissions.json", "freeze_tracker.json", "desk_activity.jsonl", "prescreen_log.jsonl",
                "extension_events.jsonl", "agent_approvals.json", "etherscan.key")


def _private(rel):
    """Is this one of the user's own files (anything .gitignore keeps out of the program)?"""
    import fnmatch
    name = rel.replace("\\", "/")
    pats = list(CORE_PRIVATE)
    try:
        with open(os.path.join(HERE, ".gitignore"), encoding="utf-8") as f:
            pats += [l.strip() for l in f if l.strip() and not l.startswith("#") and not l.startswith("!")]
    except OSError:
        pass
    for pat in pats:
        p = pat.rstrip("/")
        if pat.endswith("/") and (name.startswith(p + "/") or ("/" + p + "/") in ("/" + name)):
            return True
        if fnmatch.fnmatch(name, p) or fnmatch.fnmatch(os.path.basename(name), p):
            return True
    return False


def make_copy(dest_dir=None, case_dir=None):
    """Write the share zip. (ok, message, path)"""
    import privacy_guard
    import release_sig
    ok, why, man = release_sig.check_folder(HERE)
    if not ok or not man:
        return False, f"This copy of the program doesn't match its signed release ({why}), so no share copy was made.", None
    files = sorted(man["files"])
    leaked = [f for f in files if _private(f)]
    if leaked:
        return False, ("No share copy was made: the release unexpectedly lists your private file(s) " + ", ".join(leaked)
                       + ". Please report this."), None
    hits = privacy_guard.find([os.path.join(HERE, f) for f in files], privacy_guard.case_values(case_dir or HERE))
    if hits:
        return False, ("No share copy was made: your own case details appear in " + ", ".join(os.path.relpath(f, HERE) for f in hits)
                       + ". Please report this; those files shouldn't contain them."), None
    dest_dir = dest_dir or os.path.join(os.path.expanduser("~"), "Downloads")
    os.makedirs(dest_dir, exist_ok=True)
    ver = (man.get("meta") or {}).get("signed_at", "")[:10] or time.strftime("%Y-%m-%d")
    path = os.path.join(dest_dir, f"ScamHunter-share-{ver}.zip")
    tmp = path + ".tmp"
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for rel in files + [release_sig.MANIFEST, release_sig.SIGFILE]:
            z.write(os.path.join(HERE, rel), "ScamHunter/" + rel)
        z.writestr("ScamHunter/INSTALL.cmd", INSTALL_CMD.replace("\n", "\r\n"))
    os.replace(tmp, path)
    return True, f"Share copy made: {len(files)} program files, signed (key {release_sig.fingerprint(man['pubkey'])}). None of your case files are in it.", path


def page(msg="", ok=None):
    import release_sig
    rel = _release()
    key = release_sig.fingerprint(rel["pubkey"]) if rel and rel.get("pubkey") else "unknown"
    css = ("body{font:20px/1.5 'Segoe UI',Arial,sans-serif;max-width:980px;margin:0 auto;padding:0 16px 40px;color:#111}"
           "h1{font-size:30px}h2{font-size:24px;margin:26px 0 8px}.card{border:2px solid #ddd;border-radius:12px;padding:14px 16px;margin:12px 0}"
           ".ok{background:#e9f7ef;border-color:#2e7d32}.bad{background:#fdecee;border-color:#b00020}"
           "textarea{width:100%;font:16px Consolas,monospace;padding:10px;box-sizing:border-box}button{font-size:19px;padding:9px 18px;border-radius:10px;cursor:pointer}"
           ".go{background:#0b6b3a;color:#fff;border:0}code{background:#f2f2f2;padding:2px 6px;border-radius:5px;word-break:break-all}li{margin:6px 0}")
    note = ""
    if msg:
        note = f"<div class='card {'ok' if ok else 'bad'}'>{e(msg)}</div>"
    priv = "".join(f"<li><code>{e(f)}</code>: {e(w)}</li>" for f, w in PRIVATE)
    letter = (f"I'd like you to try ScamHunter Threat Desk, a free tool for scam victims.\n\n"
              f"On a Windows computer, open PowerShell (Start menu, type PowerShell, press Enter), paste this line and press Enter:\n\n"
              f"{CMD}\n\n"
              f"It installs a fresh copy from {REPO} (about 2 minutes) and opens the Desk in your browser. "
              f"It starts empty: nothing of mine is in it. The setup guide is at {REPO}/blob/main/SETUP.md\n\n"
              f"Each release is signed. The Desk's Settings > Updates page should show signing key {key}.")
    return (f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>Share ScamHunter</title><style>{css}</style></head><body><h1>Share ScamHunter</h1>{note}"
            "<div class='card ok'><b>Your information stays on this computer.</b> The Desk only answers on this computer "
            "(<code>127.0.0.1</code>): other computers, phones and the internet can't open it. Your case is kept in these files, "
            f"which are never part of the program, so they're never in an update, on GitHub, or in a share copy:<ul>{priv}</ul></div>"
            "<h2>Easiest: send them the install line</h2><p>Copy this message and send it by text or email. They get their own fresh, "
            f"signed copy from GitHub, and set it up with their own details.</p><textarea rows=11 readonly onclick='this.select()'>{e(letter)}</textarea>"
            "<h2>Or: make a share copy (USB stick or email)</h2><div class=card>A zip file in your Downloads folder with only the signed "
            "program files. Before it's written, it's checked against your own case details (wallets, transaction IDs, IC3 number, deposit "
            "tags, email, phone) and isn't made if any appear. They unzip it and double-click <code>INSTALL.cmd</code>."
            "<form method=post><input type=hidden name=do value=make><button class=go>Make a share copy</button></form></div>"
            "<p>Setup guide for them: <code>SETUP.md</code> (in the program folder and on GitHub).</p></body></html>")


def post(form):
    if form.get("do") == "make":
        ok, msg, path = make_copy()
        return page(msg + (f" Saved as {path}" if path else ""), ok)
    return page()
