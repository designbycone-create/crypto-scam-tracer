"""Desk page: /evidence -- seal a court bundle and download it."""
import html
import os
import threading

from . import case

JOB = {"running": False, "result": None, "error": None}

CSS = """<style>body{font:15px/1.5 system-ui,sans-serif;background:#0b1020;color:#e6e9f2;margin:0}
.w{max-width:860px;margin:0 auto;padding:24px 16px}a{color:#8ab4ff}.card{background:#141b31;border:1px solid #263154;
border-radius:12px;padding:16px 18px;margin:14px 0}.btn{display:inline-block;background:#3b6cff;color:#fff;border:0;
border-radius:8px;padding:10px 16px;font-size:15px;cursor:pointer;text-decoration:none}input{background:#0b1020;color:#e6e9f2;
border:1px solid #33406b;border-radius:8px;padding:8px;width:100%;box-sizing:border-box;margin:4px 0 10px}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:13px;word-break:break-all}.mut{color:#9aa3bf}
.warn{border-color:#a0782b;background:#21190b}</style>"""


def _shell(body, refresh=False):
    r = "<meta http-equiv=refresh content=4>" if refresh else ""
    return (f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>{r}"
            f"<title>Court evidence</title>{CSS}<div class=w><p><a href='/'>&larr; Desk</a></p>{body}</div>")


def page(msg=""):
    e = html.escape
    p = case.plan()
    if JOB["running"]:
        return _shell("<h1>Sealing evidence bundle&hellip;</h1><p class=mut>Reading each transaction from two independent "
                      "ledger servers. This page refreshes on its own.</p>", refresh=True)
    out = ["<h1>&#9878;&#65039; Court evidence bundle</h1>",
           "<div class='card warn'><b>What this is, and isn't.</b> It packages your case so a qualified person (you, an "
           "investigator, or an expert) can stand behind it: every fact is checked against two independent ledger "
           "servers, the raw data is saved and fingerprinted, opinions are labelled as opinions, and anyone can re-check "
           "it with the included <span class=mono>verify.py</span>. <b>No software can guarantee a court admits evidence.</b> "
           "The judge decides. Have an attorney review the bundle before filing.</div>"]
    if msg:
        out.append(f"<div class=card>{msg}</div>")
    r = JOB.get("result")
    if r:
        out.append(f"<div class=card><b>Sealed {e(os.path.basename(r['dir']))}</b><br>"
                   f"Facts {r['counts']['FACT']} &middot; derived {r['counts']['DERIVED']} &middot; inferences {r['counts']['INFERENCE']}<br>"
                   f"Manifest SHA-256 (write this down; it goes in the certification):<div class=mono>{e(r['manifest_sha256'])}</div>"
                   f"Bundle zip SHA-256:<div class=mono>{e(r['zip_sha256'])}</div>"
                   f"<p>Saved on this computer at <span class=mono>{e(os.path.abspath(r['zip']))}</span></p>"
                   + (f"<p class=mut>Skipped: {e('; '.join(r['errors']))}</p>" if r.get("errors") else "") + "</div>")
    if JOB.get("error"):
        out.append(f"<div class='card warn'>Couldn't seal: {e(JOB['error'])}</div>")
    out.append(f"<div class=card><b>Will include</b><br>Your payment: <span class=mono>{e(p['victim_tx'] or 'not set in victim.json')}</span><br>"
               f"Cash-outs caught by the watcher: {len(p['cashouts'])}</div>")
    out.append("<div class=card><form method=post action='/evidence'>"
               "<label>Name of the person who ran this (goes on the certification)</label><input name=name>"
               "<label>Role / qualifications (optional)</label><input name=role placeholder='e.g. victim; retired IT; investigator'>"
               "<button class=btn>Seal evidence bundle</button></form>"
               "<p class=mut>Each seal is a new, separate bundle. Sealed bundles are never changed afterwards.</p></div>")
    return _shell("".join(out))


def post(form):
    if JOB["running"]:
        return page()

    def run():
        JOB.update(running=True, error=None)
        try:
            JOB["result"] = case.seal(form.get("name", "").strip(), form.get("role", "").strip())
        except Exception as ex:
            JOB["error"] = str(ex)[:400]
        finally:
            JOB["running"] = False
    threading.Thread(target=run, daemon=True).start()
    return _shell("<h1>Sealing&hellip;</h1>", refresh=True).replace("content=4", "content=3;url=/evidence")
