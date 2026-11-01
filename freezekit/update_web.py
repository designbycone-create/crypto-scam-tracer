"""Desk page /update: see what's new, install it with one click, or undo."""
import html
import threading
import time

import updater

JOB = {"running": False, "msg": "", "err": ""}
STOP_CHILDREN = None     # set by desk.main(): stops the watchers before a restart


def background_checker():
    """Check GitHub at start and every 6 hours (cached; never installs anything by itself)."""
    def loop():
        while True:
            try:
                updater.check()
            except Exception as e:
                try:
                    st = updater._state()
                    st.update({"error": str(e)[:120], "checked": time.time()})
                    updater._save_state(st)
                except Exception:
                    pass
            time.sleep(6 * 3600)
    threading.Thread(target=loop, daemon=True).start()


def banner():
    """Small notice for the Desk home page, or ''."""
    st = updater._state()
    if st.get("available"):
        n = len(st.get("changes") or [])
        return (f"<div style='background:#10233f;border:1px solid #3b6cff;border-radius:10px;padding:10px 14px;margin:10px 0'>"
                f"&#11014;&#65039; <b>An update is available</b>{f' ({n} improvement' + ('s' if n != 1 else '') + ')' if n else ''}. "
                f"<a href='/update'>See what's new and install</a></div>")
    return ""


CSS = """<style>body{font:15px/1.55 system-ui,sans-serif;background:#0f1115;color:#e8eaf0;margin:0}
.w{max-width:820px;margin:0 auto;padding:22px 16px}a{color:#5aa2ff}.card{background:#151922;border:1px solid #262b36;
border-radius:12px;padding:16px 18px;margin:14px 0}.btn{display:inline-block;background:#3b6cff;color:#fff;border:0;border-radius:8px;
padding:10px 16px;font-size:15px;cursor:pointer}.ghost{background:#262b36}.mut{color:#9aa1b2}.ok{color:#86efac}.bad{color:#ff8a7a}
code{font-family:ui-monospace,Consolas,monospace}li{margin:4px 0}</style>"""


def _shell(body, refresh=None):
    r = f"<meta http-equiv=refresh content='{refresh}'>" if refresh else ""
    return (f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>{r}"
            f"<title>Updates</title>{CSS}<div class=w><p><a href='/'>&larr; Desk</a></p>{body}</div>")


def page(force=False):
    e = html.escape
    if JOB["running"]:
        return _shell("<h1>Installing update&hellip;</h1><p class=mut>Downloading, backing up your current version, "
                      "installing and running the self-tests. The Desk restarts by itself when it's done. This page "
                      "reloads in a moment.</p>", refresh="5;url=/update")
    try:
        st = updater.check(force=force)
    except Exception as ex:
        st = dict(updater._state(), error=str(ex)[:150])
    cur, latest = st.get("installed"), st.get("latest")
    out = ["<h1>&#11014;&#65039; Updates</h1>",
           "<p class=mut>Updates come only from the official ScamHunter repository on GitHub and install only when you "
           "click. Your case, settings, keys, alerts and evidence are never touched. Your current version is backed "
           "up first, and if the new version fails its self-tests it is rolled back automatically.</p>"]
    if JOB["msg"]:
        out.append(f"<div class=card><span class=ok>{JOB['msg']}</span></div>")
    if JOB["err"]:
        out.append(f"<div class=card><span class=bad>{e(JOB['err'])}</span></div>")
    if st.get("error") and not latest:
        out.append(f"<div class=card><span class=bad>Couldn't reach GitHub ({e(st['error'])}). Try again later.</span></div>")
    out.append(f"<div class=card>Installed version: <code>{e((cur or 'unknown')[:7])}</code><br>"
               f"Newest version: <code>{e((latest or '?')[:7])}</code>"
               f"{' &middot; ' + e((st.get('latest_date') or '')[:10]) if latest else ''}</div>")
    if st.get("available"):
        ch = "".join(f"<li>{e(c)}</li>" for c in st.get("changes") or [])
        out.append(f"<div class=card><h3>What's new</h3><ul>{ch or '<li>Improvements and fixes</li>'}</ul>"
                   "<form method=post action='/update'><input type=hidden name=do value=apply>"
                   "<button class=btn>Install update</button></form></div>")
    elif latest:
        out.append("<div class=card><span class=ok>&#10003; You have the newest version.</span></div>")
    out.append("<div class=card><form method=post action='/update' style='display:inline'><input type=hidden name=do value=check>"
               "<button class='btn ghost'>Check now</button></form> ")
    if st.get("last_backup"):
        out.append("<form method=post action='/update' style='display:inline'><input type=hidden name=do value=undo>"
                   "<button class='btn ghost'>Undo last update</button></form>")
    out.append("</div>")
    return _shell("".join(out))


def _restart_soon():
    def go():
        time.sleep(1.5)
        updater.relaunch_desk(STOP_CHILDREN or (lambda: None))
    threading.Thread(target=go, daemon=True).start()


def post(form):
    do = form.get("do")
    JOB.update(msg="", err="")
    if do == "check":
        return page(force=True)
    if do == "apply" and not JOB["running"]:
        sha = updater._state().get("latest")

        def run():
            JOB["running"] = True
            try:
                r = updater.apply(sha)
                JOB["msg"] = f"Updated to {r['version'][:7]} ({r['files']} files). Restarting the Desk&hellip;"
                JOB["running"] = False
                _restart_soon()
            except Exception as ex:
                JOB["err"] = str(ex)[:300]
                JOB["running"] = False
        threading.Thread(target=run, daemon=True).start()
        return _shell("<h1>Installing update&hellip;</h1>", refresh="3;url=/update")
    if do == "undo":
        try:
            r = updater.undo()
            JOB["msg"] = f"Restored the previous version ({(r['version'] or 'unknown')[:7]}). Restarting the Desk&hellip;"
            _restart_soon()
        except Exception as ex:
            JOB["err"] = str(ex)[:200]
    return page()
