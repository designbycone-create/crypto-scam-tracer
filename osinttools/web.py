"""Desk page /lookup: look up a scammer's username, email, phone, website or name with Maigret / SpiderFoot."""
import html

from osinttools import runner

e = lambda s: html.escape(str(s if s is not None else ""), quote=True)

CSS = ("body{font:20px/1.5 'Segoe UI',Arial,sans-serif;max-width:1000px;margin:0 auto;padding:0 16px 40px;color:#111}"
       "h1{font-size:30px}h2{font-size:24px;margin:26px 0 8px}.card{border:2px solid #ddd;border-radius:12px;padding:14px 16px;margin:12px 0}"
       ".stop{background:#fdecee;border-color:#b00020}.caution{background:#fff8e6;border-color:#f2b01e}.ok{background:#e9f7ef;border-color:#2e7d32}"
       ".info{background:#eef3fb;border-color:#9bb}button{font-size:19px;padding:9px 18px;border-radius:10px;cursor:pointer}"
       ".go{background:#0b6b3a;color:#fff;border:0}input[type=text]{font-size:19px;padding:9px;width:100%;box-sizing:border-box}"
       "code{background:#f2f2f2;padding:2px 6px;border-radius:5px;word-break:break-all}.small{font-size:16px;color:#444}"
       "li{margin:6px 0}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:8px;vertical-align:top;text-align:left}"
       "textarea{width:100%;box-sizing:border-box;font:16px/1.4 Consolas,monospace;min-height:220px}a{color:#0b4f9c;word-break:break-all}"
       "form.inline{display:inline;margin:0}")
STATUS = {"running": "running&hellip;", "done": "finished", "error": "didn't finish"}


def _tools():
    m = runner.maigret_path()
    sf_ok, sf_why = runner.spiderfoot_status()
    rows = [f"<li>{'&#9989;' if m else '&#9888;&#65039;'} <b>Maigret</b> (usernames): "
            + (f"installed (<code>{e(m)}</code>)" if m else "not found") + "</li>",
            f"<li>{'&#9989;' if sf_ok else '&#9888;&#65039;'} <b>SpiderFoot</b> (emails, phone numbers, websites, names): {e(sf_why)}</li>"]
    setup = ""
    if not m or not sf_ok:
        setup = ("<details><summary><b>How to set them up</b> (both free, MIT license, each a separate program)</summary>"
                 "<p>Open <b>PowerShell</b> and paste these lines.</p>"
                 + ("" if m else "<p>Maigret:</p><pre><code>py -m venv $HOME\\osint\\maigret-venv\n"
                                 "& $HOME\\osint\\maigret-venv\\Scripts\\pip.exe install maigret</code></pre>")
                 + ("" if sf_ok else "<p>SpiderFoot (install once, then start it whenever you want to use it):</p><pre><code>"
                                     "git clone https://github.com/smicallef/spiderfoot $HOME\\osint\\spiderfoot\n"
                                     "cd $HOME\\osint\\spiderfoot; py -m venv venv; .\\venv\\Scripts\\pip.exe install -r requirements.txt\n"
                                     ".\\venv\\Scripts\\python.exe sf.py -l 127.0.0.1:5001</code></pre>"
                                     "<p class=small>The last line starts it. It only listens on this computer.</p>")
                 + "</details>")
    return f"<div class=card><ul style='margin:0'>{''.join(rows)}</ul>{setup}</div>"


def _jobs_table(js):
    if not js:
        return "<p class=small>No lookups yet.</p>"
    rows = []
    for j in js:
        tool = "Maigret" if j["tool"] == "maigret" else "SpiderFoot"
        st = STATUS.get(j["status"], j["status"])
        if j["status"] == "done":
            st += f": <b>{j.get('count', 0)}</b> found"
        elif j["status"] == "error":
            st += f"<div class=small>{e(j.get('error'))}</div>"
        elif j.get("sf_state"):
            st += f"<div class=small>SpiderFoot: {e(j['sf_state'].lower())}</div>"
        acts = []
        if j["status"] == "done":
            acts.append(f"<a href='/lookup?show={e(j['id'])}'><b>See results</b></a>")
        if j["status"] == "running" and j["tool"] == "spiderfoot":
            acts.append(f"<form method=post class=inline><input type=hidden name=do value=stop><input type=hidden name=id value='{e(j['id'])}'>"
                        "<button>Stop</button></form>")
        if j["status"] != "running":
            acts.append(f"<form method=post class=inline><input type=hidden name=do value=delete><input type=hidden name=id value='{e(j['id'])}'>"
                        "<button>Delete</button></form>")
        rows.append(f"<tr><td><b>{e(j['target'])}</b><div class=small>{e(j['kind'])} &middot; {tool} &middot; {e(j['started'])}</div></td>"
                    f"<td>{st}</td><td style='white-space:nowrap'>{' '.join(acts)}</td></tr>")
    return f"<table><tr><th>Looked up</th><th>Status</th><th></th></tr>{''.join(rows)}</table>"


def _results(jid):
    job = next((j for j in runner.jobs() if j["id"] == jid), None)
    res = runner.results(jid)
    if not job or not res:
        return "<div class='card caution'>Those results aren't here any more.</div>"
    items = res["items"]
    head = f"<h2>Results for {e(job['target'])}</h2>"
    if not items:
        return head + "<div class='card info'>Nothing was found. That doesn't clear anyone: new or careful accounts leave few traces.</div>"
    if job["tool"] == "maigret":
        rows = "".join(f"<tr><td><b>{e(i['site'])}</b>{' <span class=small>(possible match)</span>' if i['maybe'] else ''}</td>"
                       f"<td><a href='{e(i['url'])}' target=_blank rel='noopener noreferrer'>{e(i['url'])}</a>"
                       + (f"<div class=small>{e(', '.join(f'{k}: {v}' for k, v in i['details'].items()))}</div>" if i["details"] else "")
                       + "</td></tr>" for i in items)
        body = f"<table><tr><th>Site</th><th>Profile</th></tr>{rows}</table>"
    else:
        groups = {}
        for i in items:
            groups.setdefault(i["label"], []).append(i)
        body = "".join(f"<details class=card {'open' if n < 6 else ''}><summary><b>{e(lbl)}</b> ({len(g)})</summary><ul>"
                       + "".join(f"<li><code>{e(i['data'])}</code> <span class=small>via {e(i['module'])}</span></li>" for i in g[:200])
                       + "</ul></details>" for n, (lbl, g) in enumerate(sorted(groups.items())))
    return (head + "<div class='card caution'><b>These are leads, not proof.</b> Different people can share a username, and public "
            "records can be out of date. Don't contact or accuse anyone from these results; give them to IC3 and the police.</div>"
            + body + "<h2>For your IC3 report</h2><p class=small>Copy this into the description of your IC3 complaint "
            "(or give it to the officer on your case).</p>"
            f"<textarea readonly onclick='this.select()'>{e(runner.ic3_text(job, res))}</textarea>")


def page(msg="", level="caution", show=None):
    js = runner.jobs()
    running = any(j["status"] == "running" for j in js)
    out = [f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
           f"<title>Look up a scammer</title><style>{CSS}</style>" + ("<meta http-equiv=refresh content=15>" if running and not show else "")
           + "</head><body><h1>Look up a scammer</h1>",
           "<p>Put in a username, email address, phone number, website or name <b>the scammer used with you</b>. The Desk asks public "
           "websites and public records what's linked to it, so you can give investigators more to go on.</p>",
           "<div class='card info small'><b>Passive only.</b> Lookups go to public websites and public data services. Nothing is sent to the "
           "scammer's own computers or accounts, nothing is posted, and nobody is contacted. Results stay on this computer.</div>"]
    if msg:
        out.append(f"<div class='card {level}'>{e(msg)}</div>")
    if show:
        out.append(_results(show))
    out.append("<h2>Tools on this computer</h2>" + _tools())
    out.append("<h2>Check a username</h2><form method=post class=card><input type=hidden name=do value=maigret>"
               "<label>Username the scammer used (on Telegram, Instagram, a dating site...):<input type=text name=target "
               "placeholder='e.g. crypto_mentor_amy' autocomplete=off></label><p class=small>Checks the 500 most popular websites for an "
               "account with that name. Takes about 2 to 5 minutes.</p><button class=go>Check this username</button></form>")
    out.append("<h2>Check an email, phone number, website or name</h2><form method=post class=card><input type=hidden name=do value=spiderfoot>"
               "<label>What the scammer gave you:<input type=text name=target placeholder='e.g. support@fake-exchange.com, +1 251 555 0100, "
               "fake-exchange.com, or John Smith' autocomplete=off></label><p class=small>Searches public records and data services with "
               "SpiderFoot's passive checks. Often takes 10 to 60 minutes; you can close this page and come back. Some checks only run if "
               "you've added free keys inside SpiderFoot's own settings.</p><button class=go>Start the background check</button></form>")
    out.append("<h2>Your lookups</h2>" + _jobs_table(js))
    if running and not show:
        out.append("<p class=small>This page refreshes by itself while a lookup is running.</p>")
    out.append("</body></html>")
    return "".join(out)


def post(form):
    def g(k):
        v = form.get(k) or ""
        return (v[0] if v else "") if isinstance(v, list) else v
    do = g("do")
    if do == "maigret":
        jid, why = runner.start_maigret(g("target"))
        return page(why, "caution") if why else page("Started. Results usually take a few minutes.", "ok")
    if do == "spiderfoot":
        jid, why = runner.start_spiderfoot(g("target"))
        return page(why, "caution") if why else page("Started. SpiderFoot's passive checks often take 10 to 60 minutes.", "ok")
    if do == "stop":
        return page("Stopping the scan." if runner.stop(g("id")) else "Couldn't stop it (it may have just finished).", "info")
    if do == "delete":
        runner.delete(g("id"))
        return page("Deleted.", "info")
    return page()
