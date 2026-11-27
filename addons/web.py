"""Desk page /website ("My website"): PatchPulse, a separate product for people who own a website.

Until PatchPulse launches (addons.patchpulse.RELEASED is False) the page is a short "coming soon" card with a
link, and makes no connection of any kind. Connecting (typing the API key) only works at the computer: the
phone app's policy refuses POSTs to this page, and any field named like a key.
"""
import html

from addons import patchpulse as pp

e = lambda s: html.escape(str(s if s is not None else ""), quote=True)

CSS = ("body{font:20px/1.5 'Segoe UI',Arial,sans-serif;max-width:980px;margin:0 auto;padding:0 16px 40px;color:#111}"
       "h1{font-size:30px}h2{font-size:24px;margin:26px 0 8px}.card{border:2px solid #ddd;border-radius:12px;padding:14px 16px;margin:12px 0}"
       ".stop{background:#fdecee;border-color:#b00020}.caution{background:#fff8e6;border-color:#f2b01e}.ok{background:#e9f7ef;border-color:#2e7d32}"
       ".info{background:#eef3fb;border-color:#9bb}button{font-size:19px;padding:9px 18px;border-radius:10px;cursor:pointer}"
       ".go{background:#0b6b3a;color:#fff;border:0}input[type=text],input[type=password]{font-size:19px;padding:9px;width:100%;box-sizing:border-box}"
       ".small{font-size:16px;color:#444}.tag{display:inline-block;font-size:15px;font-weight:700;padding:2px 10px;border-radius:20px;"
       "background:#0b4f9c;color:#fff;vertical-align:middle}li{margin:6px 0}a{color:#0b4f9c}")

WHAT = ("<p><b>PatchPulse</b> watches websites you own, such as a business site on WordPress, for the flaws attackers are "
        "using right now. It checks every hour against official sources (CISA's list of exploited flaws and the national "
        "vulnerability database), and when your site is at risk it tells you in plain words what to do, with a message "
        "ready to send to your hosting company.</p>"
        "<ul><li>Out-of-date PHP, WordPress and plugins</li><li>Password and backup files left where anyone can download "
        "them</li><li>Expired or expiring security certificates</li><li>New outside code appearing on your homepage</li></ul>")
SEPARATE = ("<p class=small>PatchPulse is a separate, paid product from FPH LLC, the makers of ScamHunter. It isn't part of "
            "ScamHunter, and everything else on this Desk stays free.</p>")
ICON = {"stop": "&#9940;", "caution": "&#9888;&#65039;", "ok": "&#9989;"}


def _head(title="My website"):
    return (f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{e(title)}</title><style>{CSS}</style></head><body><h1>My website</h1>")


def page(msg="", level="info"):
    out = [_head()]
    if msg:
        out.append(f"<div class='card {level}'>{e(msg)}</div>")
    if not pp.RELEASED:
        out.append("<div class='card info'><h2 style='margin-top:0'>PatchPulse <span class=tag>Coming soon</span></h2>" + WHAT
                   + f"<p>PatchPulse will be available soon at <a href='{e(pp.SITE)}' target=_blank rel=noopener>patchpulsehq.com</a>. "
                   "Once you have it, this page will show how your websites are doing, and the Desk will warn you on your "
                   "phone if one needs attention.</p>" + SEPARATE + "</div></body></html>")
        return "".join(out)

    s = pp.summary()
    st = s["state"]
    if st == "ok":
        sites = s.get("sites") or []
        if not sites:
            out.append("<div class='card info'>PatchPulse is connected, but no websites are added yet. Add yours in PatchPulse.</div>")
        for x in sites:
            out.append(f"<div class='card {x['level']}'><h2 style='margin-top:0'>{ICON.get(x['level'], '')} {e(x['label'])}</h2>"
                       f"<p><b>{e(x['words'])}</b>" + (f": {e(x['top'])}" if x.get("top") else "") + "</p>"
                       + (f"<p class=small>Last checked {e(x['last_scan_at'])}</p>" if x.get("last_scan_at") else "")
                       + "</div>")
        out.append(f"<p><a href='{e(s['base'])}' target=_blank rel=noopener>Open PatchPulse for the details and fixes &rarr;</a></p>")
    else:
        words = {
            "not_connected": ("info", "Connect PatchPulse to see your websites here."),
            "bad_address": ("caution", "The saved PatchPulse address isn't on this computer. Connect again below."),
            "not_running": ("caution", "PatchPulse isn't running on this computer right now. Start it, then reload this page."),
            "bad_key": ("caution", "PatchPulse no longer accepts the saved key. Make a new one in PatchPulse > Settings and connect again."),
            "unlicensed": ("caution", "PatchPulse is installed but its license isn't active, so it isn't watching your websites. "
                                      + (s.get("message") or "")),
            "error": ("caution", s.get("message") or "PatchPulse answered in a way the Desk doesn't understand."),
        }.get(st, ("caution", "Something went wrong reading PatchPulse."))
        out.append(f"<div class='card {words[0]}'>{e(words[1])}</div>")
        if st == "not_connected":
            out.append("<div class=card>" + WHAT + f"<p>Don't have it yet? Get it at <a href='{e(pp.SITE)}' target=_blank rel=noopener>"
                       "patchpulsehq.com</a>.</p>" + SEPARATE + "</div>")

    if st in ("not_connected", "bad_address", "bad_key"):
        out.append("<h2>Connect PatchPulse</h2><div class=card><ol>"
                   "<li>Open PatchPulse on this computer and go to <b>Settings</b>.</li>"
                   "<li>Click <b>Create API key</b> and copy it (it starts with <code>ppk_</code>).</li>"
                   "<li>Paste it below. The Desk only reads your websites' status; it can't change anything in PatchPulse.</li></ol>"
                   "<form method=post><input type=hidden name=do value=connect>"
                   f"<p>PatchPulse address<br><input type=text name=url value='{e(pp.settings().get('url') or pp.DEFAULT_URL)}'></p>"
                   "<p>API key<br><input type=password name=api_key autocomplete=off></p>"
                   "<button class=go>Connect</button></form>"
                   "<p class=small>The key is locked to your Windows account, like the Desk's other keys, and is never shown again.</p></div>")
    elif st != "off":
        out.append("<form method=post><input type=hidden name=do value=disconnect><button>Disconnect PatchPulse</button></form>")
    out.append("</body></html>")
    return "".join(out)


def post(form):
    def g(k):
        v = form.get(k) or ""
        return (v[0] if v else "") if isinstance(v, list) else v
    do = g("do")
    if not pp.RELEASED:
        return page()
    if do == "connect":
        why = pp.connect(g("url"), g("api_key"))
        return page(why or "Connected. Your websites are shown below.", "caution" if why else "ok")
    if do == "disconnect":
        pp.disconnect()
        return page("Disconnected. The saved key was removed from this Desk.", "ok")
    return page()
