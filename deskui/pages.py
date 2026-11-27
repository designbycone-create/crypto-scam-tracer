"""Overview and the section landing pages (Crypto & Wallets, Phone & Messages, Online Defense, Settings),
laid out to the Night Desk design (design/redesign/DESK_REDESIGN.md): one main action per card, a word plus an
icon on every result, large plain type. No outside scripts or fonts, so the Desk works the same offline.
"""
import html
import json
import os
from datetime import datetime

from deskui import data, icons, shell

HERE = os.path.dirname(os.path.abspath(__file__))
e = lambda s: html.escape(str(s if s is not None else ""), quote=True)


def _map():
    with open(os.path.join(HERE, "us_states.json"), encoding="utf-8") as f:
        return json.load(f)


def _ago(t):
    try:
        then = datetime.strptime(str(t)[:16].replace("T", " "), "%Y-%m-%d %H:%M")
    except ValueError:
        return e(str(t)[:16]) or "Earlier"
    mins = int((datetime.now() - then).total_seconds() // 60)
    if mins < 1:
        return "Just now"
    if mins < 60:
        return f"{mins} min ago"
    if mins < 24 * 60:
        h = mins // 60
        return f"{h} hour{'s' if h > 1 else ''} ago"
    return then.strftime("%b %d")


def _head(title, lead, kicker=None):
    return ("<div class=page-head>" + (f"<p class=kicker>{e(kicker)}</p>" if kicker else "")
            + f"<h1>{e(title)}</h1><p class=lead>{e(lead)}</p></div>")


def _watchers():
    s = data.services()
    rows = s.get("list") or []
    if not rows:
        return ("<section class=card><div class=spread><h2>Watchers</h2>" + icons.chip("caution", "Not sure") + "</div>"
                "<p>The Desk couldn't read its watcher status yet. If this stays, open My case to check.</p></section>")
    needed = [r for r in rows if not r["skipped"]]
    up = sum(1 for r in needed if r["alive"])
    title = f"{up} watchers running" if up == len(needed) else f"{up} of {len(needed)} watchers running"
    items = []
    for r in rows:
        if r["skipped"]:
            items.append(f"<li><span class='dot info'></span><span>{e(r['name'])}</span><span class=note>Off</span></li>")
        elif r["alive"]:
            items.append(f"<li><span class=dot></span><span>{e(r['name'])}</span><span class=note>Running</span></li>")
        else:
            items.append(f"<li>{icons.svg('careful', 20)}<span>{e(r['name'])}</span><span class=note>Not running</span></li>")
    chip = icons.chip("ok", "OK") if up == len(needed) else icons.chip("caution")
    return (f"<section class=card id=watchers><div class=spread><h2>{e(title)}</h2>{chip}</div>"
            f"<ul class=watcher-list>{''.join(items)}</ul></section>")


def _activity(sec=None, n=6):
    rows = [x for x in data.feed() if not sec or x.get("sec") == sec][:n]
    if not rows:
        body = "<p>Nothing here yet. Checks you run and warnings the watchers find show up here.</p>"
    else:
        body = "<ul class=feed>" + "".join(
            f"<li><span class=when>{_ago(x.get('t'))}</span><span>{icons.chip(x.get('lvl', 'info'))} "
            f"<a href='{e(x.get('href') or '#')}'>{e(x.get('title'))}</a>"
            + (f"<br><span class=note>{e(x.get('detail'))}</span>" if x.get("detail") else "") + "</span></li>" for x in rows) + "</ul>"
    return f"<section class=card><h2>Recent activity</h2>{body}</section>"


def _rising():
    try:
        from threatmap import feeds
        s = feeds.summary()
    except Exception:
        s = {}
    fams = [r for r in (s.get("rising") or []) if r.get("kind") == "family"][:3]
    if not fams:
        why = ("The Desk is still learning what's normal for each threat." if s.get("learning_since") else
               "Nothing is above its usual level right now.")
        return f"<section class=card><h2>Rising threats this week</h2><p>{why}</p><a class='btn btn-secondary' href='/threatmap'>Open the Threat Map</a></section>"
    cards = "".join(
        f"<div class='card card-quiet'>{icons.chip('caution')}<h3 style='margin:.6rem 0 .4rem'>{e(r['key'])}</h3>"
        f"<p>{e(r['now'])} reports in the last day, about {e(r['x'])} times its usual level.</p>"
        f"<a class='btn btn-secondary' href='/threatmap?q={e(r['key'])}'>See this threat</a></div>" for r in fams)
    return f"<section class=card><h2>Rising threats this week</h2><div class=stack>{cards}</div></section>"


QUICK = ("<section class=card><h2>Quick check</h2><p>Paste one thing. The Desk opens the right check.</p>"
         "<form method=post action=/quick><div class=field><label for=q>Paste a wallet address, a phone number, or a message</label>"
         "<textarea id=q name=q placeholder='Example: a wallet address, or the text of a message' required></textarea>"
         "<p class=hint>One check at a time. Never paste a recovery phrase here.</p></div>"
         "<button class='btn btn-primary'>Check this</button></form></section>")


def overview(phone=False):
    body = [_head("Overview", "Everything the Desk is watching. Pick a tab to work in one area."), _watchers(),
            "<div class=grid-12 style='margin-top:1.5rem'><div class=span-7>", _activity(), "</div><div class=span-5>", _rising(),
            "</div></div><div style='margin-top:1.5rem'>", QUICK, "</div>"]
    if phone:
        body.append("<section class=card style='margin-top:1.5rem'><h2>Settings</h2><p>Alerts, updates, and pairing.</p>"
                    "<div class=actions><a class='btn btn-secondary btn-block' href='/settings'>Desk settings</a>"
                    "<a class='btn btn-secondary btn-block' href='shapp://settings'>Phone app settings</a></div></section>")
    return _page("Overview", "".join(body))


def _page(title, body):
    return (f"<!doctype html><html><head><meta charset=utf-8><title>{e(title)} - ScamHunter Threat Desk</title></head>"
            f"<body>{body}</body></html>")


def _usmap():
    m = _map()
    st = (data.live().get("phone") or {}).get("states") or {}
    mx = max([1] + list(st.values()))
    def fill(v):
        if not v:
            return "#132033"
        t = (v / mx) ** 0.5
        return f"hsl({int(200 - 170 * t)},{int(55 + 30 * t)}%,{int(22 + 30 * t)}%)"
    paths = "".join(f"<path d='{d}' fill='{fill(st.get(n, 0))}' stroke='#2C415C'><title>{e(n)}: {st.get(n, 0):,} reports</title></path>"
                    for n, d in m["states"].items() if not n.endswith("@c"))
    top = sorted(st.items(), key=lambda kv: -kv[1])[:5]
    rows = "".join(f"<tr><td>{e(n)}</td><td>{v:,}</td></tr>" for n, v in top) or "<tr><td colspan=2>State data starts with the next FTC download.</td></tr>"
    return (f"<section class=card style='margin-top:1.5rem'><h2>Scam-call reports by state</h2>"
            "<p>Reports to the FTC in the last 30 days, by the state of the person called. These are unverified consumer reports.</p>"
            f"<div class=grid-12><div class=span-7><svg viewBox='{m['viewBox']}' role=img aria-label='Map of scam-call reports by state' style='width:100%;height:auto'>{paths}</svg></div>"
            f"<div class=span-5><table><thead><tr><th>State</th><th>Reports</th></tr></thead><tbody>{rows}</tbody></table></div></div></section>")


HUB = {
    "crypto": "Protect your wallets, follow stolen funds, and build the case.",
    "phone": "Check a caller or a message before you trust it.",
    "defense": "Your browser, the websites you use, your home network, and AI agents.",
    "settings": "Where alerts go, updates, your case details, and the phone app.",
}


def hub(key):
    _, tab, home, groups = shell.section(key)
    cards = []
    for g, pages in groups:
        links = "".join(f"<a class=nd-tile href='{p}'><b>{e(l)} {shell._new(p)}</b><span>{e(dsc)}</span></a>" for p, l, dsc in pages)
        cards.append(f"<section class=nd-hubgroup><h2>{e(g)}</h2><div class=nd-tiles>{links}</div></section>")
    extra = _usmap() if key == "phone" else ""
    if key in ("crypto", "defense"):        # each tab's own threat map, like the scam-call map on Phone & Messages
        try:
            from threatmap import page as tmpage
            extra = tmpage.preview("crypto", "/cryptomap") if key == "crypto" else tmpage.preview("cyber", "/cybermap")
        except Exception as ex:
            extra = f"<section class=card style='margin-top:1.5rem'><p>The threat map couldn't be drawn ({e(type(ex).__name__)}).</p></section>"
    if key == "phone":
        extra += ("<section class=card style='margin-top:1.5rem'><h2>ScamHunter Guard for your phone</h2>"
                  "<p>The free Android app warns about scam calls while the phone rings, checks messages, and helps report a scam call "
                  "in large print. It only ever sees the caller's number, never the call itself.</p></section>")
    return _page(tab, _head(tab, HUB[key]) + "".join(cards) + extra)
