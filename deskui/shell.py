"""The Desk's tabs: every page is filed under one section, and every page gets the same header.

Sections keep the Desk from becoming one long page: crypto and wallets, phone and messages, online
defense, and settings each have their own tab, their own landing page and their own menu.
To add a page: add (path, label, one-line description) to its section's group below.
"""
import html
import os
import re

from deskui import icons

# (key, tab label, landing page, [(group label, [(path, label, description), ...]), ...])
SECTIONS = [
    ("overview", "Overview", "/", []),
    ("threatmap", "Threat Map", "/threatmap", []),
    ("crypto", "Crypto & Wallets", "/crypto", [
        ("Protect", [
            ("/hwcheck", "New hardware wallet check", "Seven short questions about a new wallet, before you set it up."),
            ("/prescreen", "Check before you send", "Background check on any address before you send crypto to it."),
            ("/shield", "Wallet shield", "Find risky approvals in your wallet and see if it is being drained."),
            ("/clipguard", "Copy-paste guard", "Stops a copied address from being swapped for a scammer's."),
            ("/check", "Claim checker", "Is that 'recovery service' or 'support agent' real?"),
            ("/compromised", "Wallet compromised?", "What to do right now if someone has your keys."),
        ]),
        ("My case", [
            ("/case", "My case", "Where your funds are, the watchers, and what to do next."),
            ("/submit", "Freeze requests", "Draft freeze and preservation requests, track what you've sent."),
            ("/requests", "Officer packets", "Printable packets for police and investigators."),
            ("/evidence", "Court evidence", "Signed, verifiable evidence bundles."),
        ]),
        ("Investigate", [
            ("/graph", "Network graph", "Interactive map of the wallets and exchanges behind the scam."),
            ("/network", "Network table", "Every wallet in the network, as a table."),
            ("/radar", "Scam radar", "New scam wallets and patterns seen on-chain."),
            ("/intel", "Threat intel", "Search known scam addresses, operators and campaigns."),
            ("/lookup", "Look up a scammer", "Check a scammer's username, email, phone, website or name in public records (Maigret, SpiderFoot)."),
            ("/incident", "Incident mode", "Step-by-step help in the first hour after a theft."),
        ]),
    ]),
    ("phone", "Phone & Messages", "/phone", [
        ("Check", [
            ("/numbercheck", "Check a phone number", "Has this number been reported to the FTC as a scam or robocall?"),
            ("/msgcheck", "Is this message a scam?", "Paste a text, email or chat message and get a plain answer."),
        ]),
    ]),
    ("defense", "Online Defense", "/defense", [
        ("Protect", [
            ("/extension", "Browser extension", "Blocks address swaps, drainer pages and known attack scripts."),
            ("/sitewatch", "Sites I use", "Watches the websites you use for injected attack code."),
            ("/exposure", "Exposure check", "Is anything on your home network open to the internet?"),
            ("/malware", "Malware & link check", "Windows Defender status, check a download before opening it or a link before clicking it."),
            ("/secretscan", "Secrets left in the open", "Find seed phrases, private keys and passwords saved in files on this computer."),
            ("/agentguard", "Agent firewall", "Stops AI agents from doing risky things without your OK."),
            ("/website", "My website", "PatchPulse, coming soon: watches websites you own for flaws attackers are using."),
        ]),
    ]),
    ("settings", "Settings", "/settings", [
        ("Desk", [
            ("/alerts", "Alerts to your phone", "Where the Desk sends warnings: Telegram, ntfy or email."),
            ("/update", "Updates", "Install signed updates."),
            ("/setup", "Case setup", "Your case details: wallets, chains, the scam address."),
            ("/share", "Share ScamHunter", "Give the program to someone without giving them your case."),
            ("/relay", "Phone app", "Pair the ScamHunter Threat Desk phone app with this Desk (encrypted, through your own Worker)."),
        ]),
    ]),
]

_BY_PATH = {}
for _key, _tab, _home, _groups in SECTIONS:
    _BY_PATH[_home] = (_key, None)
    for _g, _pages in _groups:
        for _p, _label, _desc in _pages:
            _BY_PATH[_p] = (_key, _p)

# pages that are printed or downloaded: no header
BARE = ("/kit/", "/ic3")


def section_for(path):
    if path in _BY_PATH:
        return _BY_PATH[path]
    for p, v in _BY_PATH.items():
        if p != "/" and path.startswith(p + "/"):
            return v
    return (None, None)


def section(key):
    return next(s for s in SECTIONS if s[0] == key)


OWN = "/*nd-own*/"
# full-screen tools: shown on a stage under the header, without the page menu
STAGE = ("/graph",)
# menu items that get a "New" badge
NEW = {"/hwcheck", "/website"}
# bottom bar in the phone app: (label, icon, address, sections it covers)
PHONE_TABS = [("Home", "home", "/", ("overview", "settings")), ("Map", "map", "/threatmap", ("threatmap",)),
              ("Crypto", "crypto", "/crypto", ("crypto",)), ("Phone", "phone", "/phone", ("phone",)),
              ("Defense", "defense", "/defense", ("defense",))]
HERE = os.path.dirname(os.path.abspath(__file__))
_CSS = None


def css():
    global _CSS
    if _CSS is None:
        with open(os.path.join(HERE, "nightdesk.css"), encoding="utf-8") as f:
            _CSS = f.read()
    return _CSS


esc = lambda s: html.escape(str(s), quote=True)


def _new(p):
    return f"<span class=nd-new>{icons.svg('spark', 16)}New</span>" if p in NEW else ""


def _label(path):
    for _k, _t, _h, groups in SECTIONS:
        for g, pages in groups:
            for p, lbl, _d in pages:
                if p == path:
                    return g, lbl
    return None, None


def header(path):
    key, _ = section_for(path)
    tabs = "".join(f"<a href='{h}'" + (" aria-current=page" if k == key else "") + f">{esc(t)}</a>" for k, t, h, _ in SECTIONS)
    return ("<header class=shell-head><div class=brandbar>"
            f"<a class=brand href='/'><span class=mark>{icons.svg('shield', 40)}</span><span><span class=brand-name>ScamHunter</span>"
            "<br><span class=brand-sub>Threat Desk</span></span></a>"
            "<p class=pledge>Free. Never asks for money or a recovery phrase.</p>"
            "<span class=desk-status><span class=dot></span>Desk online</span></div>"
            f"<nav class=tabs aria-label='Sections'>{tabs}</nav></header>")


def menu(path):
    key, current = section_for(path)
    if not key or not section(key)[3]:
        return ""
    _, tab, home, groups = section(key)
    out = [f"<nav class=group-menu aria-label='{esc(tab)} pages'>"]
    for g, pages in groups:
        out.append(f"<p class=group-label>{esc(g)}</p>")
        out += [f"<a href='{p}' title='{esc(d)}'" + (" aria-current=page" if p == current else "") + f"><span>{esc(lbl)}</span>{_new(p)}</a>"
                for p, lbl, d in pages]
    return "".join(out) + "</nav>"


def crumbs(path):
    key, current = section_for(path)
    if not key or not current:
        return ""
    _, tab, home, _g = section(key)
    g, lbl = _label(current)
    return (f"<nav class=nd-crumbs aria-label='You are here'><a href='{home}'>{esc(tab)}</a><span aria-hidden=true>/</span>"
            f"<span>{esc(g)}</span><span aria-hidden=true>/</span><span aria-current=page>{esc(lbl)}</span></nav>")


def phone_back(path):
    key, current = section_for(path)
    if not key or key == "overview":
        return ""
    _, tab, home, _g = section(key)
    if current is None and key != "settings":
        return ""
    target, name = (home, tab) if current else ("/", "Home")
    return f"<a class=nd-back href='{target}'>&larr;&nbsp;Back to {esc(name)}</a>"


def tabbar(path):
    key, _ = section_for(path)
    items = "".join(f"<a href='{h}'" + (" aria-current=page" if key in keys else "") + f">{icons.svg(ic, 24, 'currentColor')}<span>{lbl}</span></a>"
                    for lbl, ic, h, keys in PHONE_TABS)
    return f"<nav class=tabbar aria-label='Sections'>{items}</nav>"


_PHONE_JS = ("<script>document.querySelectorAll('.nd-page table').forEach(function(t){var h=[].map.call(t.querySelectorAll('thead th'),"
             "function(x){return x.textContent.trim()});if(!h.length)return;t.querySelectorAll('tbody tr').forEach(function(r){"
             "[].forEach.call(r.children,function(c,i){if(h[i]&&!c.hasAttribute('data-th'))c.setAttribute('data-th',h[i])})})});</script>")


def _parts(body):
    """Split a page into (title, its own CSS, head extras, body attributes, body content)."""
    m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
    title = m.group(1).strip() if m else "ScamHunter Threat Desk"
    styles = re.findall(r"<style[^>]*>(.*?)</style>", body, re.I | re.S)
    rest = re.sub(r"<style[^>]*>.*?</style>", "", body, flags=re.I | re.S)
    head_extra = ""
    hm = re.search(r"<head[^>]*>(.*?)</head>", rest, re.I | re.S)
    if hm:
        head_extra = "".join(re.findall(r"<script\b.*?</script>", hm.group(1), re.I | re.S))
        rest = rest[:hm.start()] + rest[hm.end():]
    bm = re.search(r"<body([^>]*)>", rest, re.I)
    attrs = ""
    if bm:
        attrs = re.sub(r"\s(class|style)=('[^']*'|\"[^\"]*\"|\S+)", "", bm.group(1))
        rest = rest[bm.end():]
    rest = re.sub(r"</body>\s*</html>\s*$", "", rest.strip(), flags=re.I)
    rest = re.sub(r"(?is)^\s*<!doctype[^>]*>|</?html[^>]*>|</body>", "", rest).strip()
    return title, styles, head_extra, attrs, rest


_SMALL = re.compile(r"(font(?:-size)?\s*:[^;}'\"]*?)\b(\d{1,2}(?:\.\d+)?)px", re.I)


def _no_small(text):
    """Older pages set labels at 11-17px; the Night Desk minimum is 20px on the computer and 18px on the phone
    (var(--nd-min)). Raise only sizes below it, and only inside font / font-size declarations."""
    return _SMALL.sub(lambda m: m.group(1) + ("var(--nd-min)" if float(m.group(2)) < 18 else m.group(2) + "px"), text)


def wrap(body, path, phone=False):
    """Put a page inside the Night Desk shell (no-op for printable/downloadable pages)."""
    if any(path.startswith(b) for b in BARE) or "class=nd-main" in body:
        return body
    title, styles, head_extra, attrs, content = _parts(body)
    # styles written for the Night Desk start with OWN and sit above the shared look; older styles go in a lower layer
    own = "".join(x for x in styles if x.lstrip().startswith(OWN))
    legacy = _no_small("".join(x for x in styles if not x.lstrip().startswith(OWN)).replace("@charset", "/*charset*/"))
    content = re.sub(r"style=(['\"])(.*?)\1", lambda m: "style=" + m.group(1) + _no_small(m.group(2)) + m.group(1), content, flags=re.S)
    page = f"<div class=nd-page>{content}</div>"
    head = (f"<!doctype html><html lang=en{' class=nd-phone' if phone else ''}><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1,viewport-fit=cover'>"
            f"<title>{title}</title><style>@layer legacy{{{legacy}}}</style><style>{css()}</style>"
            + (f"<style>{own}</style>" if own else "") + f"{head_extra}</head>")
    if phone:
        return (f"{head}<body{attrs}><main id=main class=nd-main>{phone_back(path)}{page}</main>{tabbar(path)}{_PHONE_JS}</body></html>")
    if path in STAGE:
        return (f"{head}<body{attrs}><a class=skip href='#main'>Skip to the page</a>{header(path)}"
                f"<main id=main class='nd-main nd-stage'>{content}</main></body></html>")
    m = menu(path)
    return (f"{head}<body{attrs}><a class=skip href='#main'>Skip to the page</a>{header(path)}"
            f"<div class='workspace{'' if m else ' no-menu'}'>{m}<main id=main class=nd-main>{crumbs(path)}{page}</main></div></body></html>")
