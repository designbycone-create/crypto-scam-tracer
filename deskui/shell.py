"""The Desk's tabs: every page is filed under one section, and every page gets the same header.

Sections keep the Desk from becoming one long page: crypto and wallets, phone and messages, online
defense, and settings each have their own tab, their own landing page and their own menu.
To add a page: add (path, label, one-line description) to its section's group below.
"""
import html

# (key, tab label, landing page, [(group label, [(path, label, description), ...]), ...])
SECTIONS = [
    ("overview", "Overview", "/", []),
    ("crypto", "Crypto & Wallets", "/crypto", [
        ("Protect", [
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
        ]),
    ]),
    ("settings", "Settings", "/settings", [
        ("Desk", [
            ("/alerts", "Alerts to your phone", "Where the Desk sends warnings: Telegram, ntfy or email."),
            ("/update", "Updates", "Install signed updates."),
            ("/setup", "Case setup", "Your case details: wallets, chains, the scam address."),
            ("/share", "Share ScamHunter", "Give the program to someone without giving them your case."),
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


CSS = """
#sh-shell{all:initial;display:block;box-sizing:border-box;width:100vw;margin:0 0 18px calc(50% - 50vw);
 background:#070b14;border-bottom:1px solid #1c2a40;font:16px/1.4 'Segoe UI',system-ui,Arial,sans-serif;color:#e8eef9;
 position:sticky;top:0;z-index:9999}
#sh-shell *{box-sizing:border-box;font-family:inherit}
#sh-shell .sh-top{display:flex;align-items:center;gap:6px;padding:8px 16px 0;overflow-x:auto;scrollbar-width:none}
#sh-shell .sh-brand{font-weight:800;letter-spacing:.08em;color:#5fe1ff;margin-right:14px;white-space:nowrap;text-decoration:none;font-size:16px}
#sh-shell .sh-tab{white-space:nowrap;color:#a9b8d0;text-decoration:none;padding:10px 16px;border-radius:10px 10px 0 0;font-size:17px;font-weight:600;
 border:1px solid transparent;border-bottom:none}
#sh-shell .sh-tab:hover{color:#fff;background:#0f1a2c}
#sh-shell .sh-tab.on{color:#fff;background:#0f1a2c;border-color:#1c2a40;box-shadow:inset 0 3px 0 #22d3ee}
#sh-shell .sh-sub{display:flex;flex-wrap:wrap;gap:6px 6px;align-items:center;padding:10px 16px;background:#0f1a2c}
#sh-shell .sh-grp{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#6b7f9e;margin:0 4px 0 10px}
#sh-shell .sh-grp:first-child{margin-left:0}
#sh-shell .sh-pill{white-space:nowrap;color:#cfe3ff;text-decoration:none;padding:6px 12px;border-radius:999px;border:1px solid #23395a;font-size:15px}
#sh-shell .sh-pill:hover{border-color:#22d3ee;color:#fff}
#sh-shell .sh-pill.on{background:#22d3ee;border-color:#22d3ee;color:#04111c;font-weight:700}
#sh-shell .sh-pledge{margin-left:auto;font-size:12px;color:#7ee2a8;white-space:nowrap;padding-left:12px}
body{margin-top:0!important}
@media(max-width:820px){#sh-shell .sh-top{flex-wrap:wrap;padding:8px 10px 0}#sh-shell .sh-brand{width:100%;margin:0 0 4px}
 #sh-shell .sh-tab{padding:9px 12px;font-size:16px;border-radius:10px 10px 0 0}#sh-shell .sh-pledge{display:none}
 #sh-shell .sh-sub{padding:8px 10px}#sh-shell .sh-grp{width:100%;margin:6px 0 0}}
@media print{#sh-shell{display:none}}
"""


def header(path):
    key, current = section_for(path)
    esc = lambda s: html.escape(s, quote=True)
    tabs = "".join(f"<a class='sh-tab{' on' if k == key else ''}' href='{h}'>{esc(t)}</a>" for k, t, h, _ in SECTIONS)
    sub = ""
    if key and key != "overview":
        _, tab, home, groups = section(key)
        bits = [f"<a class='sh-pill{' on' if current is None else ''}' href='{home}'>All {esc(tab)}</a>"]
        for g, pages in groups:
            bits.append(f"<span class=sh-grp>{esc(g)}</span>")
            bits += [f"<a class='sh-pill{' on' if p == current else ''}' href='{p}' title='{esc(d)}'>{esc(lbl)}</a>" for p, lbl, d in pages]
        sub = "<div class=sh-sub>" + "".join(bits) + "</div>"
    return (f"<style>{CSS}</style><div id=sh-shell><div class=sh-top><a class=sh-brand href='/'>&#128737;&#65039; SCAMHUNTER</a>{tabs}"
            f"<span class=sh-pledge>Free &middot; never asks for money or a seed phrase</span></div>{sub}</div>")


def wrap(body, path):
    """Put the Desk header at the top of an HTML page (no-op for printable/downloadable pages)."""
    if any(path.startswith(b) for b in BARE) or "id=sh-shell" in body:
        return body
    h = header(path)
    low = body[:4000].lower()
    i = low.find("<body")
    if i >= 0:
        j = body.find(">", i)
        return body[:j + 1] + h + body[j + 1:]
    i = low.find("</style>")
    if i >= 0:
        return body[:i + 8] + h + body[i + 8:]
    i = low.find("<h1")
    if i >= 0:
        return body[:i] + h + body[i:]
    return h + body
