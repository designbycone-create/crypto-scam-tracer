"""Desk pages: Submission Center, Incident mode, Scam radar, Claim checker.

Rendered server-side (standard library). POSTs are accepted only from the
Desk's own pages (Origin/Referer must be localhost), so a website you visit
cannot change your tracker.
"""
import html
import json
import os
import urllib.parse

from . import channels, custody, tracker, xrpl_tokens

e = lambda s: html.escape(str(s if s is not None else ""), quote=True)
KITS = "freeze_kits"

CSS = """:root{--bg:#0f1115;--fg:#e8eaf0;--mut:#9aa1b2;--line:#262b36;--acc:#5aa2ff;--warn:#ff6a5a;--ok:#86efac;--card:#151922}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:1000px;margin:0 auto;padding:16px}
h1{font-size:22px;margin:0 0 4px} h2{font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin:26px 0 8px}
h3{font-size:16px;margin:0 0 6px} a{color:var(--acc)} small{font-size:12px}
.nav a{margin-right:14px;font-weight:600;text-decoration:none} .mut{color:var(--mut)} .warn{color:var(--warn)} .ok{color:var(--ok)}
.card{border:1px solid var(--line);background:var(--card);border-radius:12px;padding:14px;margin:10px 0}
.card.you{border:2px solid var(--warn)} .pledge{border:1px solid #2f6f4f;background:#0f1f17;border-radius:10px;padding:8px 12px;font-size:13px;margin:10px 0}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;background:#333;margin-left:6px;vertical-align:middle}
.badge.you{background:var(--warn);color:#000} .badge.ok{background:#16a34a;color:#000} .badge.amber{background:#d97706;color:#000}
.btn{display:inline-block;background:var(--acc);color:#07101f;padding:6px 12px;border-radius:8px;text-decoration:none;font-weight:600;margin:2px 4px 2px 0;border:0;cursor:pointer;font-size:13px}
.btn.alt{background:transparent;color:var(--acc);border:1px solid var(--acc)} .btn.red{background:var(--warn)}
table{width:100%;border-collapse:collapse;font-size:13px} td,th{border-bottom:1px solid var(--line);padding:7px;text-align:left;vertical-align:top}
.m{font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}
select,input,textarea{background:#0b0d12;color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:5px;font:13px system-ui}
textarea{width:100%;min-height:140px;box-sizing:border-box}
.chan{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center;border-top:1px dashed var(--line);padding:8px 0}
.clock{font-weight:700;font-size:15px} .step{counter-increment:s} .verdict{font-size:22px;font-weight:800}
@media(max-width:640px){.chan{grid-template-columns:1fr}}"""

JS = """<script>
async function copyFile(p,btn){try{const r=await fetch('/kit/'+p);const t=await r.text();await navigator.clipboard.writeText(t);
btn.textContent='Copied ✓';setTimeout(()=>btn.textContent='Copy text',2000)}catch(x){window.open('/kit/'+p,'_blank')}}
</script>"""

PLEDGE = ("<div class=pledge><b>Free for victims. Always.</b> This tool never asks for money, a seed phrase or a "
          "\"recovery fee\", never contacts anyone for you, never sends anything without you, and never promises "
          "recovery. Anyone who does is running a recovery scam.</div>")


def shell(title, body, refresh=None):
    nav = ("<div class=nav><a href='/'>Desk</a><a href='/graph'>Network graph</a><a href='/submit'>Submission Center</a><a href='/incident'>Incident mode</a>"
           "<a href='/radar'>Scam radar</a><a href='/check'>Claim checker</a></div>")
    meta = f"<meta http-equiv=refresh content={refresh}>" if refresh else ""
    return (f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"{meta}<title>{e(title)}</title><style>{CSS}</style>{JS}</head><body>{nav}{body}</body></html>")


def _j(p):
    try:
        with open(p, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return None


def _read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _status_form(key, st, label="Status", deadline_hint=""):
    s = tracker.get(st, key)
    opts = "".join(f"<option{' selected' if o == s.get('state', 'to do') else ''}>{e(o)}</option>" for o in tracker.STATES)
    badge_cls = {"submitted": "amber", "acknowledged": "amber", "frozen": "ok", "not needed": ""}.get(s.get("state"), "")
    hist = ""
    if s.get("updated"):
        hist = f"<small class=mut> · {e(s.get('state'))} {e(s.get('updated', '')[:16])}" + \
               (f" · case #{e(s['case_no'])}" if s.get("case_no") else "") + "</small>"
    return (f"<form method=post action='/submit/status' style='margin:4px 0'>"
            f"<input type=hidden name=key value='{e(key)}'>"
            f"<span class='badge {badge_cls}'>{e(s.get('state', 'to do'))}</span> "
            f"<select name=state>{opts}</select> <input name=case_no placeholder='case / ticket #' size=12 value='{e(s.get('case_no', ''))}'> "
            f"<input name=when placeholder='when (optional) YYYY-MM-DD HH:MM' size=24> "
            f"<button class='btn alt'>Save</button>{hist}{deadline_hint}</form>")


def _gmail(to, subject, body):
    if len(body) > 6000:
        body = body[:6000] + "\n\n[...full text in the attached kit file]"
    return "https://mail.google.com/mail/?" + urllib.parse.urlencode(
        {"view": "cm", "fs": "1", "to": to, "su": subject, "body": body})


def _subject_and_body(text):
    if text.startswith("SUBJECT:"):
        first, _, rest = text.partition("\n")
        return first[8:].strip(), rest.lstrip("\n")
    return "Stolen funds - freeze and preservation request", text


def submission_center(desk_note=""):
    st = tracker.load()
    case_dir = os.path.join(KITS, "_case")
    if not os.path.isdir(case_dir):
        return shell("Submission Center", PLEDGE + "<h1>Submission Center</h1><p class=mut>Building your first freeze kits&hellip; "
                     "(the Responder service creates them within a minute of the network map existing). "
                     "Refresh shortly.</p>", refresh=20)
    body = [PLEDGE, "<h1>&#128232; Submission Center</h1>",
            "<p class=mut>Every route below is one that actually gets freezes done. Exchanges freeze on "
            "<b>law-enforcement</b> requests &mdash; so the plan is: alert the industry network (SEAL 911), file your "
            "victim reports, and hand your officer a ready-to-file packet. Mark each step as you go.</p>"]

    # ---- network-wide steps
    body.append("<h2>Do these first (all cases)</h2>")
    files = {"seal911": "_case/seal911_message.txt", "chainabuse": "_case/chainabuse_update.txt",
             "ic3": "_case/ic3_update.txt", "local_police": None}
    for key, ent in channels.network_channels():
        btns = ""
        for c in ent.get("channels", []):
            if c.get("url"):
                lbl = {"telegram": "Open Telegram bot", "webform": "Open report form",
                       "in_person": "Find FBI field office"}.get(c["type"], "Open")
                btns += f"<a class=btn href='{e(c['url'])}' target=_blank>{lbl}</a>"
            if c.get("email") and c.get("verified"):
                f = files.get(key)
                txt = _read(os.path.join(KITS, f)) if f else ""
                btns += f"<a class='btn alt' href='{e(_gmail(c['email'], 'URGENT - fraud victim, funds moving (XRP Ledger)', txt))}' target=_blank>Email draft</a>"
        f = files.get(key)
        if f:
            btns += (f"<button class='btn alt' onclick=\"copyFile('{f}',this)\">Copy text</button>"
                     f"<a class='btn alt' href='/kit/{f}' target=_blank>View</a>")
        if key == "local_police":
            btns += "<a class='btn red' href='/kit/_case/officer_packet.html' target=_blank>Print Officer Packet</a>"
        body.append(f"<div class=card><h3>{e(ent['name'])}</h3><small class=mut>{e(ent['why'])}</small>"
                    f"<div style='margin-top:8px'>{btns}</div>{_status_form('net:' + key, st)}</div>")

    # ---- per exchange targets
    from . import kit as _kit
    root, targets, issuer_targets, mc_ops = _kit.collect()
    yours = [t for t in targets.values() if t["yours"]]
    others = [t for t in targets.values() if not t["yours"]]
    ex_status = (_j("exchange_status.json") or {}).get("exchanges", {})
    body.append("<h2>Where YOUR funds landed</h2>")
    if not yours:
        body.append("<p class=ok>Your funds have not reached an exchange yet. The moment they do, a kit appears here and "
                    "you get a critical alert on every channel.</p>")
    for t in sorted(yours, key=lambda t: -sum(d["xrp"] for d in t["deposits"])):
        body.append(_target_card(t, st, ex_status, mine=True))
    body.append(f"<h2>Other exchanges this network cashes out through ({len(others)})</h2>"
                "<p class=mut>Not your funds, but other victims'. Each has an evidence kit for IC3 and for the officer &mdash; "
                "the more of these that get frozen, the more of the operation is shut down.</p>")
    if others:
        rows = ""
        for t in sorted(others, key=lambda t: -sum(d["xrp"] for d in t["deposits"])):
            tid = t["id"]
            le = [c for c in t["entry"].get("channels", []) if c.get("who") in ("law_enforcement", "both")]
            atts = t.get("attributions") or {}
            att_txt = "".join(f"<br><small class=mut>{e(v.get('confidence'))}: {e((v.get('evidence') or [''])[0])}</small>"
                              for v in list(atts.values())[:1])
            rows += (f"<tr id='{e(tid)}'><td><b>{e(t['entry'].get('name', tid))}</b>{att_txt}</td><td>{len(t['deposits'])}</td>"
                     f"<td>{sum(d['xrp'] for d in t['deposits']):,.0f}</td>"
                     f"<td>{'<br>'.join(e(c.get('label', c['type'])) for c in le) or '<span class=mut>officer route (unverified)</span>'}</td>"
                     f"<td><a href='/kit/{e(tid)}/officer_request.txt' target=_blank>officer request</a> · "
                     f"<a href='/kit/{e(tid)}/fund_inflow.csv'>CSV</a></td></tr>")
        body.append(f"<table><tr><th>Platform</th><th>Deposits</th><th>XRP</th><th>LE channel</th><th>Kit</th></tr>{rows}</table>")

    # ---- issuers
    body.append("<h2 id=issuers>Issuer freezes (tokens the network holds)</h2>")
    toks = xrpl_tokens.load()
    if issuer_targets or any(op.get("kind") == "stablecoin_issuer" for op in mc_ops):
        rows = "".join(f"<tr><td>{e(h['issuer_name'] or h['issuer'])}</td><td>{e(h['currency'])}</td><td>{h['balance']:,.2f}</td>"
                       f"<td class=m>{e(h['wallet'])}</td><td>{'clawback' if h['clawback'] else 'freeze'}"
                       f"{' · <b class=ok>already frozen</b>' if h['frozen_by_issuer'] else ''}</td></tr>" for h in issuer_targets)
        body.append(f"<table><tr><th>Issuer</th><th>Token</th><th>Amount</th><th>Held by</th><th>Issuer can</th></tr>{rows}</table>"
                    "<p><a class=btn href='/kit/_case/issuer_requests.txt' target=_blank>Issuer request text</a> "
                    "<small class=mut>Route through your officer and SEAL 911 &mdash; issuers act on law-enforcement requests.</small></p>"
                    + _status_form("issuers", st))
    else:
        body.append(f"<p class=mut>No freezable issued tokens found in the network"
                    f"{' (last scan ' + e(toks['scanned']) + ', ' + str(toks['wallets_scanned']) + ' wallets)' if toks else ' yet'}. "
                    "XRP itself can't be frozen &mdash; but if the network swaps into RLUSD or another issued token, it shows up here.</p>")

    # ---- integrity
    ok, n, bad = custody.verify_log()
    body.append(f"<h2>Evidence integrity</h2><p>{'<span class=ok>&#10003; Custody log intact</span>' if ok else '<span class=warn>&#9888; Custody log altered at line ' + str(bad) + '</span>'}"
                f" &mdash; {n} recorded file versions, each SHA-256 hashed. Every kit folder has a MANIFEST.txt an officer can verify.</p>")
    return shell("Submission Center", "".join(body))


def _target_card(t, st, ex_status, mine):
    tid, ent = t["id"], t["entry"]
    rec = st["targets"].get(tid, {})
    xrp = sum(d["xrp"] for d in t["deposits"] if d["yours"]) or sum(d["xrp"] for d in t["deposits"])
    tags = ", ".join(sorted({str(d["tag"]) for d in t["deposits"] if d["yours"]}))
    out = [f"<div class='card you' id='{e(tid)}'><h3>{e(ent.get('name', 'Unidentified custodial service'))}"
           f"<span class='badge you'>YOUR FUNDS</span></h3>",
           f"<div>{xrp:,.2f} XRP &middot; destination tag <b>{e(tags)}</b> &middot; "
           f"<span class=clock>cash-out detected {e(tracker.elapsed(rec.get('yours_since') or rec.get('detected', '')))}</span></div>"]
    exs = ex_status.get(t["key"] or "", {})
    if exs.get("state") not in (None, "no public status feed", "none"):
        out.append(f"<div class=warn>Exchange status: {e(exs.get('description') or exs.get('state'))} {e(', '.join(exs.get('incidents') or []))}</div>")
    if ent.get("us_restricted"):
        out.append("<div class=warn><small>&#9888; Restricts US users &mdash; its consumer pages may block your IP. Do not use a VPN. "
                   "The law-enforcement route below (through your officer) and SEAL 911 are not geo-blocked.</small></div>")
    if ent.get("note"):
        out.append(f"<div><small class=mut>{e(ent['note'])}</small></div>")
    notice = _read(os.path.join(KITS, tid, "victim_notice.txt"))
    subj, nbody = _subject_and_body(notice)
    chans = ent.get("channels", [])
    for i, c in enumerate(chans):
        key = f"{tid}:{i}"
        who = {"victim": "You file this", "law_enforcement": "Your OFFICER files this", "both": "You or your officer"}.get(c.get("who"), "")
        btns = ""
        if c.get("url"):
            btns += f"<a class=btn href='{e(c['url'])}' target=_blank>Open</a>"
        if c.get("email"):
            if c.get("who") == "law_enforcement":
                btns += f"<span class=m>{e(c['email'])}</span> "
            elif c.get("verified"):
                btns += f"<a class='btn' href='{e(_gmail(c['email'], subj, nbody))}' target=_blank>Email draft</a>"
        if c.get("who") in ("victim", "both"):
            btns += f"<button class='btn alt' onclick=\"copyFile('{e(tid)}/victim_notice.txt',this)\">Copy text</button>"
        else:
            btns += f"<a class='btn alt' href='/kit/{e(tid)}/officer_request.txt' target=_blank>Officer request</a>"
        dl_hint = ""
        if c.get("who") == "victim" and ent.get("deadline_hours"):
            dl = tracker.deadline_from(st, key, ent["deadline_hours"])
            if dl:
                txt, secs = tracker.countdown(dl)
                dl_hint = f"<div class='clock {'warn' if (secs or 0) < 12 * 3600 else ''}'>&#9200; Law-enforcement request due: {e(txt)}</div>"
            else:
                dl_hint = f"<div><small class=warn>{e(ent['deadline_hours'])}h law-enforcement clock starts when you mark this submitted.</small></div>"
        out.append(f"<div class=chan><div><b>{e(c.get('label', c['type']))}</b> <small class=mut>· {e(who)}"
                   f"{'' if c.get('verified') else ' · NOT verified &mdash; confirm on the official site'}</small><br>{btns}</div>"
                   f"<div></div></div>{_status_form(key, st, deadline_hint=dl_hint)}")
    if not chans:
        out.append(f"<div class=chan><div><b>No verified channel yet.</b> <small class=mut>Use SEAL 911 + your officer (Officer Packet lists this platform).</small></div></div>"
                   + _status_form(f"{tid}:officer", st))
    if ent.get("needs"):
        out.append("<div><small><b>This platform asks for:</b> " + " · ".join(e(n) for n in ent["needs"]) + "</small></div>")
    files = sorted(os.listdir(os.path.join(KITS, tid))) if os.path.isdir(os.path.join(KITS, tid)) else []
    out.append("<div style='margin-top:8px'><small>Kit files: " +
               " · ".join(f"<a href='/kit/{e(tid)}/{e(f)}' target=_blank>{e(f)}</a>" for f in files) +
               f"<br><span class=mut>Folder on your PC: {e(os.path.abspath(os.path.join(KITS, tid)))} (add your withdrawal screenshot here)</span></small></div></div>")
    return "".join(out)


# ------------------------------------------------------------ incident ------

def incident_page(msg=""):
    from responder import incident
    d = incident.load()
    rows = "".join(f"<tr><td>{e(r['chain'])}</td><td class=m>{e(r['address'])}</td><td>{e(r.get('label'))}</td>"
                   f"<td><small>{e(r.get('added'))}</small></td></tr>" for r in reversed(d["addresses"][-200:]))
    return shell("Incident mode", f"""<h1>&#128680; Incident mode</h1>
<p class=mut>A hack or a new scam just happened? Paste anything that contains the attacker's addresses &mdash; a tweet, an incident post, a list.
Addresses are checksum-validated. <b>XRPL</b> ones are watched live (critical alert the moment funds hit an exchange);
<b>Ethereum/EVM, Tron, Bitcoin</b> ones are followed by the multi-chain tracer, which drafts issuer and exchange freeze requests.</p>
{f"<div class=pledge>{e(msg)}</div>" if msg else ""}
<form method=post action='/incident'><input name=label placeholder='Incident name (e.g. Exchange X hot-wallet drain)' style='width:100%;margin-bottom:6px'>
<textarea name=text placeholder='Paste text with addresses here'></textarea><br><button class=btn>Start watching</button></form>
<p><small class=mut>Public feeds: add URLs of address lists to <span class=m>"incident_feeds"</span> in config.json &mdash; they're pulled every 30 minutes.</small></p>
<h2>Watching ({len(d['addresses'])})</h2><table><tr><th>Chain</th><th>Address</th><th>Incident</th><th>Added</th></tr>{rows}</table>""")


def incident_post(form):
    from responder import incident
    new = incident.add(form.get("text", ""), form.get("label", "").strip())
    if not new:
        return incident_page("No new valid addresses found in that text.")
    by = {}
    for c, _ in new:
        by[c] = by.get(c, 0) + 1
    return incident_page("Now watching " + ", ".join(f"{n} {c}" for c, n in by.items()) + " address(es).")


# --------------------------------------------------------------- radar ------

def radar_page():
    from responder import radar, risk
    d = radar.load()
    rows = "".join(f"<tr><td class=m>{e(dom)}</td><td>{e(v.get('cert_not_before'))}</td><td>{e(', '.join(v.get('brands', [])))} + "
                   f"{e(', '.join(v.get('lures', [])))}</td></tr>"
                   for dom, v in sorted(d["domains"].items(), key=lambda kv: kv[1].get("cert_not_before", ""), reverse=True)[:150])
    links = " ".join(f"<a class='btn alt' href='{e(u)}' target=_blank>{e(l)}</a>" for l, u in radar.REPORT_LINKS)
    rk = _j(risk.OUT) or {}
    rrows = "".join(f"<tr><td>{e(v['chain'])}</td><td class=m>{e(a)}</td><td>{'<br>'.join(e(s) for s in v['signals'])}</td></tr>"
                    for a, v in sorted(rk.get("wallets", {}).items(), key=lambda kv: -kv[1]["score"])[:60])
    return shell("Scam radar", f"""<h1>&#128225; Scam radar</h1>
<p class=mut>Every HTTPS site gets a certificate, and every certificate is published in public Certificate Transparency logs &mdash; usually
<i>before</i> the site is promoted. After a big hack, fake "refund / compensation / claim" sites appear within hours. The radar watches
{d.get('combos', '?')} brand + lure combinations (rotating) and lists new lookalikes. Last run: {e(d.get('last_run', 'not yet'))}.</p>
<p>{links}</p>
<table><tr><th>Domain</th><th>Certificate issued</th><th>Matched</th></tr>{rows or '<tr><td colspan=3 class=mut>Nothing yet.</td></tr>'}</table>
<h2>Early-warning signals on network wallets</h2>
<p class=mut>Fresh throwaway wallets, victim-collector wallets, laundering splitters, drained wallets, exchange-funded wallets (a KYC lead),
EIP-7702-delegated or mixer-funded EVM wallets. Last scan: {e(rk.get('scanned', 'not yet'))}.</p>
<table><tr><th>Chain</th><th>Wallet</th><th>Signals</th></tr>{rrows or '<tr><td colspan=3 class=mut>Nothing yet.</td></tr>'}</table>""")


# --------------------------------------------------------------- check ------

def check_page(text="", result=None):
    res = ""
    if result:
        color = {"KNOWN SCAM NETWORK": "var(--warn)", "HIGH RISK": "var(--warn)", "CAUTION": "#d97706"}.get(result["verdict"], "var(--ok)")
        res = (f"<div class=card><div class=verdict style='color:{color}'>{e(result['verdict'])}</div>"
               + "".join(f"<p class=warn><b>&#9888; {e(k)}</b></p>" for k in result["known"])
               + ("<ul>" + "".join(f"<li>{e(f)}</li>" for f in result["flags"]) + "</ul>" if result["flags"] else "")
               + f"<p>{e(result['advice'])}</p></div>")
    return shell("Claim checker", f"""<h1>&#128270; Claim checker</h1>
<p class=mut>Got a "refund", "compensation", "giveaway" or "we can recover your funds" message? Paste it (or a link / address).
It checks for the patterns these scams use and whether anything in it is already known to belong to the network you're tracking.
It can't certify anything as safe.</p>
<form method=post action='/check'><textarea name=text>{e(text)}</textarea><br><button class=btn>Check it</button></form>{res}""")


def check_post(form):
    from responder import claimcheck
    t = form.get("text", "")
    return check_page(t, claimcheck.check(t))


# ------------------------------------------------------------- routing ------

def handle_status_post(form):
    st = tracker.load()
    tracker.set_status(st, form.get("key", ""), form.get("state", "to do"), form.get("case_no", "").strip(),
                       form.get("note", "").strip(), form.get("when", "").strip())
    tracker.save(st)


def kit_file(rel):
    """Safe read of a file under freeze_kits/. Returns (bytes, ctype) or None."""
    rel = urllib.parse.unquote(rel).replace("\\", "/").lstrip("/")
    base = os.path.realpath(KITS)
    p = os.path.realpath(os.path.join(KITS, rel))
    if not p.startswith(base + os.sep) or not os.path.isfile(p):
        return None
    ext = os.path.splitext(p)[1].lower()
    ctype = {".html": "text/html; charset=utf-8", ".csv": "text/csv; charset=utf-8", ".png": "image/png",
             ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".pdf": "application/pdf"}.get(ext, "text/plain; charset=utf-8")
    with open(p, "rb") as f:
        return f.read(), ctype
