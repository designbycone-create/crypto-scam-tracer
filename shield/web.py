"""DRAFT Desk pages for shield: /shield (check my wallet / I signed something),
/sitewatch (sites I use), /compromised (same-day incident domains).

Uses the Desk's page shell so it looks native once plugged in.
"""
import html
from datetime import datetime, timezone

e = lambda s: html.escape(str(s if s is not None else ""), quote=True)
RISK = {"danger": ("#ff4d6d", "REVOKE NOW"), "high": ("#ffb020", "HIGH RISK"), "review": ("#7cc4ff", "REVIEW"),
        "ok": ("#2ee6a8", "OK")}
LEVEL = {"alert": ("#ff4d6d", "ALERT - don't connect your wallet"), "watch": ("#ffb020", "watch"),
         "notice": ("#7cc4ff", "changed (likely a normal update)"), "ok": ("#2ee6a8", "no changes"),
         "new": ("#9aa1b2", "baseline pending")}


def _shell(title, body):
    try:
        from freezekit.web import shell
        return shell(title, body)
    except Exception:
        return f"<!doctype html><meta charset=utf-8><title>{e(title)}</title><body style='background:#0f1115;color:#e8eaf0;font:15px system-ui;max-width:1000px;margin:auto;padding:16px'>{body}"


def _approval_rows(res):
    rows = ""
    for chain, items in (res.get("chains") or {}).items():
        for a in items:
            col, lab = RISK[a["risk"]]
            amt = "Unlimited" if a["unlimited"] else f"{a['amount']:,.4f}"
            if "usd_at_risk" in a:
                amt += ("<br><b>${:,.2f} at risk now</b>".format(a["usd_at_risk"]) if a["usd_at_risk"] is not None
                        else "<br><small class=mut>value unknown</small>")
            rows += (f"<tr><td><b style='color:{col}'>{lab}</b><br><small class=mut>{e(a['why'])}</small></td>"
                     f"<td>{e(chain)}</td><td>{e(a['symbol'])}<br><small class=mut>{e(a['kind'])}</small></td><td>{amt}</td>"
                     f"<td class=m>{e(a['spender'])}</td><td><a class=btn href='{e(a['revoke'])}' target=_blank>Revoke</a>"
                     + (f"<br><small class=mut>{e(a['revoke_hint'])}</small>" if a.get("revoke_hint") else "") + "</td></tr>")
    return rows


def shield_page(q=None, mode=None, result=None):
    body = ["<h1>&#128737;&#65039; Wallet shield</h1>",
            "<p class=mut>Two tools that work around your wallet. <b>Check my wallet</b> lists every app you've allowed to move your "
            "tokens, so you can revoke the ones you don't use. <b>I signed something</b> is for after a bad signature: it finds what "
            "was taken, who took it, and what to do in the next ten minutes. Read-only: it never asks for a seed phrase or a signature.</p>",
            f"""<div class=card><form method=get action='/shield'>
<input name=wallet value='{e(q or "")}' placeholder='Your wallet address (0x… / T… / Solana / r… / bc1…)' style='width:60%'>
<button class=btn name=mode value=check>Check my wallet</button>
<button class='btn red' name=mode value=drain>I signed something</button></form>
<small class=mut>Works on Ethereum, BNB Chain, Polygon, Arbitrum, Base, Optimism, Avalanche, Tron, Solana and the XRP Ledger
(Bitcoin has no approvals). No keys needed. Without a free key, BNB Chain gets balance and contract checks only (add a free endpoint in setup).</small></div>"""]
    def _account(res):
        out = ""
        for lvl, txt in (res or {}).get("takeover") or []:
            col = RISK.get(lvl, RISK["high"])[0]
            out += f"<div class=card style='border:2px solid {col}'><b style='color:{col}'>ACCOUNT {e(lvl.upper())}</b> &mdash; {e(txt)}</div>"
        for n in (res or {}).get("notes") or []:
            out += f"<p class=mut><small>{e(n)}</small></p>"
        if (res or {}).get("error"):
            out += f"<p class=warn>{e(res['error'])}</p>"
        return out
    if result and mode == "check":
        body.append(_account(result))
        s = result.get("summary", {})
        body.append(f"<h2>Open approvals &mdash; {s.get('danger', 0)} revoke now · {s.get('high', 0)} high risk · "
                    f"{s.get('review', 0)} to review · {s.get('ok', 0)} ok</h2>"
                    + (f"<p><b>About ${result['usd_at_risk']:,.2f}</b> of your tokens can be moved right now by the "
                       "approvals marked revoke / high / review. Revoke the top rows first.</p>" if result.get("usd_at_risk") else ""))
        rows = _approval_rows(result)
        body.append(f"<table><tr><th>Risk</th><th>Chain</th><th>Token</th><th>Allowed</th><th>Spender</th><th></th></tr>{rows}</table>"
                    if rows else "<p class=ok>No open approvals found.</p>")

    if result and mode == "drain":
        body.append(_account(result.get("open_approvals")))
        for n in result.get("notes") or []:
            body.append(f"<p class=mut><small>{e(n)}</small></p>")
        drains = result.get("drains", [])
        if not drains:
            body.append("<div class=card><b>No drain transactions found</b> &mdash; nothing was pulled out by someone else's transaction "
                        "on the chains checked. Still review your open approvals below; a signed approval can be used later.</div>")
        else:
            body.append("<div class='card you'><h3 style='color:#ff4d6d'>Do these now, in order</h3><ol>"
                        + "".join(f"<li>{e(x)}</li>" for x in result["next_steps"]) + "</ol></div>")
            rows = ""
            for d in drains:
                when = datetime.fromtimestamp(d["time"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if d.get("time") else ""
                toks = "<br>".join(f"{t['amount']:,.4f} {e(t['symbol'])}" for t in d["tokens"])
                rows += (f"<tr><td>{e(when)}<br><small>{e(d['chain'])}</small></td><td>{toks}</td><td class=m>{e(d['drainer_contract'])}</td>"
                         f"<td class=m>{'<br>'.join(e(r) for r in d['receivers'])}</td><td class=m><small>{e(d['hash'][:18])}&hellip;</small></td></tr>")
            body.append(f"<h2>What was taken</h2><table><tr><th>When</th><th>Tokens</th><th>Drainer contract</th><th>Funds went to</th><th>Tx</th></tr>{rows}</table>")
            if result.get("likely_fee_wallets"):
                body.append("<p><b>Likely drainer-kit fee wallet(s):</b> <span class=m>"
                            + ", ".join(e(f"{c}:{a}") for c, a in result["likely_fee_wallets"]) + "</span><br><small class=mut>"
                            "The smaller cut in a split drain usually goes to the kit operator. The same fee wallet across many "
                            "victims links many sites to one operator &mdash; give it to SEAL 911 and your officer.</small></p>")
        appr = result.get("open_approvals") or {}
        rows = _approval_rows(appr)
        if rows:
            body.append(f"<h2>Open approvals on this wallet</h2><table><tr><th>Risk</th><th>Chain</th><th>Token</th><th>Allowed</th><th>Spender</th><th></th></tr>{rows}</table>")
    return _shell("Wallet shield", "".join(body))


def sitewatch_page(msg=""):
    from . import sitewatch
    d = sitewatch.load()
    rows = ""
    for dom, s in sorted(d["sites"].items(), key=lambda kv: ["alert", "watch", "notice", "new", "ok"].index(kv[1].get("level", "ok"))):
        col, lab = LEVEL.get(s.get("level"), LEVEL["ok"])
        base = (s.get("baseline") or {})
        rows += (f"<tr><td><b>{e(dom)}</b></td><td><b style='color:{col}'>{e(lab)}</b><br><small>{'<br>'.join(e(x) for x in s.get('signals') or [])}</small></td>"
                 f"<td><small>{e(', '.join((base.get('ns') or [])[:2]))}<br>{e(((base.get('rdap') or {}).get('registrar')) or '')}</small></td>"
                 f"<td><form method=post action='/sitewatch' style='display:inline'><input type=hidden name=domain value='{e(dom)}'>"
                 f"<button class='btn alt' name=op value=accept title='The team confirmed the change is legitimate'>Accept change</button>"
                 f"<button class='btn alt' name=op value=remove>Remove</button></form></td></tr>")
    return _shell("Sites I use", f"""<h1>&#128272; Sites I use</h1>
<p class=mut>A hijacked dApp keeps its real address, so lookalike checks can't catch it. This watches the plumbing of the sites you
connect your wallet to &mdash; nameservers, registrar and transfer lock, hosting, certificates and scripts &mdash; and warns you when they
change underneath you. A warning means <b>don't connect your wallet until the team confirms</b>. No warning is not a guarantee.</p>
{f"<div class=pledge>{e(msg)}</div>" if msg else ""}
<div class=card><form method=post action='/sitewatch'><input name=domains placeholder='app.example.fi, another.xyz' style='width:60%'>
<button class=btn name=op value=add>Watch these sites</button> <button class='btn alt' name=op value=defaults>Add popular dApps</button></form></div>
<p class=mut><small>Last check: {e(d.get('checked', 'not yet'))}. Checked every 30 minutes.</small></p>
<table><tr><th>Site</th><th>Status</th><th>Baseline</th><th></th></tr>{rows or '<tr><td colspan=4 class=mut>No sites yet.</td></tr>'}</table>""")


def sitewatch_post(form):
    from . import sitewatch
    op = form.get("op")
    if op == "add":
        added = sitewatch.add([x.strip() for x in form.get("domains", "").replace(" ", ",").split(",") if x.strip()])
        return sitewatch_page(f"Watching {len(added)} new site(s). The first check sets the baseline.")
    if op == "defaults":
        added = sitewatch.add(sitewatch.DEFAULT_WATCH)
        return sitewatch_page(f"Added {len(added)} popular dApps.")
    if op == "accept":
        sitewatch.accept(form.get("domain", ""))
        return sitewatch_page(f"Accepted the change on {form.get('domain')}; it's the new baseline.")
    if op == "remove":
        sitewatch.remove(form.get("domain", ""))
        return sitewatch_page(f"Stopped watching {form.get('domain')}.")
    return sitewatch_page()


def compromised_page(msg=""):
    from . import compromised
    d = compromised.load()
    rows = "".join(f"<tr><td><b>{e(k)}</b></td><td>{e(v.get('status'))}</td><td>{e(v.get('label'))}</td><td><small>{e(v.get('added'))}</small></td></tr>"
                   for k, v in sorted(d["domains"].items(), key=lambda kv: kv[1].get("added", ""), reverse=True))
    return _shell("Compromised sites", f"""<h1>&#9888;&#65039; Compromised sites (same-day)</h1>
<p class=mut>Public scam lists lag by days. When an incident post names hijacked sites or drainer addresses, paste it here and every check
in the Desk flags them immediately.</p>{f"<div class=pledge>{e(msg)}</div>" if msg else ""}
<div class=card><form method=post action='/compromised'><input name=label placeholder='Incident (e.g. Step Drainer front-end hijacks)' style='width:100%;margin-bottom:6px'>
<textarea name=text placeholder='Paste the post or a list of domains / addresses'></textarea><br><button class=btn>Add to list</button></form></div>
<table><tr><th>Domain</th><th>Status</th><th>Incident</th><th>Added</th></tr>{rows or '<tr><td colspan=4 class=mut>None yet.</td></tr>'}</table>""")


def compromised_post(form):
    from . import compromised
    nd, na = compromised.add(form.get("text", ""), form.get("label", "").strip())
    return compromised_page(f"Added {len(nd)} domain(s) and {len(na)} address(es).")


# ------------------------------------------------------------ prescreen ---

VERDICT = {"STOP": ("#ff4d6d", "Don't send."), "CAUTION": ("#ffb020", "Think twice before sending."),
           "NO RED FLAGS FOUND": ("#2ee6a8", "Nothing bad found -- that's not a guarantee.")}
LVL = {"stop": ("#ff4d6d", "&#9940;"), "caution": ("#ffb020", "&#9888;&#65039;"), "info": ("#7cc4ff", "&#8505;&#65039;")}


def prescreen_page(form=None, result=None):
    f = form or {}
    body = ["<h1>&#128270; Check before you send</h1>",
            "<p class=mut>A background check on the wallet you're about to pay: scam and sanctions lists, the networks you track, "
            "how the wallet behaves, who it deals with, and the common mistakes (poisoned lookalike addresses, missing tags, wrong network). "
            "Read-only &mdash; nothing is sent and no signature is asked for.</p>",
            f"""<div class=card><form method=get action='/prescreen'>
<label>Address you're about to send to</label><input name=address class=m value='{e(f.get("address", ""))}' style='width:100%' placeholder='r... / 0x... / T... / bc1...'>
<div style='display:grid;grid-template-columns:1fr 1fr 2fr;gap:8px;margin-top:8px'>
<select name=chain><option value=''>Network: auto</option>{''.join(f"<option{' selected' if f.get('chain') == c else ''}>{c}</option>" for c in ['ethereum','bsc','polygon','arbitrum','base','optimism','avalanche','opbnb'])}</select>
<input name=tag value='{e(f.get("tag", ""))}' placeholder='Destination tag / memo (if any)'>
<input name=me class=m value='{e(f.get("me", ""))}' placeholder='Your own wallet (optional, catches poisoning)'></div>
<button class=btn style='margin-top:10px'>Check this wallet</button></form></div>"""]
    if result and not result.get("ok"):
        body.append(f"<p class=warn>{e(result.get('error'))}</p>")
    elif result:
        col, line = VERDICT[result["verdict"]]
        body.append(f"<div class=card style='border:2px solid {col}'><div style='font-size:26px;font-weight:800;color:{col}'>{e(result['verdict'])}</div>"
                    f"<div>{e(line)}</div><div class='m mut' style='margin-top:6px'>{e(result['address'])} &middot; {e(result['chain'])}"
                    f"{(' &middot; ' + e(result['identity'])) if result.get('identity') else ''}</div></div>")
        rows = ""
        for x in sorted(result["findings"], key=lambda x: ["stop", "caution", "info"].index(x["level"])):
            c, icon = LVL[x["level"]]
            rows += f"<tr><td style='color:{c};white-space:nowrap'>{icon} {e(x['section'])}</td><td>{e(x['text'])}</td></tr>"
        body.append(f"<table>{rows or '<tr><td class=mut>No findings.</td></tr>'}</table>")
        body.append(f"<p class=mut><small>{e(result['note'])} Checked {e(result['checked'])} &middot; "
                    f"{result['stats']['movements']} movements reviewed. Also see "
                    f"<a href='https://www.chainabuse.com/address/{e(result['address'])}' target=_blank>Chainabuse reports</a>.</small></p>")
    return _shell("Check before you send", "".join(body))
