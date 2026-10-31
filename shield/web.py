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
            rows += (f"<tr><td><b style='color:{col}'>{lab}</b><br><small class=mut>{e(a['why'])}</small></td>"
                     f"<td>{e(chain)}</td><td>{e(a['symbol'])}<br><small class=mut>{e(a['kind'])}</small></td><td>{e(amt)}</td>"
                     f"<td class=m>{e(a['spender'])}</td><td><a class=btn href='{e(a['revoke'])}' target=_blank>Revoke</a></td></tr>")
    return rows


def shield_page(q=None, mode=None, result=None):
    body = ["<h1>&#128737;&#65039; Wallet shield</h1>",
            "<p class=mut>Two tools that work around your wallet. <b>Check my wallet</b> lists every app you've allowed to move your "
            "tokens, so you can revoke the ones you don't use. <b>I signed something</b> is for after a bad signature: it finds what "
            "was taken, who took it, and what to do in the next ten minutes. Read-only: it never asks for a seed phrase or a signature.</p>",
            f"""<div class=card><form method=get action='/shield'>
<input name=wallet value='{e(q or "")}' placeholder='Your wallet address (0x...)' style='width:60%'>
<button class=btn name=mode value=check>Check my wallet</button>
<button class='btn red' name=mode value=drain>I signed something</button></form>
<small class=mut>Ethereum, Base, Optimism, Arbitrum and Polygon work with no setup; BNB Chain and Avalanche need the free Etherscan key.</small></div>"""]
    if result and mode == "check":
        s = result.get("summary", {})
        body.append(f"<h2>Open approvals &mdash; {s.get('danger', 0)} revoke now · {s.get('high', 0)} high risk · "
                    f"{s.get('review', 0)} to review · {s.get('ok', 0)} ok</h2>")
        rows = _approval_rows(result)
        body.append(f"<table><tr><th>Risk</th><th>Chain</th><th>Token</th><th>Allowed</th><th>Spender</th><th></th></tr>{rows}</table>"
                    if rows else "<p class=ok>No open approvals found.</p>")
        if result.get("skipped"):
            body.append(f"<p class=mut><small>Not checked (needs Etherscan key): {e(', '.join(result['skipped']))}</small></p>")
    if result and mode == "drain":
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
