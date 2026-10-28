"""Turn trace + infrastructure findings into a case file and ready-to-send
report drafts, routed to the right desk and jurisdiction.

Nothing here sends anything. Every draft is a text file the victim reviews
and sends under their own name.
"""
import html
import json
import os
from datetime import datetime

# Reporting desks for the victim's side. Edit or extend freely.
VICTIM_JURISDICTION = {
    "US": [
        ("FBI Internet Crime Complaint Center (IC3)", "https://www.ic3.gov"),
        ("FTC fraud report", "https://reportfraud.ftc.gov"),
        ("Your state Attorney General's consumer protection office", "search: '<your state> attorney general consumer complaint'"),
    ],
}

# Where the scam infrastructure sits decides who can take it down.
INFRA_NOTES = {
    "default": "Report to the hosting provider's and registrar's abuse contacts below. They can take the site down and "
               "preserve account records. Law enforcement in the provider's country can compel those records.",
    "EU": "For EU-hosted infrastructure, Europol lists each member state's online crime reporting page: "
          "https://www.europol.europa.eu/report-a-crime/report-cybercrime-online",
}
EU = {"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT",
      "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE"}

# Exchange support routes (from xrpl.org "Report a Scam"). Add your own.
EXCHANGE_SUPPORT = {
    "binance": "https://www.binance.com/en/support",
    "coinbase": "https://help.coinbase.com/",
    "uphold": "https://support.uphold.com/hc/en-us/requests/new",
    "bitrue": "https://www.bitrue.com/exchange-web/footer/contactus.html",
    "robinhood": "Robinhood support, through the Help section of the Robinhood app",
}


def _exchange_route(label):
    low = (label or "").lower()
    for k, v in EXCHANGE_SUPPORT.items():
        if k in low:
            return v
    return "Identify the exchange (check the address on xrpscan.com / bithomp.com), then use its support or compliance contact."


def _fmt_contact(c):
    if not c:
        return "not listed"
    parts = [c.get("name"), c.get("email"), c.get("phone")]
    return ", ".join(p for p in parts if p) or "not listed"


def build_case(case, out_dir):
    os.makedirs(os.path.join(out_dir, "drafts"), exist_ok=True)
    with open(os.path.join(out_dir, "case.json"), "w", encoding="utf-8") as f:
        json.dump(case, f, indent=2, default=str)
    drafts = make_drafts(case)
    for name, text in drafts.items():
        with open(os.path.join(out_dir, "drafts", name), "w", encoding="utf-8") as f:
            f.write(text)
    with open(os.path.join(out_dir, "report.html"), "w", encoding="utf-8") as f:
        f.write(render_html(case, drafts))
    return list(drafts)


def _facts(case):
    v, t = case["victim"], case.get("trace") or {}
    s = t.get("summary", {})
    lines = [
        f"Scam wallet (XRP Ledger): {t.get('start')}",
        f"Scam website: {', '.join(case.get('domains') or []) or 'n/a'}",
        f"Victim transaction: {v.get('tx_hash')} ({v.get('amount')}, {v.get('date')})",
        f"Wallet totals as of {case['generated']}: {s.get('victim_payments')} incoming payments from "
        f"{s.get('victim_sources')} source accounts, about {s.get('total_received_xrp')} XRP received, "
        f"{s.get('outgoing_payments')} outgoing payments, current balance {s.get('balance_xrp')} XRP.",
    ]
    act = t.get("activation")
    if act:
        lines.append(f"Wallet activated by {act['from']} ({act['xrp']} XRP, tx {act['hash']}, {act['time']}).")
    for e in t.get("endpoints", []):
        lines.append(f"Funds reached {e['address']} ({e.get('label') or 'unlabeled'}), destination tag "
                     f"{e.get('destination_tag')}: {e['xrp']} XRP, tx {e['hash']}, {e['time']}.")
    for dom in case.get("infrastructure", []):
        for h in dom.get("hosting", []):
            g = h.get("geo") or {}
            if g and not g.get("error"):
                lines.append(f"Server {h['ip']} ({dom['domain']}) is hosted by {g.get('org')} "
                             f"({g.get('asn')}) in {g.get('city')}, {g.get('country')}. "
                             f"This is the hosting datacenter, not an individual's location.")
    san = case.get("sanctions") or {}
    if san.get("sanctioned"):
        lines.append("OFAC SANCTIONS MATCH: " + ", ".join(san["sanctioned"]) + " is on the OFAC SDN list.")
    cl = (case.get("cluster") or {}).get("summary") or {}
    if cl.get("sibling_accounts"):
        lines.append(f"Address clustering: the funder activated {cl['sibling_accounts']} related account(s); "
                     f"{cl.get('shared_cashout_wallets', 0)} share a cash-out destination with the scam wallet.")
    if v.get("reports"):
        lines.append("Already reported to: " + "; ".join(v["reports"]))
    return "\n".join(f"- {l}" for l in lines)


def make_drafts(case):
    v = case["victim"]
    sig = f"\n\n{v.get('name')}\n{v.get('email')}\n{v.get('phone') or ''}".rstrip()
    facts = _facts(case)
    d = {}

    for dom in case.get("infrastructure", []):
        reg = dom.get("registration", {})
        d[f"registrar_abuse_{dom['domain']}.txt"] = (
            f"TO: {_fmt_contact(reg.get('registrar_abuse'))}  (registrar: {reg.get('registrar')})\n"
            f"SUBJECT: Phishing / cryptocurrency fraud domain: {dom['domain']}\n\n"
            f"The domain {dom['domain']} impersonates a real company to steal cryptocurrency. "
            f"Please suspend it and preserve the registrant's account, payment and login records for law enforcement.\n\n"
            f"{facts}\n\nScreenshots available on request.{sig}\n")
        for h in dom.get("hosting", []):
            if h.get("error"):
                continue
            d[f"host_abuse_{h['ip']}.txt"] = (
                f"TO: {_fmt_contact(h.get('abuse'))}  (network: {h.get('network')}, {h.get('country')})\n"
                f"SUBJECT: Cryptocurrency fraud site hosted at {h['ip']} ({dom['domain']})\n\n"
                f"{dom['domain']} resolves to {h['ip']} on your network and is being used for a cryptocurrency "
                f"giveaway fraud. Please take it down and preserve the customer's account and access logs for "
                f"law enforcement.\n{('NOTE: ' + h['cdn_note']) if h.get('cdn_note') else ''}\n\n{facts}{sig}\n")
        page = dom.get("page", {}).get("indicators", {})
        for w in page.get("tawk_widgets", []):
            d["tawkto_abuse.txt"] = (
                f"FORM: https://www.tawk.to/legal/report-abuse/\nSUBJECT: Fraud chat widget ({w}) on {dom['domain']}\n\n"
                f"The tawk.to {w} is embedded on {dom['domain']} as a fake support chat used to defraud victims. "
                f"Please suspend the account and preserve its records for law enforcement.\n\n{facts}{sig}\n")

    for e in (case.get("trace") or {}).get("endpoints", []):
        d[f"exchange_{e['address']}.txt"] = (
            f"WHERE: {_exchange_route(e.get('label'))}\n"
            f"SUBJECT: URGENT: stolen XRP deposited to your platform (tag {e.get('destination_tag')})\n\n"
            f"XRP stolen in a fraud was deposited to your address {e['address']} with destination tag "
            f"{e.get('destination_tag')} ({e['xrp']} XRP, tx {e['hash']}, {e['time']}). Please freeze the receiving "
            f"customer's account and preserve KYC records for law enforcement.\n\n{facts}{sig}\n")

    act = (case.get("trace") or {}).get("activation")
    if act and act.get("from") in (case.get("labels") or {}):
        d["exchange_activation_lead.txt"] = (
            f"WHERE: {_exchange_route(case['labels'][act['from']])}\n"
            f"SUBJECT: Scam wallet funded from your platform: withdrawal tx {act['hash']}\n\n"
            f"The scam wallet {act['to']} was activated by a withdrawal from your wallet {act['from']} "
            f"({act['xrp']} XRP, {act['time']}, tx {act['hash']}). The customer who made that withdrawal may be "
            f"connected to the fraud, or may be its first victim. Please review and preserve that customer's records "
            f"for law enforcement.\n\n{facts}{sig}\n")

    ic3_id = v.get("ic3_id")
    d["ic3_update.txt"] = (
        "WHERE: https://www.ic3.gov  (new complaint, answer YES to 'update to a previously filed complaint')\n\n"
        f"{'Update to complaint ' + ic3_id + '. ' if ic3_id else ''}Additional evidence:\n{facts}\n")

    country = v.get("country", "US")
    routes = VICTIM_JURISDICTION.get(country, [])
    infra_countries = sorted({h.get("country") for dom in case.get("infrastructure", []) for h in dom.get("hosting", []) if h.get("country")})
    notes = [INFRA_NOTES["default"]] + ([INFRA_NOTES["EU"]] if any(c in EU for c in infra_countries) else [])
    d["where_to_report.txt"] = (
        f"YOUR JURISDICTION ({country}):\n" + "\n".join(f"- {n}: {u}" for n, u in routes) +
        f"\n\nSCAM INFRASTRUCTURE COUNTRIES: {', '.join(infra_countries) or 'unknown'}\n" + "\n".join(f"- {n}" for n in notes) +
        "\n\nCOMMUNITY WARNINGS:\n- Chainabuse (feeds XRPScan flags): https://chainabuse.com/report\n"
        "- Publish to the XRPL registry: python -m scam_investigator registry publish ...\n")
    return d


def render_html(case, drafts):
    e = html.escape
    t = case.get("trace") or {}
    s = t.get("summary", {})
    rows = "".join(
        f"<tr><td>{e(p['time'])}</td><td class=m>{e(p['from'] or '')}</td><td>{p['xrp']}</td>"
        f"<td>{e(str(p['destination_tag'] or ''))}</td><td class=m><a href='https://livenet.xrpl.org/transactions/{p['hash']}'>{p['hash'][:12]}…</a></td></tr>"
        for p in t.get("incoming", []))
    flows = "".join(
        f"<tr><td>{x['depth']}</td><td class=m>{e(x['from'])}</td><td class=m>{e(x['to'] or '')}</td><td>{x['xrp']}</td>"
        f"<td>{e(str(x['destination_tag'] or ''))}</td><td>{e((t['nodes'].get(x['to']) or {}).get('role',''))}</td></tr>"
        for x in t.get("edges", [])) or "<tr><td colspan=6>No outgoing payments yet — funds have not moved.</td></tr>"
    infra = ""
    for dom in case.get("infrastructure", []):
        reg = dom.get("registration", {})
        def _host_li(h):
            g = h.get("geo") or {}
            geo = f" · {e(str(g.get('city')))}, {e(str(g.get('country')))} ({e(str(g.get('org')))}, {e(str(g.get('asn')))})" if g and not g.get("error") else ""
            return (f"<li>{e(h.get('ip',''))} · {e(str(h.get('network')))} · {e(str(h.get('country')))}{geo} · abuse: {e(_fmt_contact(h.get('abuse')))}"
                    f"{'<br><small>' + e(h['cdn_note']) + '</small>' if h.get('cdn_note') else ''}</li>")
        hosts = "".join(_host_li(h) for h in dom.get("hosting", []))
        ind = dom.get("page", {}).get("indicators", {})
        indl = "".join(f"<li><b>{e(k)}</b>: {e(', '.join(v))}</li>" for k, v in ind.items()) or "<li>Page not reachable or nothing found.</li>"
        infra += (f"<h3>{e(dom['domain'])}</h3><ul><li>Registrar: {e(str(reg.get('registrar')))} · registered {e(str(reg.get('registered')))}</li>"
                  f"<li>Registrar abuse: {e(_fmt_contact(reg.get('registrar_abuse')))}</li><li>Nameservers: {e(', '.join(reg.get('nameservers') or []))}</li></ul>"
                  f"<h4>Hosting</h4><ul>{hosts or '<li>No IP found (site may be down).</li>'}</ul><h4>Found on the page</h4><ul>{indl}</ul>")
    dl = "".join(f"<details><summary>{e(n)}</summary><pre>{e(txt)}</pre></details>" for n, txt in drafts.items())
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Scam Case File</title><style>
:root{{--bg:#fff;--fg:#16181d;--mut:#5b6170;--line:#e3e5ea;--acc:#0b63ce}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111318;--fg:#e8eaf0;--mut:#9aa1b2;--line:#2a2e38;--acc:#5aa2ff}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:980px;margin:0 auto;padding:16px}}
h1{{font-size:24px}} .k{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}}
.k div{{border:1px solid var(--line);border-radius:10px;padding:10px}} .k b{{display:block;font-size:20px}}
table{{width:100%;border-collapse:collapse;font-size:13px;display:block;overflow-x:auto}} td,th{{border-bottom:1px solid var(--line);padding:6px;text-align:left}}
.m{{font-family:ui-monospace,monospace;font-size:12px}} a{{color:var(--acc)}} pre{{white-space:pre-wrap;background:rgba(127,127,127,.08);padding:10px;border-radius:8px}}
small,.mut{{color:var(--mut)}} details{{border:1px solid var(--line);border-radius:8px;padding:6px 10px;margin:6px 0}}</style></head><body>
<h1>Scam Case File</h1><p class=mut>Generated {e(case['generated'])} · victim: {e(case['victim'].get('name') or '')}</p>
<div class=k><div>Balance<b>{s.get('balance_xrp')} XRP</b></div><div>Received<b>{s.get('total_received_xrp')} XRP</b></div>
<div>Victim payments<b>{s.get('victim_payments')}</b></div><div>Moved out<b>{s.get('outgoing_payments')}</b></div><div>Exchange hits<b>{s.get('exchange_endpoints')}</b></div></div>
<h2>Scam wallet</h2><p class=m>{e(str(t.get('start')))}</p>
<p>Activated by <span class=m>{e(str((t.get('activation') or {}).get('from')))}</span> {e(str((case.get('labels') or {}).get((t.get('activation') or {}).get('from'), '')))}</p>
<h2>Money in (victims)</h2><table><tr><th>Time</th><th>From</th><th>XRP</th><th>Tag</th><th>Tx</th></tr>{rows}</table>
<h2>Money out (trace)</h2><table><tr><th>Hop</th><th>From</th><th>To</th><th>XRP</th><th>Tag</th><th>Role</th></tr>{flows}</table>
<h2>Scam infrastructure</h2>{infra or '<p>No domains given.</p>'}
{_sanctions_cluster_html(case, e)}
<h2>Report drafts</h2><p class=mut>Review, then send each one yourself. Nothing has been sent.</p>{dl}
<p class=mut><small>Website IPs identify the hosting company, not the scammer's location. Identifying the person requires the provider's records, which law enforcement can obtain.</small></p>
</body></html>"""


def _sanctions_cluster_html(case, e):
    out = ""
    san = case.get("sanctions") or {}
    if san.get("checked"):
        if san.get("sanctioned"):
            out += "<h2>OFAC sanctions</h2><p style='color:#c0392b'><b>MATCH</b> — on the OFAC SDN list: " \
                   + e(", ".join(san["sanctioned"])) + "</p>"
        elif san.get("list_unavailable"):
            out += "<h2>OFAC sanctions</h2><p class=mut>List could not be fetched; screening skipped.</p>"
        else:
            out += f"<h2>OFAC sanctions</h2><p class=mut>Checked {san['checked']} address(es); none on the OFAC SDN list.</p>"
    cl = case.get("cluster") or {}
    if cl:
        s = cl.get("summary", {})
        sib = "".join(f"<li class=m>{e(x['account'])} · {e(str(x.get('time')))} · {x.get('xrp')} XRP</li>"
                      for x in cl.get("common_funder", [])[:30]) or "<li>None found.</li>"
        shared = "".join(f"<li class=m>{e(x['account'])} shares a cash-out destination</li>" for x in cl.get("shared_cashout", [])) or "<li>None found.</li>"
        out += (f"<h2>Address clustering (leads, not proof)</h2><p class=mut>Funder: <span class=m>{e(str(s.get('funder')))}</span></p>"
                f"<h4>Accounts activated by the same funder</h4><ul>{sib}</ul>"
                f"<h4>Wallets sharing a cash-out destination</h4><ul>{shared}</ul>")
    return out


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M %Z").strip() or datetime.now().isoformat()
