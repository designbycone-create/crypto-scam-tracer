"""Build freeze kits from what the watchers found.

    python -m freezekit build        # (re)build every kit now
    python -m freezekit verify       # check the custody log is intact

One kit per exchange (an officer files one request per platform, listing every
deposit account). Kits live in freeze_kits/<exchange>/ and the case-wide files
(SEAL 911 message, Chainabuse list, IC3 update, Officer Packet) in
freeze_kits/_case/. Files are only rewritten when their content changes, and
every write is recorded in the custody log.

Nothing is ever sent. The kit is what YOU (or your officer) submit.
"""
import csv
import html
import io
import json
import os
from collections import defaultdict

from . import channels, custody, tracker, xrpl_tokens

ROOT = "freeze_kits"
EXPLORER = "https://livenet.xrpl.org/transactions/"
ACCT = "https://livenet.xrpl.org/accounts/"


# ------------------------------------------------------------- inputs -------

def _j(path):
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return None


def load_case():
    case = _j("victim.json") or {}
    try:
        import scamconfig
        case.setdefault("scam_wallet", scamconfig.scam_wallet())
    except Exception:
        pass
    return case


def _path_to(edges, root, addr, limit=12):
    """Shortest chain of wallets root -> ... -> addr using recorded flows."""
    if not root or not edges:
        return []
    preds = defaultdict(list)
    for e in edges:
        if e.get("from") and e.get("to"):
            preds[e["to"]].append(e)
    frontier, seen = [(addr, [])], {addr}
    while frontier:
        nxt = []
        for node, chain in frontier:
            for e in preds.get(node, []):
                c = [e] + chain
                if e["from"] == root:
                    return c
                if e["from"] not in seen and len(c) < limit:
                    seen.add(e["from"])
                    nxt.append((e["from"], c))
        frontier = nxt
    return []


def collect():
    """Gather freeze targets, grouped by exchange.

    Returns {target_id: {"key","entry","deposits":[...],"yours":bool}} and the issuer list.
    """
    freeze = _j("network_map.json") or {}      # time-forward: YOUR funds
    evid = _j("scam_network.json") or {}       # full network evidence
    root = freeze.get("root") or evid.get("root") or load_case().get("scam_wallet", "") or \
        next((c["address"] for c in (_j("config.json") or {}).get("cases") or []), "")
    targets = {}

    try:
        from scam_investigator import attribution as _attr
        attrib = _attr.load()
    except Exception:
        attrib = {}

    def add(ep, yours, edges):
        att = None
        if not ep.get("label"):
            att = attrib.get(ep.get("address"))
            if att and att.get("confidence") in ("verified", "likely") and att.get("name"):
                ep = {**ep, "label": att["name"]}
        key, ent = channels.exchange_for(ep.get("label"))
        if att and att.get("name"):
            ent = {**ent, "attribution": att}
            if key is None and att.get("confidence") in ("verified", "likely"):
                ent["name"] = f"{att['name']} (attributed)"
        brand = (ep.get("label") or "").split("(")[0].strip()
        if key is None and brand:
            # labeled by an explorer but not in the verified directory yet
            import re as _re
            ent = {**ent, "name": brand,
                   "note": f"Identified as {brand} by public explorer labels; no verified freeze channel in the "
                           "directory yet. Officer route: find its official law-enforcement / compliance page. "
                           "SEAL 911 can also reach it."}
            tid = "svc-" + _re.sub(r"[^a-z0-9]+", "-", brand.lower()).strip("-")
        else:
            tid = key or f"unidentified-{ep['address'][:10]}"
        t = targets.setdefault(tid, {"id": tid, "key": key, "entry": ent, "deposits": [], "yours": False,
                                     "addresses": set()})
        if att and att.get("name"):
            t.setdefault("attributions", {})[ep.get("address")] = att
        t["yours"] = t["yours"] or yours
        k = (ep.get("hash"), ep.get("address"))
        if any((d.get("hash"), d.get("address")) == k for d in t["deposits"]):
            if yours:
                for d in t["deposits"]:
                    if (d.get("hash"), d.get("address")) == k:
                        d["yours"] = True
            return
        chain_ = ep.get("chain") or "xrpl"
        d = {"address": ep.get("address"), "tag": ep.get("destination_tag"),
             "xrp": (ep.get("xrp") or 0) if chain_ == "xrpl" else 0,
             "chain": chain_, "asset": ep.get("asset") or "XRP",
             "amount": ep.get("amount") if ep.get("amount") is not None else (ep.get("xrp") or 0),
             "tx_url": ep.get("tx_url") or f"{EXPLORER}{ep.get('hash')}",
             "hash": ep.get("hash"), "time": ep.get("time"), "label": ep.get("label"),
             "post_theft": ep.get("post_theft", True), "yours": yours,
             "path": [{"from": e["from"], "to": e["to"], "hash": e.get("hash"), "xrp": e.get("xrp"),
                       "time": e.get("time")} for e in _path_to(edges, root, ep.get("address"))]}
        t["deposits"].append(d)
        t["addresses"].add(ep.get("address"))

    # YOUR cash-outs: the live watcher's permanent record + its event log (older installs)
    mine = {}
    try:
        with open("cashouts.jsonl", encoding="utf-8-sig") as f:
            for line in f:
                try:
                    ep = json.loads(line)
                    mine[ep["hash"]] = ep
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    try:
        import re
        with open("netwatch_events.log", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.search(r"(?:CASH-OUT|BRIDGE/SWAP): .*? tag (\d+)\s+.*?tx ([0-9A-F]{64})", line)
                if m:
                    mine.setdefault(m.group(2), {"hash": m.group(2), "destination_tag": int(m.group(1))})
    except FileNotFoundError:
        pass
    all_eps = {ep.get("hash"): ep for ep in evid.get("endpoints", []) + freeze.get("endpoints", [])}
    for h, ep in mine.items():
        if not ep.get("address") and h in all_eps:
            ep = {**all_eps[h], **{k: v for k, v in ep.items() if v is not None}}
        if ep.get("address"):
            add(ep, True, freeze.get("edges", []) + evid.get("edges", []))
    for ep in freeze.get("endpoints", []):
        if ep.get("address"):
            add(ep, ep.get("hash") in mine or ep.get("post_theft", True), freeze.get("edges", []))
    for ep in evid.get("endpoints", []):
        if ep.get("address"):
            add(ep, ep.get("hash") in mine, evid.get("edges", []))
    _add_multichain(add)
    for t in targets.values():
        t["addresses"] = sorted(a for a in t["addresses"] if a)
        t["deposits"].sort(key=lambda d: (not d["yours"], str(d.get("time"))))

    toks = xrpl_tokens.load() or {}
    # known, accountable issuers first; then other freezable tokens (largest first, capped)
    hold = [h for h in toks.get("holdings", []) if h.get("freezable") or h.get("clawback")]
    issuer_targets = [h for h in hold if h.get("issuer_name")] + \
        [h for h in hold if not h.get("issuer_name")][:15]
    mc = _j("mc_map.json") or {}
    return root, targets, issuer_targets, mc.get("freeze_ops", [])


# ------------------------------------------------------------ writers -------

def _refs(case):
    r = []
    if case.get("ic3_id"):
        r.append(f"FBI IC3 complaint {case['ic3_id']}")
    r += [x for x in case.get("reports", []) if x]
    return r


def _chain_name(c):
    try:
        from .chainlookup import CHAIN_NAMES
        return CHAIN_NAMES.get(c, c)
    except Exception:
        return c


def amt_str(deps):
    """'1,200 XRP + 3,000 USDT' -- totals per asset."""
    tot = {}
    for d in deps:
        tot[d.get("asset") or "XRP"] = tot.get(d.get("asset") or "XRP", 0) + float(d.get("amount") or 0)
    return " + ".join(f"{v:,.4f}".rstrip("0").rstrip(".") + f" {k}" for k, v in sorted(tot.items(), key=lambda kv: -kv[1])) or "0"


def _deposit_lines(t, only_yours=False):
    out = []
    for d in t["deposits"]:
        if only_yours and not d["yours"]:
            continue
        if d.get("chain", "xrpl") == "xrpl":
            acct = f"  - Deposit address {d['address']}  destination tag {d['tag']}  (XRP Ledger)"
        else:
            acct = (f"  - Deposit address {d['address']}  ({_chain_name(d['chain'])}; "
                    f"this deposit address belongs to one customer account)")
        out.append(f"{acct}\n    {float(d.get('amount') or 0):,.6f} {d.get('asset', 'XRP')}  at {d.get('time')}\n"
                   f"    Tx {d['hash']}\n    {d.get('tx_url') or EXPLORER + str(d['hash'])}"
                   + ("   << traced from the victim's stolen funds" if d["yours"] else ""))
    return "\n".join(out)


def _case_seeds():
    try:
        with open("config.json", encoding="utf-8-sig") as f:
            return [(c["chain"], c["address"]) for c in json.load(f).get("cases") or [] if c.get("chain") != "xrpl"]
    except Exception:
        return []


def _add_multichain(add):
    """Exchange cash-outs found by the multi-chain tracer (BTC, EVM, Tron, Solana).

    The deposit ADDRESS is the customer account on these chains: it is the
    sender of the transfer into the exchange's labeled hot wallet, or the
    exchange-labeled address itself when funds were sent straight to it."""
    mc = _j("mc_map.json") or {}
    nodes, edges = mc.get("nodes", {}), mc.get("edges", [])
    if not edges:
        return
    seeds = _case_seeds()
    reach = set()
    if seeds:
        adj = {}
        for e in edges:
            adj.setdefault((e.get("chain"), e.get("from")), []).append((e.get("chain"), e.get("to")))
        stack = [(c, a) for c, a in seeds]
        # EVM addresses are the same on every EVM chain
        try:
            from multichain.core import CHAINS
            evm = [k for k, v in CHAINS.items() if v.evm_chainid is not None]
            stack += [(k, a) for c, a in seeds if c in evm for k in evm]
        except Exception:
            pass
        while stack:
            x = stack.pop()
            if x in reach:
                continue
            reach.add(x)
            stack += adj.get(x, [])
    try:
        from multichain.core import CHAINS
    except Exception:
        CHAINS = {}
    for ep in mc.get("endpoints", []):
        if ep.get("type") not in ("exchange", "bridge"):
            continue
        ch, hot = ep.get("chain"), ep.get("address")
        info = CHAINS.get(ch)
        for e in edges:
            if e.get("chain") != ch or e.get("to") != hot:
                continue
            yours = (ch, hot) in reach if seeds else False
            add({"address": e.get("from") if nodes.get(f"{ch}:{e.get('from')}", {}).get("type") == "wallet" else hot,
                 "label": ep.get("label"), "destination_tag": None, "hash": e.get("txid"), "time": e.get("time"),
                 "chain": ch, "asset": e.get("asset"), "amount": e.get("amount"),
                 "tx_url": info.explorer_tx(e.get("txid")) if info else None, "post_theft": True},
                yours, [])


def victim_notice(t, case, root):
    ent = t["entry"]
    name = ent.get("name", "your platform")
    refs = _refs(case)
    yours = [d for d in t["deposits"] if d["yours"]]
    lines = [
        f"SUBJECT: Stolen funds deposited to {name} - freeze and preservation request ("
        + (f"XRP, tag {', '.join(str(d['tag']) for d in (yours or t['deposits'])[:5])}"
           if (yours or t['deposits'])[0].get("chain", "xrpl") == "xrpl" else
           f"{_chain_name((yours or t['deposits'])[0]['chain'])}, deposit address {(yours or t['deposits'])[0]['address'][:14]}...")
        + ")", "",
        f"To the {name} compliance / security team,", "",
        f"I am the victim of a cryptocurrency fraud ({case.get('scam_type', 'a fake giveaway')}). "
        f"My funds were sent to the scam wallet {root} and traced on the public blockchain to "
        f"account(s) on your platform. I ask that you freeze the receiving account(s) and preserve "
        f"their records for law enforcement.", "",
        "Victim transaction:",
        f"  {case.get('tx_hash', '[your transaction hash]')}",
        f"  {EXPLORER}{case.get('tx_hash', '')}", "",
        "Deposits to your platform:", _deposit_lines(t, only_yours=bool(yours)), "",
    ]
    if yours:
        d = yours[0]
        if d["path"]:
            lines += ["Trace (each step is a public, verifiable transaction):"]
            lines += [f"  {p['time']}  {p['from']} -> {p['to']}  {p.get('xrp') or 0:,.2f} XRP  {p.get('hash')}"
                      for p in d["path"]]
            lines += [""]
    if refs:
        lines += ["Case references: " + "; ".join(refs), ""]
    lines += ["A law-enforcement request will follow through your official law-enforcement channel. "
              "Please treat this as notice to preserve.", "",
              case.get("name") or "[Your name]", case.get("email") or "[Your email]",
              case.get("phone") or ""]
    return "\n".join(lines).rstrip() + "\n"


def officer_request(t, case, root):
    ent = t["entry"]
    name = ent.get("name", "[Exchange]")
    le = [c for c in ent.get("channels", []) if c.get("who") in ("law_enforcement", "both")]
    route = "\n".join(f"  {c.get('label', c['type'])}: {c.get('url') or c.get('email')}"
                      + ("" if c.get("verified") else "  (unverified - confirm on the official site)")
                      for c in le) or "  Use this platform's official law-enforcement request page (not verified here)."
    return f"""[AGENCY LETTERHEAD]

LAW ENFORCEMENT REQUEST - PRESERVATION AND ACCOUNT RESTRICTION
To: {name} - Law Enforcement Response Team
Submit via:
{route}

Agency: ______________________   Case / report no.: ______________
Officer: _____________________   Badge/ID: ________   Email: ______________
Phone: ______________________    Date: ______________
Legal authority: [cite the applicable preservation request / subpoena / court order]

1. SUMMARY
On {case.get('theft_time', '[date]')} the complainant, {case.get('name', '[victim name]')}, sent
{_amount_txt(case)} from their own wallet {case.get('victim_wallet', '[victim wallet]')}
to the fraud wallet {root} (tx {case.get('tx_hash', '[hash]')}).
Complainant's FBI IC3 complaint: {case.get('ic3_id', '[IC3 number]')}.
Public blockchain analysis shows funds from this fraud wallet were deposited to the {name}
account(s) below. On the XRP Ledger a DESTINATION TAG identifies the individual customer
account at the exchange; on Bitcoin, Ethereum/EVM, Tron and Solana each DEPOSIT ADDRESS does.

2. ACCOUNTS (deposit address, plus destination tag on the XRP Ledger)
{_deposit_lines(t)}

3. REQUESTS
  a. PRESERVE all records for the account(s) above: KYC identity documents, account
     registration details, login/IP/device logs, linked bank cards / payment methods,
     deposit and withdrawal history (with destination addresses and chains).
  b. RESTRICT / FREEZE withdrawals from the account(s) for [__] days pending legal process.
  c. DISCLOSE (on receipt of appropriate legal process) the account holder identity and the
     destination of any onward withdrawals.

{_attribution_block(t)}4. EVIDENCE
Every transaction above is public and verifiable at the explorer links given. An evidence
package with SHA-256 manifest and full network trace accompanies this request.

_____________________________  (signature)
"""


def _attribution_block(t):
    atts = t.get("attributions") or {}
    if not atts:
        return ""
    out = ["ATTRIBUTION (how this platform was identified - public evidence):"]
    for a, att in atts.items():
        out.append(f"  {a}: {att.get('name') or 'unknown'} [{att.get('confidence')}]")
        out += [f"    - {e}" for e in att.get("evidence", [])]
    return "\n".join(out) + "\n\n"


def _amount_txt(case):
    a = str(case.get("amount") or "[amount]")
    return a if any(ch.isalpha() for ch in a) else f"{a} XRP"


def fund_inflow_csv(t):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["chain", "deposit_address", "destination_tag", "amount", "asset", "tx_hash", "time_utc",
                "traced_from_victim", "explorer"])
    for d in t["deposits"]:
        w.writerow([_chain_name(d.get("chain", "xrpl")), d["address"], d["tag"] if d["tag"] is not None else "",
                    f"{float(d.get('amount') or 0):.8f}".rstrip("0").rstrip("."), d.get("asset", "XRP"), d["hash"],
                    d.get("time"), "yes" if d["yours"] else "network", d.get("tx_url") or f"{EXPLORER}{d['hash']}"])
    return buf.getvalue()


def readme(t, case):
    ent = t["entry"]
    name = ent.get("name", "Unidentified service")
    out = [f"FREEZE KIT - {name}", "=" * 60, ""]
    if ent.get("deadline_note"):
        out += ["DEADLINE: " + ent["deadline_note"], ""]
    if ent.get("us_restricted"):
        out += ["NOTE: this platform restricts US users; its consumer pages may block a US IP.",
                "Do NOT use a VPN (law-enforcement systems reject VPN submissions). Use the",
                "law-enforcement route below through your officer, plus SEAL 911.", ""]
    if t.get("attributions"):
        out += [_attribution_block(t)]
    out += ["DO THESE IN ORDER:",
            "  1. SEAL 911 - paste _case/seal911_message.txt into https://t.me/seal_911_bot",
            "     (they flag addresses to the TRM Beacon Network, which alerts member exchanges).",
            "  2. Victim channel for this platform (if any, below) - submit victim_notice.txt.",
            "  3. Give officer_request.txt + the _case/officer_packet.html to your officer;",
            "     they submit it through the law-enforcement channel below.",
            "  4. Update IC3 (_case/ic3_update.txt) and Chainabuse (_case/chainabuse_update.txt).",
            "  5. Mark each step in the Desk's Submission Center so you can see what's left.", "",
            "CHANNELS:"]
    for c in ent.get("channels", []):
        out.append(f"  [{c.get('who')}] {c.get('label', c['type'])}: {c.get('url') or c.get('email')}"
                   + ("  (verified)" if c.get("verified") else "  (NOT verified - confirm first)"))
    if not ent.get("channels"):
        out.append("  None verified yet. " + ent.get("note", ""))
    elif ent.get("note"):
        out += ["", "  " + ent["note"]]
    if ent.get("needs"):
        out += ["", "THIS PLATFORM ASKS FOR:"] + [f"  - {n}" for n in ent["needs"]]
        out += ["  (Your withdrawal screenshot: add it to this folder as withdrawal_proof.png/jpg.)"]
    return "\n".join(out) + "\n"


def seal911_message(root, targets, case, issuer_targets):
    yours = [t for t in targets.values() if t["yours"]]
    chains = sorted({_chain_name(d.get("chain", "xrpl")) for t in targets.values() for d in t["deposits"]}) or ["XRP Ledger"]
    lines = [f"Fraud victim - funds moving now. Chain(s): {', '.join(chains)}.",
             f"Scam wallet: {root}",
             f"My tx: {case.get('tx_hash', '?')}"]
    if case.get("ic3_id"):
        lines.append(f"IC3: {case['ic3_id']}")
    for t in sorted(targets.values(), key=lambda t: (not t["yours"], -sum(d["xrp"] for d in t["deposits"]))):
        name = t["entry"].get("name", "unidentified")
        tags = sorted({str(d["tag"]) for d in t["deposits"] if d.get("tag") is not None})
        lines.append(f"- {name}: {', '.join(t['addresses'][:3])}" + (f" tags {', '.join(tags[:8])}" if tags else "")
                     + (" (MY funds)" if t["yours"] else ""))
        if len(lines) > 25:
            break
    for h in issuer_targets[:5]:
        lines.append(f"- {h['currency']} {h['balance']:,.2f} held at {h['wallet']} (issuer {h['issuer']}"
                     + (", clawback enabled" if h["clawback"] else "") + ")")
    for op in [o for o in (_j("mc_map.json") or {}).get("freeze_ops", []) if o.get("kind") == "stablecoin_issuer"][:5]:
        lines.append(f"- {op.get('asset')} on {_chain_name(op.get('chain'))} at {op.get('address')} "
                     f"({op.get('amount') or '?'} {op.get('asset')}, issuer {op.get('issuer')} can freeze)")
    lines.append("Requesting Beacon flag / exchange outreach. Full trace + evidence available.")
    return "\n".join(lines) + "\n"


def chainabuse_update(root, evid_nodes, targets):
    lines = ["CHAINABUSE - addresses to add to the existing report (category: giveaway scam)",
             "Paste each into the report's 'addresses' field with its chain.", "",
             f"{root}  - primary scam receiving wallet"]
    for a, n in list(evid_nodes.items())[:200]:
        if a != root and str(n.get("role", "")).startswith("intermediate"):
            lines.append(f"{a}  - laundering/consolidation wallet")
    for t in targets.values():
        for a in t["addresses"]:
            ch = next((_chain_name(d.get("chain", "xrpl")) for d in t["deposits"] if d["address"] == a), "XRP Ledger")
            lines.append(f"{a}  - [{ch}] {t['entry'].get('name', 'unidentified custodial')} deposit address (cash-out)")
    return "\n".join(lines) + "\n"


def ic3_update(root, targets, case):
    lines = [f"IC3 UPDATE for complaint {case.get('ic3_id', '[number]')}", "",
             "New information: stolen funds were traced on the public blockchain to the following "
             "exchange deposit accounts (address + destination tag identifies the customer account):", ""]
    for t in targets.values():
        if t["yours"]:
            lines.append(f"{t['entry'].get('name', 'Unidentified service')}:")
            lines.append(_deposit_lines(t, only_yours=True))
    lines += ["", f"The fraud wallet {root} is part of a larger network; a full network evidence "
              "record (every wallet and exchange it uses) is attached / available."]
    return "\n".join(lines) + "\n"


def issuer_requests(issuer_targets, mc_ops, case):
    if not issuer_targets and not mc_ops:
        return None
    lines = ["ISSUER FREEZE / CLAWBACK REQUESTS (route through law enforcement + SEAL 911)", ""]
    for h in issuer_targets:
        lines += [f"{h['issuer_name'] or 'Token issuer'} {h['issuer']}",
                  f"  Token {h['currency']}  balance {h['balance']:,.6f}  held by {h['wallet']}",
                  f"  {ACCT}{h['wallet']}",
                  f"  Issuer can freeze this trust line: {'yes' if h['freezable'] else 'no'}; "
                  f"clawback enabled: {'yes' if h['clawback'] else 'no'}; "
                  f"already frozen: {'yes' if h['frozen_by_issuer'] else 'no'}", ""]
    for op in mc_ops:
        if op.get("kind") == "stablecoin_issuer":
            lines += [f"{op.get('issuer')} {op.get('asset')} on {op.get('chain')}: {op.get('address')} "
                      f"(tx {op.get('txid')})", ""]
    lines.append("Request: freeze (and where enabled, claw back) the balances above pending legal process. "
                 f"Victim IC3: {case.get('ic3_id', '[number]')}.")
    return "\n".join(lines) + "\n"


def officer_packet_html(root, targets, issuer_targets, case, manifest_rows):
    e = html.escape
    rows = ""
    for t in sorted(targets.values(), key=lambda t: (not t["yours"], -sum(d["xrp"] for d in t["deposits"]))):
        ent = t["entry"]
        le = [c for c in ent.get("channels", []) if c.get("who") in ("law_enforcement", "both")]
        route = "<br>".join(f"<a href='{e(c.get('url') or 'mailto:' + c.get('email', ''))}'>"
                            f"{e(c.get('label', c['type']))}</a>" for c in le) or \
            "<i>official LE page (not verified here)</i>"
        deps = "<br>".join(f"<span class=m>{e(str(d['address']))}</span> tag <b>{e(str(d['tag']))}</b> "
                           f"- {float(d.get('amount') or 0):,.4f} {e(d.get('asset', 'XRP'))} ({e(_chain_name(d.get('chain', 'xrpl')))}) - {e(str(d.get('time')))} "
                           f"<a href='{e(d.get('tx_url') or EXPLORER + str(d['hash']))}'>tx</a>" + (" <b>[victim funds]</b>" if d["yours"] else "")
                           for d in t["deposits"][:25])
        more = f"<br><i>+{len(t['deposits']) - 25} more in the kit CSV</i>" if len(t["deposits"]) > 25 else ""
        rows += (f"<tr><td><b>{e(ent.get('name', 'Unidentified'))}</b>"
                 + (f"<br><small>{e(ent['deadline_note'])}</small>" if ent.get("deadline_note") else "")
                 + f"</td><td>{deps}{more}</td><td>{route}</td></tr>")
    iss = "".join(f"<tr><td>{e(h['issuer_name'] or h['issuer'])}</td><td>{e(h['currency'])} {h['balance']:,.2f} at "
                  f"<span class=m>{e(h['wallet'])}</span></td><td>freeze: {'yes' if h['freezable'] else 'no'}; "
                  f"clawback: {'yes' if h['clawback'] else 'no'}</td></tr>" for h in issuer_targets)
    man = "".join(f"<tr><td class=m>{e(d)}</td><td>{e(f)}</td></tr>" for f, d in manifest_rows)
    return f"""<!doctype html><html><head><meta charset=utf-8><title>Officer Packet</title><style>
body{{font:14px/1.45 Georgia,serif;max-width:900px;margin:24px auto;padding:0 16px;color:#111;background:#fff}}
h1{{font-size:22px}} h2{{font-size:16px;border-bottom:2px solid #111;margin-top:26px}}
table{{border-collapse:collapse;width:100%;font-size:12.5px}} td,th{{border:1px solid #999;padding:6px;vertical-align:top;text-align:left}}
.m{{font-family:Consolas,monospace;font-size:11.5px;word-break:break-all}} .box{{border:2px solid #111;padding:10px;margin:10px 0}}
@media print{{a{{color:#000}}}}</style></head><body>
<h1>Cryptocurrency Fraud - Officer Packet</h1>
<div class=box><b>What this is:</b> a ready-to-file package for a law-enforcement officer. Exchanges freeze
accounts on <b>law-enforcement requests</b>. Each exchange below lists its official law-enforcement channel.
A signed request template for each exchange is in the kit folder (<i>officer_request.txt</i>).
Every transaction is public and verifiable on its blockchain via the links.</div>
<h2>1. Complainant</h2>
<p>Name: {e(case.get('name', '_____'))} &nbsp; Email: {e(case.get('email', '_____'))} &nbsp; Phone: {e(case.get('phone', '_____'))}<br>
FBI IC3 complaint: <b>{e(case.get('ic3_id', '_____'))}</b><br>
Other reports: {e('; '.join(case.get('reports', [])) or '-')}<br>
Victim transaction: <span class=m>{e(case.get('tx_hash', '_____'))}</span> <a href='{EXPLORER}{e(case.get('tx_hash', ''))}'>view</a><br>
Fraud wallet: <span class=m>{e(root)}</span> <a href='{ACCT}{e(root)}'>view</a></p>
<h2>2. Exchange accounts that received funds (address + destination tag = customer account)</h2>
<table><tr><th>Platform</th><th>Deposits</th><th>Law-enforcement channel</th></tr>{rows or '<tr><td colspan=3>None yet</td></tr>'}</table>
<h2>3. Issued-token freeze opportunities</h2>
{'<table><tr><th>Issuer</th><th>Holding</th><th>Issuer powers</th></tr>' + iss + '</table>' if iss else '<p>None detected (XRP itself cannot be frozen; issued tokens such as RLUSD can be).</p>'}
<h2>4. Requested actions</h2><ol><li>Preservation request to each platform above (KYC, IP/device logs, linked payment methods, withdrawal destinations).</li>
<li>Withdrawal restriction on each listed account pending legal process. <b>MEXC: an LE request must arrive within 48 hours of the victim's report to keep the temporary freeze.</b></li>
<li>Freeze / clawback request to the issuer of any token listed in section 3.</li></ol>
<h2>5. Evidence integrity (SHA-256)</h2><table><tr><th>SHA-256</th><th>File</th></tr>{man}</table>
<p><small>Generated by ScamHunter Desk (open-source, free for victims). This tool never contacts anyone and never asks victims for payment.</small></p>
</body></html>"""


# --------------------------------------------------------------- build ------

def _write(path, text, changed):
    old = None
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace", newline="") as f:
            old = f.read()
    if old == text:
        return
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    custody.record(path, "generated" if old is None else "updated")
    changed.append(path)


def build(log=print):
    """Rebuild all kits. Returns {"targets":..., "new":[tid...], "changed":[paths]}."""
    case = load_case()
    root, targets, issuer_targets, mc_ops = collect()
    os.makedirs(os.path.join(ROOT, "_case"), exist_ok=True)
    changed, new = [], []
    st = tracker.load()
    manifest_rows = []
    for tid, t in targets.items():
        folder = os.path.join(ROOT, tid)
        os.makedirs(folder, exist_ok=True)
        files = {"00_READ_ME_FIRST.txt": readme(t, case),
                 "victim_notice.txt": victim_notice(t, case, root),
                 "officer_request.txt": officer_request(t, case, root),
                 "fund_inflow.csv": fund_inflow_csv(t)}
        before = len(changed)
        for fn, txt in files.items():
            _write(os.path.join(folder, fn), txt, changed)
        paths = sorted(os.path.join(folder, f) for f in os.listdir(folder) if f != "MANIFEST.txt")
        if len(changed) > before or not os.path.exists(os.path.join(folder, "MANIFEST.txt")):
            custody.write_manifest(folder, paths)
        manifest_rows += [(f"{tid}/{os.path.basename(p)}", custody.sha256_file(p)) for p in paths]
        info = {"name": t["entry"].get("name"), "yours": t["yours"],
                "xrp": round(sum(d["xrp"] for d in t["deposits"]), 6), "deposits": len(t["deposits"]),
                "amount_str": amt_str([d for d in t["deposits"] if d["yours"]] or t["deposits"])}
        tracker.register_target(st, tid, None, info)
        rec = st["targets"][tid]
        rec.update(info)
        if t["yours"] and not rec.get("yours_since"):
            # first time YOUR funds are seen here: start the "time since cash-out" clock.
            # (Platform deadlines, e.g. MEXC's 48h, run from when YOU file the victim
            # report -- the Submission Center computes them from that status.)
            from datetime import datetime
            rec["yours_since"] = datetime.now().strftime(tracker.FMT)
            new.append(tid)
    evid = _j("scam_network.json") or {}
    case_files = {"seal911_message.txt": seal911_message(root, targets, case, issuer_targets),
                  "chainabuse_update.txt": chainabuse_update(root, evid.get("nodes", {}), targets),
                  "ic3_update.txt": ic3_update(root, targets, case)}
    ir = issuer_requests(issuer_targets, mc_ops, case)
    if ir:
        case_files["issuer_requests.txt"] = ir
    for fn, txt in case_files.items():
        _write(os.path.join(ROOT, "_case", fn), txt, changed)
    manifest_rows += [(f"_case/{fn}", custody.sha256_file(os.path.join(ROOT, "_case", fn))) for fn in case_files]
    _write(os.path.join(ROOT, "_case", "officer_packet.html"),
           officer_packet_html(root, targets, issuer_targets, case, manifest_rows), changed)
    # forget targets that no longer exist (e.g. now attributed to an exchange) unless you tracked them
    for old_tid in list(st["targets"]):
        if old_tid not in targets and not any(k.split(":")[0] == old_tid for k in st["status"]):
            st["targets"].pop(old_tid, None)
    tracker.save(st)
    if changed:
        log(f"freeze kits: {len(changed)} file(s) updated across {len(targets)} target(s)")
    return {"targets": targets, "issuer_targets": issuer_targets, "new": new, "changed": changed, "root": root}
