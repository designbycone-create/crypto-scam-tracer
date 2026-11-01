"""Officer-ready request packets, built from the case the Desk already tracks.

  exchange_kit(target)     one PDF + one CSV per exchange that received the money:
                             routing (only channels verified on the exchange's own page),
                             the deposit facts, a draft preservation-and-freeze request,
                             "Attachment A" (records to request), and a copyable address/hash list.
  stablecoin_packet(name)  one PDF for Tether (USDT) or Circle (USDC): where the scam network holds
                             that token right now (live balances), the transactions, and what to ask.

Rules: these are DRAFTS for a police officer or attorney. Exchanges and stablecoin issuers act on law
enforcement or court process; ScamHunter never sends anything. Channels not verified on the company's
own page are shown as "confirm on the official site", never guessed.
"""
import csv
import io
import json
import os
import time

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

OUT = os.path.join("freeze_kits", "requests")

# Stablecoin contracts by chain (issuer-published; mirrors multichain.entities.STABLECOINS)
TOKENS = {
    "tether": {"ethereum": "0xdac17f958d2ee523a2206206994597c13d831ec7", "polygon": "0xc2132d05d31c914a87c6611c10748aeb04b58e8f",
               "bsc": "0x55d398326f99059ff775485246999027b3197955", "arbitrum": "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",
               "avalanche": "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7", "optimism": "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58",
               "tron": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"},
    "circle": {"ethereum": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "polygon": "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
               "arbitrum": "0xaf88d065e77c8cc2239327c5edb3a432268e5831", "base": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
               "optimism": "0x0b2c639c533813f4aa9d7837caf62653d097ff85", "avalanche": "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e"},
}
ISSUER = {
    "tether": {"name": "Tether (USDT)", "token": "USDT",
               "how": "Tether freezes USDT addresses at law-enforcement request, often before formal court proceedings "
                      "conclude, and in some cases burns frozen tokens and reissues them to law enforcement or victims.",
               "sources": [("Tether freeze network figures (BlockEden, Mar 2026)",
                            "https://blockeden.xyz/blog/2026/03/14/tether-3-4b-global-freeze-network-usdt-law-enforcement-1800-investigations/"),
                           ("T3 Financial Crime Unit (TRM Labs)",
                            "https://www.trmlabs.com/resources/blog/t3-financial-crime-unit-a-model-for-public-private-disruption-in-the-age-of-stablecoins")]},
    "circle": {"name": "Circle (USDC)", "token": "USDC",
               "how": "Circle can blacklist USDC addresses, but reporting shows it generally acts on court orders, regulatory "
                      "mandates or sanctions rather than a police request alone. Plan for a court order (seizure warrant or "
                      "restraining order) naming the addresses below.",
               "sources": [("Freeze practices compared, Tether vs Circle (BlockEden, Mar 2026)",
                            "https://blockeden.xyz/blog/2026/03/14/tether-3-4b-global-freeze-network-usdt-law-enforcement-1800-investigations/"),
                           ("Prosecutors on Circle and stolen USDC (ICIJ)",
                            "https://www.icij.org/investigations/coin-laundry/crypto-giant-circle-rebuffed-efforts-to-help-scam-victims-police-say/")]},
}
RECORDS = [
    "Identity (KYC) records: name, date of birth, addresses, phone numbers, emails, government ID images, selfies/liveness checks.",
    "Account opening and profile data, including referral codes and linked or sub-accounts.",
    "Login and session records: IP addresses with timestamps, device identifiers, user agents, 2FA changes.",
    "Full deposit and withdrawal history, including on-chain transaction hashes, destination addresses and memos/tags.",
    "Internal transfers, trades, conversions and fiat on/off-ramp records (bank accounts, cards, payment processors).",
    "Linked accounts sharing identity data, devices, IP addresses or withdrawal destinations.",
    "Support tickets and communications with the account holder.",
    "Any prior compliance flags, freezes or law-enforcement requests concerning these accounts.",
]


def _st():
    ss = getSampleStyleSheet()
    return {"t": ParagraphStyle("t", parent=ss["Title"], fontSize=18, leading=22, alignment=0),
            "h": ParagraphStyle("h", parent=ss["Heading2"], fontSize=13, leading=16, spaceBefore=10),
            "b": ParagraphStyle("b", parent=ss["BodyText"], fontSize=10, leading=14),
            "s": ParagraphStyle("s", parent=ss["BodyText"], fontSize=8.5, leading=11),
            "c": ParagraphStyle("c", parent=ss["BodyText"], fontSize=8, leading=10, wordWrap="CJK")}


def _e(x):
    return str(x if x is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _tbl(rows, widths, st):
    t = Table([[Paragraph(_e(c), st["c"]) for c in r] for r in rows], colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8ecf3"))]))
    return t


def _victim():
    try:
        with open("victim.json", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return {}


def _pdf(path, story, title, footer_text):
    def foot(c, doc):
        c.saveState()
        c.setFont("Helvetica", 7.5)
        c.setFillColor(colors.HexColor("#555555"))
        c.drawString(0.6 * inch, 0.45 * inch, footer_text)
        c.drawRightString(LETTER[0] - 0.6 * inch, 0.45 * inch, f"Page {doc.page}")
        c.restoreState()
    SimpleDocTemplate(path, pagesize=LETTER, leftMargin=0.6 * inch, rightMargin=0.6 * inch, topMargin=0.6 * inch,
                      bottomMargin=0.75 * inch, title=title, creator="ScamHunter").build(story, onFirstPage=foot,
                                                                                         onLaterPages=foot)


def _slug(s):
    import re
    return re.sub(r"[^a-z0-9]+", "-", (s or "x").lower()).strip("-")[:40]


def exchange_kit(target, out_dir=OUT):
    """target: one entry from freezekit.kit.collect()[1]. Returns (pdf_path, csv_path)."""
    os.makedirs(out_dir, exist_ok=True)
    st, v = _st(), _victim()
    ent = target.get("entry") or {}
    name = ent.get("name") or target.get("id")
    deps = sorted(target.get("deposits") or [], key=lambda d: str(d.get("time") or ""))
    stamp = time.strftime("%Y-%m-%d")
    base = os.path.join(out_dir, f"request_kit_{_slug(name)}_{stamp}")
    # CSV first (exchanges ask for identifiers in a copyable file)
    with open(base + ".csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["chain", "deposit_address", "tag_or_memo", "amount", "asset", "time_utc", "transaction_hash", "on_victims_path"])
        for d in deps:
            w.writerow([d.get("chain", "xrpl"), d.get("address"), "" if d.get("tag") is None else d.get("tag"),
                        d.get("amount"), d.get("asset"), d.get("time"), d.get("hash"), "yes" if d.get("yours") else "network"])
    S = [Paragraph(f"Exchange Request Kit: {_e(name)}", st["t"]),
         Paragraph(f"Prepared {stamp} with ScamHunter from public blockchain records. <b>Draft for a police officer or "
                   "attorney.</b> Exchanges release records and freeze accounts on law-enforcement or court process; "
                   "this kit gives that person everything needed to file quickly. Not legal advice.", st["b"])]
    S.append(Paragraph("1. Where the officer files", st["h"]))
    chans = ent.get("channels") or []
    le = [c for c in chans if c.get("who") in ("law_enforcement", "both")]
    vic = [c for c in chans if c.get("who") in ("victim", "both")]
    if le:
        for c in le:
            where = c.get("url") or c.get("email")
            S.append(Paragraph(f"&bull; <b>{_e(c.get('label'))}</b>: {_e(where)}"
                               + (f" <i>(verified {c['verified']} on {_e(c.get('source'))})</i>" if c.get("verified") else ""), st["b"]))
    else:
        S.append(Paragraph(f"No law-enforcement channel for {_e(name)} has been verified by ScamHunter yet. Find it on "
                           f"{_e(name)}'s official website (usually titled \"Law Enforcement Request Guide\"). Never use a "
                           "contact address found in a search result, message or social media post: scammers impersonate "
                           "exchange support.", st["b"]))
    if ent.get("note"):
        S.append(Paragraph(_e(ent["note"]), st["s"]))
    if ent.get("deadline_note"):
        S.append(Paragraph("<b>Deadline:</b> " + _e(ent["deadline_note"]), st["s"]))
    S.append(Paragraph("2. The facts", st["h"]))
    if v.get("tx_hash"):
        S.append(Paragraph(f"Victim's payment: transaction <b>{_e(v.get('tx_hash'))}</b> to scam wallet "
                           f"<b>{_e(v.get('scam_wallet'))}</b>" + (f"; FBI IC3 complaint {_e(v.get('ic3_id'))}" if v.get("ic3_id") else "")
                           + ".", st["b"]))
    rows = [["Chain", "Deposit address", "Tag / memo", "Amount", "Time (UTC)", "Transaction"]]
    for d in deps:
        rows.append([d.get("chain", "xrpl"), d.get("address"), "" if d.get("tag") is None else d.get("tag"),
                     f"{d.get('amount')} {d.get('asset') or ''}", d.get("time"), d.get("hash")])
    S.append(_tbl(rows, [0.6 * inch, 1.9 * inch, 0.8 * inch, 1.0 * inch, 1.0 * inch, 1.6 * inch], st))
    S.append(Paragraph("On the XRP Ledger the destination tag identifies the customer account inside the exchange; "
                       "on other chains the deposit address does. The same list is in the attached CSV file.", st["s"]))
    S.append(PageBreak())
    S.append(Paragraph("3. Draft: request to preserve records and hold funds", st["h"]))
    tags = ", ".join(sorted({str(d['tag']) for d in deps if d.get('tag') is not None})) or "n/a"
    addrs = ", ".join(sorted({str(d['address']) for d in deps}))
    letter = [
        "[AGENCY LETTERHEAD]",
        f"To: {name}, Law Enforcement Response Team",
        f"Date: [DATE] &nbsp;&nbsp; Our case number: [CASE NUMBER]",
        "Re: Request to preserve records and place a hold on funds connected to a fraud investigation",
        f"This agency is investigating a cryptocurrency fraud reported by [VICTIM NAME]. Funds traced from the victim's "
        f"payment were deposited to {name} as listed in the attached table (deposit address(es): {addrs}; "
        f"destination tag(s): {tags}).",
        "We request that you (1) preserve all records described in Attachment A for every account associated with "
        "these deposits, for 90 days pending legal process; (2) place a hold on the funds in those accounts, to the "
        "extent your policies and applicable law allow, pending legal process; and (3) confirm receipt and the "
        "account identifier(s) involved.",
        "A subpoena, court order or warrant for production will follow. Please contact the undersigned with any "
        "questions.",
        "[NAME, TITLE, BADGE NUMBER] &nbsp;&middot;&nbsp; [AGENCY] &nbsp;&middot;&nbsp; [OFFICIAL EMAIL] &nbsp;&middot;&nbsp; [PHONE]"]
    for l in letter:
        S.append(Paragraph(l, st["b"]))
        S.append(Spacer(1, 4))
    S.append(Paragraph("4. Attachment A: records requested", st["h"]))
    for i, r in enumerate(RECORDS, 1):
        S.append(Paragraph(f"{i}. {_e(r)}", st["b"]))
    S.append(Paragraph(f"Time period: from the account's opening to the date of production. Accounts: all accounts "
                       f"associated with the deposit addresses and tags in the attached table.", st["s"]))
    if vic:
        S.append(Paragraph("5. What the victim can send now (a notice, not a legal request)", st["h"]))
        for c in vic:
            S.append(Paragraph(f"&bull; {_e(c.get('label'))}: {_e(c.get('url') or c.get('email'))}", st["b"]))
        S.append(Paragraph("Victim notice text: \"I am the victim of a cryptocurrency fraud. Funds stolen from me were "
                           "deposited to your exchange as listed in the attached file. I have reported this to "
                           "law enforcement (FBI IC3 complaint [NUMBER]). Please review these accounts and preserve "
                           "records; law enforcement will contact you.\"", st["b"]))
    _pdf(base + ".pdf", S, f"Exchange Request Kit {name}", f"ScamHunter request kit: {name}: draft for law enforcement, {stamp}")
    return base + ".pdf", base + ".csv"


# ------------------------------------------------------------ stablecoin holdings ---
def _evm_balance(chain, token, addr):
    from shield import evm
    raw = int(evm.call(chain, token, "0x70a08231" + evm.pad(addr)[2:]) or "0x0", 16)
    return raw / 1e6           # USDT/USDC use 6 decimals on these chains (BSC USDT uses 18; handled below)


def _tron_balance(token, addr):
    from shield import tron
    d = tron._get(f"/v1/accounts/{addr}") or {}
    for row in ((d.get("data") or [{}])[0].get("trc20") or []):
        if token in row:
            return int(row[token]) / 1e6
    return 0.0


def case_addresses():
    """(chain, address) of every wallet in the tracked scam network on chains where these tokens live."""
    out = []
    try:
        with open("mc_map.json", encoding="utf-8") as f:
            for key in (json.load(f).get("nodes") or {}):
                ch, _, a = key.partition(":")
                if ch and a:
                    out.append((ch, a))
    except Exception:
        pass
    try:
        with open("config.json", encoding="utf-8-sig") as f:
            for c in json.load(f).get("cases") or []:
                out.append((c.get("chain"), c.get("address")))
    except Exception:
        pass
    seen, res = set(), []
    for ch, a in out:
        if ch and a and (ch, a) not in seen:
            seen.add((ch, a))
            res.append((ch, a))
    return res


def holdings(issuer, addresses=None, limit=60):
    rows = []
    for ch, a in (addresses if addresses is not None else case_addresses())[:limit]:
        tok = TOKENS[issuer].get(ch)
        if not tok:
            continue
        try:
            if ch == "tron":
                bal = _tron_balance(tok, a)
            else:
                bal = _evm_balance(ch, tok, a)
                if ch == "bsc":
                    bal = bal / 1e12        # BSC-USD has 18 decimals
            rows.append({"chain": ch, "address": a, "token_contract": tok, "balance": round(bal, 2), "error": None})
        except Exception as e:
            rows.append({"chain": ch, "address": a, "token_contract": tok, "balance": None, "error": str(e)[:60]})
    return rows


def stablecoin_packet(issuer, out_dir=OUT, rows=None):
    os.makedirs(out_dir, exist_ok=True)
    st, info, v = _st(), ISSUER[issuer], _victim()
    rows = holdings(issuer) if rows is None else rows
    held = [r for r in rows if r.get("balance")]
    stamp = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    path = os.path.join(out_dir, f"freeze_packet_{issuer}_{time.strftime('%Y-%m-%d')}.pdf")
    S = [Paragraph(f"Stablecoin Freeze Packet: {_e(info['name'])}", st["t"]),
         Paragraph(f"Balances read from the public blockchain at {stamp}. <b>For a police officer or attorney.</b> "
                   f"Only law enforcement or a court can ask {info['name'].split(' (')[0]} to freeze tokens; a victim "
                   "cannot. Not legal advice.", st["b"]),
         Paragraph("How this issuer acts", st["h"]), Paragraph(_e(info["how"]), st["b"])]
    for t, u in info["sources"]:
        S.append(Paragraph(f"Source: {_e(t)}: {_e(u)}", st["s"]))
    S.append(Paragraph(f"Official submission channel: not verified by ScamHunter. Use {info['name'].split(' (')[0]}'s "
                       "law-enforcement contact as published on its official website, or route through a blockchain "
                       "investigations partner your agency already uses.", st["s"]))
    S.append(Paragraph(f"{info['token']} held right now by wallets in the scam network", st["h"]))
    if held:
        tbl = [["Chain", "Address", f"{info['token']} balance", "Token contract"]]
        for r in sorted(held, key=lambda r: -r["balance"]):
            tbl.append([r["chain"], r["address"], f"{r['balance']:,.2f}", r["token_contract"]])
        S.append(_tbl(tbl, [0.8 * inch, 2.7 * inch, 1.1 * inch, 2.4 * inch], st))
        total = sum(r["balance"] for r in held)
        S.append(Paragraph(f"Total: <b>{total:,.2f} {info['token']}</b> across {len(held)} address(es). Balances change; "
                           "re-run before filing.", st["b"]))
    else:
        S.append(Paragraph(f"No {info['token']} found in the tracked network's wallets right now "
                           f"({len(rows)} checked on chains where {info['token']} exists). Keep this packet ready: the Desk "
                           "re-checks and alerts when the network receives stablecoins.", st["b"]))
    errs = [r for r in rows if r.get("error")]
    if errs:
        S.append(Paragraph(f"{len(errs)} address(es) couldn't be read this time and are not included.", st["s"]))
    S.append(Paragraph("What to request", st["h"]))
    S.append(Paragraph(f"Freeze (blacklist) the addresses listed above for {info['token']}, pending legal process, "
                       f"because they hold proceeds of the fraud reported in case [CASE NUMBER]"
                       + (f" (victim transaction {_e(v.get('tx_hash'))}; FBI IC3 complaint {_e(v.get('ic3_id'))})" if v.get("tx_hash") else "")
                       + ". Ask the issuer to confirm the freeze and the frozen amount in writing.", st["b"]))
    _pdf(path, S, f"Stablecoin Freeze Packet {issuer}", f"ScamHunter freeze packet: {info['name']}: for law enforcement, {stamp}")
    return path, held
