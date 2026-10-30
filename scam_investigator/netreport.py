"""Auto-draft freeze/preservation reports when stolen funds reach an exchange.

When the network watcher detects a cash-out (funds landing at an exchange or
custodial deposit), it calls make_report() to produce a complete, ready-to-send
report addressed to that exchange's compliance / law-enforcement channel. The
report is written to network_reports/ and the watcher pushes a phone alert that
one is ready. Nothing is sent automatically — the victim reviews and sends.

Reports are factual: stolen funds, the exact deposit transaction, a freeze and
records-preservation request, and the victim's existing case references. They
name no individual — across shared laundering hubs we do not know who controls
which account, and a precise, verifiable report is what an exchange acts on.

EXCHANGE_CONTACTS is best-effort and meant to be edited/verified. Exchanges
change their intake channels; always confirm the current law-enforcement /
compliance route before sending, and submit through their official portal.
"""
import json
import os
import re
import urllib.parse
from datetime import datetime

from .swaps import swap_info

# Best-effort compliance / law-enforcement intake routes. VERIFY before sending.
# Keyed by a substring of the xrpscan label (lower-cased).
EXCHANGE_CONTACTS = {
    "binance":    {"route": "Binance Law Enforcement Request System: https://www.binance.com/en/support/law-enforcement (or compliance via official support). Reference your IC3 complaint."},
    "coinbase":   {"route": "Coinbase: lawenforcement@coinbase.com and https://www.coinbase.com/legal/law_enforcement_guidelines"},
    "kraken":     {"route": "Kraken: lawenforcement@kraken.com"},
    "kucoin":     {"route": "KuCoin: compliance / law-enforcement portal https://www.kucoin.com/legal (law enforcement request guide)"},
    "changenow":  {"route": "ChangeNOW: compliance@changenow.io / support@changenow.io (quote the tx hash; they can freeze pending exchanges)"},
    "union chain":{"route": "Union Chain: search their official site for a compliance / support / law-enforcement contact; include this report and your IC3 number."},
    "bitrue":     {"route": "Bitrue: https://www.bitrue.com/exchange-web/footer/contactus.html (compliance)"},
    "uphold":     {"route": "Uphold: https://support.uphold.com/hc/en-us/requests/new (compliance / fraud)"},
    "okx":        {"route": "OKX: law enforcement request portal on okx.com; reference IC3."},
    "bybit":      {"route": "Bybit: law enforcement request portal on bybit.com; reference IC3."},
}
GENERIC_ROUTE = ("Identify this exchange's compliance / law-enforcement request channel "
                 "(search '<exchange name> law enforcement request'), and submit this report "
                 "with your IC3 complaint number. If the receiving address is unlabeled, report "
                 "it to Chainabuse (https://chainabuse.com/report) and note it for law enforcement.")

# Direct compliance EMAIL where one exists (enables a one-tap Gmail draft).
# Where an exchange only takes reports via a web portal, we open the PORTAL
# instead. VERIFY these before relying on them.
EXCHANGE_EMAIL = {}   # Only VERIFIED addresses belong here -- see freezekit/channels.json,
                      # which the Submission Center uses. Guessed emails bounce and waste
                      # the hours that matter, so none are hardcoded.
EXCHANGE_PORTAL = {
    "binance": "https://www.binance.com/en/support/law-enforcement",
    "kucoin":  "https://www.kucoin.com/legal",
    "bitrue":  "https://www.bitrue.com/exchange-web/footer/contactus.html",
    "okx":     "https://www.okx.com/",
    "bybit":   "https://www.bybit.com/",
}


def _key_for(label):
    low = (label or "").lower()
    for k in list(EXCHANGE_EMAIL) + list(EXCHANGE_PORTAL):
        if k in low:
            return k
    return None


def _route_for(label):
    low = (label or "").lower()
    for k, v in EXCHANGE_CONTACTS.items():
        if k in low:
            return v["route"]
    return GENERIC_ROUTE


def _slug(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s or "")[:60]


def load_case(path="victim.json"):
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def make_report(event, scam_wallet, case=None):
    """event: {address,label,destination_tag,xrp,hash,time}. Returns (filename, text)."""
    case = case or {}
    label = event.get("label") or "unlabeled custodial wallet"
    tag = event.get("destination_tag")
    sw = swap_info(event.get("label"))
    is_swap = bool(event.get("is_swap")) or bool(sw)
    svc = (sw or {}).get("name") or label.split("(")[0].strip()
    refs = []
    if case.get("ic3_id"):
        refs.append(f"FBI IC3 complaint {case['ic3_id']}")
    for r in case.get("reports", []):
        if "chainabuse" in r.lower():
            refs.append(r)
    refs_line = ("Existing case references: " + "; ".join(refs)) if refs else ""
    sig = case.get("name") or "A documented victim of the fraud"
    contact = case.get("email") or ""

    if is_swap:
        route = (f"Contact {svc} immediately via their official compliance / support channel"
                 + (f" ({sw['site']})" if sw and sw.get("site") else "")
                 + ". Instant-swap services can halt a pending conversion if reached fast; "
                 "quote the transaction hash and reference your IC3 complaint.")
        subject = (f"URGENT - stolen XRP sent to your swap/bridge service; funds may be converting "
                   f"to another asset (tx {event['hash'][:12]}...)")
        intro = (f"Funds stolen in a cryptocurrency fraud have been sent to {svc}. Because your service "
                 f"converts assets and bridges value off the XRP Ledger, these funds may be in the "
                 f"process of leaving the ledger right now. I am a victim and I am asking you to halt "
                 f"this conversion/exchange and preserve all records for law enforcement. Time is critical.")
        requests = (f"Requests:\n"
                    f"  1. Immediately halt / freeze the pending swap or exchange associated with this "
                    f"deposit (destination tag {tag}) and any onward transfer of the converted funds.\n"
                    f"  2. Record and preserve the DESTINATION asset, address, and chain the funds were "
                    f"(or were to be) converted to -- this is the lead for continuing the trace.\n"
                    f"  3. Preserve any KYC identity records, access/IP logs, and the full transaction "
                    f"history for law enforcement.\n")
    else:
        route = _route_for(event.get("label"))
        subject = f"URGENT - stolen cryptocurrency deposited to your platform (XRP, destination tag {tag})"
        intro = ("Funds stolen in a cryptocurrency fraud have been deposited to an account on your platform. "
                 "I am a victim and I am requesting that you freeze the receiving account and preserve its "
                 "records for law enforcement.")
        requests = (f"Requests:\n"
                    f"  1. Freeze the account associated with destination tag {tag} that received this deposit.\n"
                    f"  2. Preserve that account's KYC identity records, access/IP logs, and transaction history "
                    f"for law enforcement.\n")

    text = (
        f"ROUTE: {route}\n"
        f"SUBJECT: {subject}\n\n"
        f"To the compliance / law-enforcement team of {svc},\n\n"
        f"{intro}\n\n"
        f"Deposit details (XRP Ledger, public and verifiable):\n"
        f"  Receiving address: {event['address']}\n"
        f"  Destination tag:   {tag}\n"
        f"  Amount:            {event['xrp']:,.6f} XRP\n"
        f"  Transaction hash:  {event['hash']}\n"
        f"  Time:              {event.get('time')}\n"
        f"  Explorer:          https://livenet.xrpl.org/transactions/{event['hash']}\n\n"
        f"Origin of funds: these XRP trace from the scam wallet {scam_wallet}, which collected funds "
        f"from multiple victims of a fake cryptocurrency giveaway and forwarded them through "
        f"intermediary wallets to your service.\n\n"
        f"{requests}\n"
        f"{refs_line}\n"
        f"I can provide the full on-chain trace and supporting evidence on request, and my identity is "
        f"on record with the FBI / IC3.\n\n"
        f"{sig}\n{contact}\n\n"
        f"[Review this draft before sending. Funds commingle at intermediary wallets, so confirm this "
        f"deposit against the trace before asserting it contains your specific XRP. Submit via the ROUTE "
        f"above and reference your IC3 complaint.]\n"
    )
    kind = "swap_freeze" if is_swap else "freeze_request"
    fname = f"{kind}_{_slug(event.get('label') or svc or 'custodial')}_{event['hash'][:10]}.txt"
    return fname, text


def gmail_action(event, scam_wallet, case=None):
    """Return (label, url) for a one-tap phone action.

    If the exchange has a direct compliance email, the url is a Gmail compose
    link prefilled with recipient + subject + the full report (review and send).
    Otherwise the url opens the exchange's report portal, and the full text is
    in the saved draft file / the notification.
    """
    _, body = make_report(event, scam_wallet, case)
    # The report's first lines are ROUTE/SUBJECT meta; the email body is the rest.
    sw = swap_info(event.get("label"))
    if sw:
        subject = (f"URGENT: stolen XRP sent to your swap/bridge service - funds may be converting "
                   f"to another asset (tag {event.get('destination_tag')})")
        if sw.get("email"):
            q = urllib.parse.urlencode({"view": "cm", "fs": "1", "to": sw["email"], "su": subject, "body": body})
            return "Open Gmail draft", f"https://mail.google.com/mail/?{q}"
        if sw.get("site"):
            return f"Open {sw['name']} site", sw["site"]
    subject = f"URGENT: stolen XRP deposited to your platform (destination tag {event.get('destination_tag')})"
    key = _key_for(event.get("label"))
    email = EXCHANGE_EMAIL.get(key) if key else None
    if email:
        q = urllib.parse.urlencode({"view": "cm", "fs": "1", "to": email, "su": subject, "body": body})
        return "Open Gmail draft", f"https://mail.google.com/mail/?{q}"
    portal = EXCHANGE_PORTAL.get(key) if key else None
    if portal:
        return "Open report portal", portal
    return "View transaction", f"https://livenet.xrpl.org/transactions/{event['hash']}"


def write_report(event, scam_wallet, out_dir="network_reports", case=None):
    os.makedirs(out_dir, exist_ok=True)
    fname, text = make_report(event, scam_wallet, case)
    path = os.path.join(out_dir, fname)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def write_all_from_map(net, out_dir="network_reports", case=None):
    """Regenerate a report for every cash-out endpoint in a saved map."""
    scam = net.get("root")
    written = []
    seen = set()
    for ep in net.get("endpoints", []):
        key = (ep["address"], ep.get("destination_tag"), ep.get("hash"))
        if key in seen:
            continue
        seen.add(key)
        written.append(write_report(ep, scam, out_dir, case))
    return written
