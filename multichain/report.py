"""Auto-draft freeze / preservation / takedown reports for every opportunity
the tracer finds, on any chain. Nothing is ever auto-sent -- each is written to
mc_reports/ for review, with a one-tap action where a channel is known.

Three kinds of report:
  * stablecoin_issuer -> to Tether / Circle: freeze USDT/USDC at a specific
                         address on a specific chain. The strongest lever: the
                         issuer can freeze regardless of who holds the tokens.
  * exchange          -> to the exchange's compliance / law-enforcement desk:
                         freeze the depositing account and preserve KYC.
  * bridge            -> to the bridge / swap service: halt the conversion and
                         DISCLOSE the destination asset, address and chain (the
                         lead that lets the trace continue).

Contacts are best-effort published channels and must be verified before
sending; we never invent an email. Where only a portal / guidelines page is
known, that URL is used and the full text is in the saved draft.
"""
import json
import os
import re
import urllib.parse

from . import entities
from .core import chain as chain_info

try:
    import scamconfig
except Exception:
    scamconfig = None

# Published law-enforcement / compliance channels. VERIFY before sending.
EXCHANGE_ROUTES = {
    "binance":   ("portal", "https://www.binance.com/en/support/law-enforcement"),
    "coinbase":  ("email", "lawenforcement@coinbase.com"),
    "kraken":    ("email", "lawenforcement@kraken.com"),
    "okx":       ("portal", "https://www.okx.com/"),
    "kucoin":    ("portal", "https://www.kucoin.com/legal"),
    "bybit":     ("portal", "https://www.bybit.com/"),
    "huobi":     ("portal", "https://www.htx.com/"),
    "htx":       ("portal", "https://www.htx.com/"),
    "gate":      ("portal", "https://www.gate.com/"),
    "mexc":      ("portal", "https://www.mexc.com/"),
    "bitfinex":  ("email", "compliance@bitfinex.com"),
    "crypto.com":("portal", "https://crypto.com/"),
    "uphold":    ("email", "compliance@uphold.com"),
    "changenow": ("email", "compliance@changenow.io"),
    "changelly": ("portal", "https://changelly.com"),
    "fixedfloat":("portal", "https://fixedfloat.com"),
}
GENERIC_EXCHANGE = ("Identify this platform's compliance / law-enforcement request channel "
                    "(search '<name> law enforcement request') and submit this report with your "
                    "IC3 complaint number.")


def _route_for(label):
    low = (label or "").lower()
    for k, v in EXCHANGE_ROUTES.items():
        if k in low:
            return v
    return ("generic", None)


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


def _refs(case):
    out = []
    if case.get("ic3_id"):
        out.append(f"FBI IC3 complaint {case['ic3_id']}")
    for r in case.get("reports", []):
        if "chainabuse" in r.lower():
            out.append(r)
    return out


def _origin(case):
    tx = case.get("tx_hash")
    w = case.get("scam_wallet") or (scamconfig.scam_wallet() if scamconfig else "")
    line = "These funds originate from a cryptocurrency fraud"
    if case.get("scam_type"):
        line += f" ({case['scam_type']})"
    if w:
        line += f". The scam collected victim funds at source wallet {w}"
    if tx:
        line += f" (documented victim transaction {tx})"
    return line + ". They were laundered through intermediary wallets and across chains to the address below."


def _sig(case, anonymous=True):
    if anonymous:
        return ("A documented victim of the fraud\n(Identity on record with the U.S. FBI / IC3; "
                "available on lawful request)")
    return f"{case.get('name','')}\n{case.get('email','')}"


def make(op, case=None, anonymous=True):
    """op: a freeze_op dict from the tracer. Returns (filename, subject, route, text)."""
    case = case or {}
    ci = chain_info(op["chain"])
    addr = op["address"]
    refs = _refs(case)
    refs_line = ("Existing case references: " + "; ".join(refs) + ".") if refs else ""
    origin = _origin(case)
    sig = _sig(case, anonymous)
    addr_url = ci.explorer_addr(addr)

    if op["kind"] == "stablecoin_issuer":
        issuer = entities.ISSUERS.get(op.get("issuer"), {})
        iname = issuer.get("name") or op.get("issuer", "the token issuer")
        route = ("portal", issuer.get("contact"))
        subject = (f"URGENT - request to freeze stolen {op.get('asset')} on {ci.name} "
                   f"(address {addr[:12]}...)")
        amt = op.get("amount")
        amt_line = f"Approximately {amt:,.2f} {op.get('asset')} reached this address" if amt else \
                   f"Stolen {op.get('asset')} reached this address"
        text = (f"To {iname} - Compliance / Law Enforcement,\n\n"
                f"I am a victim of cryptocurrency fraud. {origin}\n\n"
                f"{amt_line} on {ci.name}:\n"
                f"  Token:    {op.get('asset')}\n"
                f"  Address:  {addr}\n"
                f"  Chain:    {ci.name}\n"
                f"  Tx:       {op.get('txid')}\n"
                f"  Explorer: {addr_url}\n\n"
                f"Because {op.get('asset')} is issued by you, you are able to freeze these tokens at "
                f"this address. I request that you:\n"
                f"  1. Freeze / blacklist the {op.get('asset')} held at {addr} on {ci.name}.\n"
                f"  2. Preserve all records associated with it for law enforcement.\n\n"
                f"{refs_line}\n"
                f"My identity is on record with the FBI / IC3 and I can provide the full on-chain "
                f"trace on request.\n\n{sig}\n\n"
                f"[Review before sending. Submit via {iname}'s official law-enforcement / compliance "
                f"channel: {route[1]} . Funds commingle across hops; confirm this address against the "
                f"trace first.]\n")
        return (f"freeze_{op.get('asset')}_{op['chain']}_{_slug(addr)[:16]}.txt", subject, route, text)

    if op["kind"] == "bridge":
        route = _route_for(op.get("label"))
        svc = op.get("label") or "the bridge / swap service"
        subject = f"URGENT - stolen funds routed through your service on {ci.name}; disclose destination"
        text = (f"To the compliance team of {svc},\n\n"
                f"I am a victim of cryptocurrency fraud. {origin}\n\n"
                f"Stolen funds reached your service at this address on {ci.name}:\n"
                f"  Address:  {addr}\n  Explorer: {addr_url}\n\n"
                f"Because your service converts or bridges assets, these funds may be leaving {ci.name}. "
                f"I request that you:\n"
                f"  1. Halt / freeze any pending conversion or transfer associated with this address.\n"
                f"  2. Disclose the DESTINATION asset, address and chain the funds were converted to "
                f"(this is required to continue the trace), and preserve all related records.\n\n"
                f"{refs_line}\nMy identity is on record with the FBI / IC3.\n\n{sig}\n\n"
                f"[Review before sending. Route: {route[1] or GENERIC_EXCHANGE}]\n")
        return (f"bridge_{op['chain']}_{_slug(op.get('label') or addr)[:20]}.txt", subject, route, text)

    # exchange
    route = _route_for(op.get("label"))
    svc = op.get("label") or "the receiving platform"
    subject = f"URGENT - stolen cryptocurrency deposited to your platform on {ci.name}"
    text = (f"To the compliance / law-enforcement team of {svc},\n\n"
            f"I am a victim of cryptocurrency fraud. {origin}\n\n"
            f"Stolen funds were deposited to an account on your platform:\n"
            f"  Address:  {addr}\n  Chain:    {ci.name}\n  Explorer: {addr_url}\n\n"
            f"I request that you:\n"
            f"  1. Freeze the account that received these funds.\n"
            f"  2. Preserve its KYC identity records, access/IP logs and transaction history for "
            f"law enforcement.\n\n"
            f"{refs_line}\nMy identity is on record with the FBI / IC3.\n\n{sig}\n\n"
            f"[Review before sending. Route: {route[1] or GENERIC_EXCHANGE}]\n")
    return (f"exchange_{op['chain']}_{_slug(op.get('label') or addr)[:20]}.txt", subject, route, text)


def action_for(op, case=None):
    """One-tap (label, url): a Gmail draft when a direct email is known, else
    the service's portal / guidelines page, else the address on the explorer."""
    fname, subject, route, body = make(op, case)
    if route[0] == "email" and route[1]:
        q = urllib.parse.urlencode({"view": "cm", "fs": "1", "to": route[1], "su": subject, "body": body})
        return "Open Gmail draft", f"https://mail.google.com/mail/?{q}"
    if route[1]:
        return "Open report channel", route[1]
    return "View address", chain_info(op["chain"]).explorer_addr(op["address"])


def write_all(tracer_state, case=None, out_dir="mc_reports"):
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for op in tracer_state.get("freeze_ops", []):
        fname, subject, route, text = make(op, case)
        path = os.path.join(out_dir, fname)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        written.append(path)
    return written
