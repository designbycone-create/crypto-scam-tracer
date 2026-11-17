"""Second opinion on a crypto address from Public AML (publicaml.org).

Public AML is a free, non-profit screening service: no key, no signup, no paid tier. It returns a
0-100 risk score with its reasons (sanctions, scam and phishing reports, hacks, issuer freezes,
exposure to stolen funds) and, when known, who the address belongs to.

How ScamHunter uses it:
  * Only as extra evidence. A LOW score or "not found" is never shown as safe: in testing it
    scored a known OPTIMJACK attacker address 0, which ScamHunter's own feed flags.
  * The address you check is sent to Public AML. Addresses are public, but to keep the lookup
    on your computer only, set "publicaml": false in config.json.

Terms: publicaml.org/terms (results are informational; don't abuse the service).
"""
import json
import urllib.request

API = "https://intelapi.publicaml.org/v2/enrich"
CHAIN = {"ethereum": "ETH", "bsc": "BSC", "bitcoin": "BTC", "tron": "TRON", "solana": "SOL"}
UA = {"Content-Type": "application/json",
      "User-Agent": "ScamHunter/1.0 (free scam-victim tool; github.com/designbycone-create/crypto-scam-tracer)"}
POST = None        # test hook: f(url, body) -> dict


def enabled():
    try:
        with open("config.json", encoding="utf-8-sig") as f:
            return json.load(f).get("publicaml", True) is not False
    except Exception:
        return True


def lookup(addr, chain):
    """dict from Public AML for one address, {"not_found": True}, or None if the chain isn't covered / it failed."""
    code = CHAIN.get(chain)
    if not code:
        return None
    body = {"addresses": [{"wallet_address": addr, "chain": code}], "include": ["risk", "axes"]}
    try:
        if POST:
            d = POST(API, body)
        else:
            req = urllib.request.Request(API, data=json.dumps(body).encode(), headers=UA)
            with urllib.request.urlopen(req, timeout=20) as r:
                d = json.loads(r.read())
    except Exception:
        return None
    if d.get("not_found"):
        return {"not_found": True}
    ents = d.get("entities") or []
    return ents[0] if ents else {"not_found": True}


def findings(addr, chain):
    """(level, text) lines for the pre-screen."""
    if not enabled():
        return []
    e = lookup(addr, chain)
    if e is None:
        return []
    if e.get("not_found"):
        return [("info", "Public AML (free non-profit screening) has no data on this address. That is not the same as clean.")]
    risk = e.get("risk") or {}
    score = risk.get("score") or 0
    axes = e.get("axes") or {}
    legal = (axes.get("legal_status") or {}).get("category")
    label = e.get("label")
    reasons = []
    for s in ((risk.get("breakdown") or {}).get("propagated_sources") or [])[:3]:
        hop = "this address" if s.get("hops") == 0 else f"{s.get('hops')} hop(s) away"
        reasons.append(f"{s.get('category')} ({s.get('source')}, {hop})")
    why = f" Reasons: {'; '.join(reasons)}." if reasons else ""
    who = f" Public AML identifies it as {label}." if label else ""
    if legal == "sanction" or score >= 70:
        return [("stop", f"Public AML rates this address {risk.get('level', 'high').lower()} risk ({score:.0f}/100).{who}{why}")]
    if score >= 40:
        return [("caution", f"Public AML rates this address {risk.get('level', 'medium').lower()} risk ({score:.0f}/100).{who}{why}")]
    return [("info", f"Public AML found no strong risk signals ({score:.0f}/100).{who} A low score is not a guarantee: "
                     "new scam wallets often have no record yet.")]
