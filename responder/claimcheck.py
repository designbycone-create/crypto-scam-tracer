"""Claim checker: "is this real or a scam?"

Paste a message, post, link or address. Returns red flags -- and, most
usefully, whether any address or domain in it is ALREADY known to belong to
the scam network you are tracking, an incident, or the radar.

It does not (cannot) certify anything as safe. The honest output is
"red flags found" or "no known red flags -- verify independently".
"""
import json
import re
from datetime import datetime, timezone

from .addresses import extract

PHRASES = [
    (r"\b(send|deposit)\b.{0,40}\b(receive|get)\b.{0,30}\b(back|double|2x|twice)\b", "Send-to-receive-double: the classic giveaway scam. No one gives away crypto this way."),
    (r"\b(2x|double your|doubled)\b", "Promises to double funds."),
    (r"\bgiveaway\b", "Crypto 'giveaway' -- almost always a scam."),
    (r"\b(seed|recovery|secret)\s*(phrase|words)\b|\bprivate key\b|\b12[- ]word|\b24[- ]word", "Asks about a seed phrase / private key. No legitimate company EVER asks for this."),
    (r"\b(connect|validate|verify|sync)\s+(your\s+)?wallet\b", "Asks you to 'connect / validate' your wallet -- common wallet-drainer lure."),
    (r"\b(refund|compensation|reimburse\w*|claim)\b", "Refund / compensation / claim offer. After hacks, fake refund sites appear within hours. Only trust announcements on the company's own verified site/app."),
    (r"\b(fee|tax|gas)\b.{0,40}\b(release|unlock|withdraw|recover)", "Pay a fee to release / recover funds -- the signature of recovery scams."),
    (r"\b(recover|retrieve)\b.{0,30}\b(lost|stolen|scammed)\b", "Offers to recover stolen crypto. Legitimate help (police, IC3, SEAL 911) is free and never guarantees recovery."),
    (r"\b(urgent|immediately|limited time|last chance|expires? (in|today))\b", "Pressure / urgency tactics."),
    (r"\bguarantee(d)?\b", "Guaranteed returns or recovery."),
    (r"\b(dm|whatsapp|telegram)\s+(me|us)\b", "Moves you to private messages."),
]
RISKY_TLD = {"xyz", "top", "click", "site", "online", "live", "vip", "icu", "buzz", "cfd", "sbs", "lol", "shop"}
_URL = re.compile(r"\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:/[^\s]*)?", re.I)


def _known():
    """address/domain -> what we know about it."""
    k = {}
    for path, why in (("scam_network.json", "in the scam NETWORK you are tracking"),
                      ("network_map.json", "on the path of the STOLEN funds")):
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            continue
        if d.get("root"):
            k[d["root"]] = "the primary SCAM WALLET"
        for a in d.get("nodes", {}):
            k.setdefault(a, why)
    try:
        from . import incident
        for r in incident.load()["addresses"]:
            k.setdefault(r["address"].lower() if r["chain"] == "ethereum" else r["address"],
                         f"an INCIDENT address ({r.get('label') or 'attacker'})")
    except Exception:
        pass
    return k


def check(text, lookup_cert=True, _first_cert=None):
    text = text or ""
    low = text.lower()
    flags, hits = [], []
    known = _known()
    for chain, a in extract(text):
        key = a.lower() if chain == "ethereum" else a
        if key in known:
            hits.append(f"{chain} address {a} is {known[key]}.")
        else:
            try:
                from . import intel
                for src, det in intel.check(a):
                    if src != "Your cases":
                        hits.append(f"{chain} address {a} is on a public scam/sanctions list: {src}.")
            except Exception:
                pass
    domains = []
    for m in _URL.finditer(text):
        dom = m.group(1).lower().strip(".")
        if dom.count(".") == 0 or re.fullmatch(r"[\d.]+", dom):
            continue
        domains.append(dom)
    for dom in dict.fromkeys(domains):
        base = ".".join(dom.split(".")[-2:])
        if dom in known or base in known:
            hits.append(f"Domain {dom} is {known.get(dom) or known.get(base)}.")
        try:
            from . import intel
            for src, det in intel.check(dom):
                if src != "Your cases":
                    hits.append(f"Domain {dom} is on a public phishing list: {src} ({det}).")
        except Exception:
            pass
        try:
            from .radar import load as _rl
            rd = _rl()["domains"].get(dom) or _rl()["domains"].get(base)
            if rd:
                flags.append(f"{dom}: flagged by the scam radar -- certificate issued {rd.get('cert_not_before')} for a brand + lure name.")
        except Exception:
            pass
        from .radar import score
        s, b, l = score(dom)
        if b and l:
            flags.append(f"{dom}: combines a brand ({', '.join(b)}) with a lure word ({', '.join(l)}) -- typical impersonation domain.")
        if "xn--" in dom:
            flags.append(f"{dom}: punycode (look-alike characters).")
        if dom.rsplit(".", 1)[-1] in RISKY_TLD:
            flags.append(f"{dom}: uses a low-cost TLD common in scam sites.")
        if lookup_cert:
            try:
                from .radar import first_cert
                fc = (_first_cert or first_cert)(base)
                if fc:
                    age = (datetime.now(timezone.utc).replace(tzinfo=None) - fc).days
                    if age <= 30:
                        flags.append(f"{dom}: its first HTTPS certificate is only {age} day(s) old (brand-new site).")
            except Exception:
                pass
    for rx, why in PHRASES:
        if re.search(rx, low):
            flags.append(why)
    flags = list(dict.fromkeys(flags))
    if hits:
        verdict = "KNOWN SCAM"
    elif len(flags) >= 2:
        verdict = "HIGH RISK"
    elif flags:
        verdict = "CAUTION"
    else:
        verdict = "NO KNOWN RED FLAGS"
    advice = ("Do not send funds or connect a wallet. Report it (Chainabuse) and add any addresses to Incident mode."
              if verdict in ("KNOWN SCAM", "HIGH RISK") else
              "Verify independently: type the company's address yourself, check its official app and verified accounts. "
              "No red flags here does not mean it is safe.")
    return {"verdict": verdict, "known": hits, "flags": flags, "advice": advice}


if __name__ == "__main__":
    import sys
    print(json.dumps(check(" ".join(sys.argv[1:]) or sys.stdin.read()), indent=1))
