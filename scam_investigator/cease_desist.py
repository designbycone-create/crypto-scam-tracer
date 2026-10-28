"""Generate a formal cease-and-desist / takedown + evidence-preservation letter
to a hosting provider, registrar, or network operator -- the same style as the
letter sent to the scam's host. Reusable for any future case where an IP,
domain, or abuse contact becomes available.

The letter is written in the victim's own voice as the injured party. It is NOT
dressed up as a law firm or any authority the sender does not have -- a hosting
abuse desk spots a fake letterhead instantly, whereas a precise demand from a
documented victim with law enforcement already involved is what gets action.
Every pressure point is real; it names no individual.
"""
import os
import re
from datetime import datetime


def _slug(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s or "")[:60]


def _refs(case):
    out = []
    if case.get("ic3_id"):
        out.append(f"the U.S. FBI Internet Crime Complaint Center (IC3), complaint {case['ic3_id']}")
    for r in case.get("reports", []):
        if "chainabuse" in r.lower():
            out.append("Chainabuse (" + r.split()[-1] + ")")
    return out


def generate(target, case=None, scam=None, deadline_hours=48, anonymous=True):
    """target: {org, abuse, ip, domain, network, country}.
    scam: {wallet, domain, victim_tx, total_xrp, victims_note}.
    case: victim.json contents (name, email, ic3_id, reports)."""
    case = case or {}
    scam = scam or {}
    org = target.get("org") or "the responsible provider"
    abuse = target.get("abuse") or "abuse contact"
    ip = target.get("ip") or ""
    domain = target.get("domain") or scam.get("domain") or ""
    network = target.get("network") or ""
    date = datetime.now().strftime("%d %B %Y")
    refs = _refs(case)
    refs_sentence = (" This matter is already filed with " + "; ".join(refs) + "."
                     if refs else "")
    wallet = scam.get("wallet") or ""
    total = scam.get("total_xrp")
    total_line = (f" The receiving wallet {wallet} collected roughly {total:,.0f} XRP from multiple "
                  f"victims." if wallet and total else (f" The receiving wallet is {wallet}." if wallet else ""))
    vtx = scam.get("victim_tx")
    tx_line = f" Documented victim transaction: {vtx}." if vtx else ""
    signer = ("A documented victim of the fraud carried on your infrastructure\n"
              "(Identity on record with the U.S. FBI / IC3; available on lawful request)"
              if anonymous else f"{case.get('name', '')}\n{case.get('email', '')}")

    text = f"""CEASE AND DESIST - DEMAND FOR TAKEDOWN AND PRESERVATION OF EVIDENCE

To: {org} - Abuse / Compliance ({abuse})
Re: Fraudulent service on your {'network' if network else 'infrastructure'}{(' - ' + domain) if domain else ''}{(' - IP ' + ip) if ip else ''}{(' (' + network + ')') if network else ''}
Date: {date}

To the responsible officers of {org},

This is formal written notice that your {'network' if network else 'infrastructure'} is being used to commit cryptocurrency fraud against the public. You are now on actual notice. This letter establishes the date and time from which your organization can no longer claim to be unaware.

1. The abuse. {('The website ' + domain) if domain else 'A service'}{(', resolving to ' + ip + ',') if ip else ''} hosted on your {'network' if network else 'infrastructure'} is being used to defraud victims of cryptocurrency through a fraudulent scheme (impersonation / fake giveaway).{total_line}{tx_line} This constitutes fraud and the laundering of criminally obtained assets.

2. Demands. You are required, without delay, to:
   (a) Suspend and remove the offending service{(' at ' + ip) if ip else ''}{(' serving ' + domain) if domain else ''}; and
   (b) Preserve, and not destroy, delete, or alter, the complete account records, registration data, payment records, and connection/access logs (including source IP addresses) of the responsible customer, pending lawful request.

3. Escalation and record.{refs_sentence} The complainant's identity is on record with those authorities. Your response, or your silence, from this moment forward will be recorded and furnished to law enforcement, including through international cooperation channels. Continued operation of this service after receipt of this notice removes any claim of good faith and bears directly on your organization's own exposure.

4. Deadline. I require written confirmation of receipt and of the action taken within {deadline_hours} hours of the time of this message.

Govern yourselves accordingly.

- {signer}
"""
    fname = f"cease_desist_{_slug(target.get('org') or target.get('ip') or domain or 'target')}.txt"
    return fname, text


def write(target, out_dir="cease_desist", case=None, scam=None, **kw):
    os.makedirs(out_dir, exist_ok=True)
    fname, text = generate(target, case=case, scam=scam, **kw)
    path = os.path.join(out_dir, fname)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path
