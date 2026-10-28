"""Known XRPL bridge / instant-swap services.

When stolen funds reach one of these, they may be converting to another asset
and LEAVING the XRP Ledger -- the forward trace ends here. These are flagged
distinctly from ordinary exchanges because the action and the timing differ:
non-custodial instant swaps often hold funds only briefly, so a freeze request
has to go out immediately, and many keep limited or no KYC. Contacts are
best-effort and MUST be verified before sending; where no direct compliance
email is known we point to the service's official site so the sender can find
its current abuse / compliance channel.
"""

# Keyed by a substring of the (lower-cased) xrpscan / labels.json label.
SWAP_SERVICES = {
    "changenow":  {"name": "ChangeNOW",  "email": "compliance@changenow.io",
                   "site": "https://changenow.io"},
    "changelly":  {"name": "Changelly",  "site": "https://changelly.com"},
    "simpleswap": {"name": "SimpleSwap", "site": "https://simpleswap.io"},
    "stealthex":  {"name": "StealthEX",  "site": "https://stealthex.io"},
    "sideshift":  {"name": "SideShift",  "site": "https://sideshift.ai"},
    "sologenic":  {"name": "Sologenic",  "site": "https://sologenic.org"},
    "gatehub":    {"name": "GateHub",    "site": "https://gatehub.net"},
}


def swap_info(label):
    """Return the swap-service record matching this address label, or None."""
    low = (label or "").lower()
    for key, rec in SWAP_SERVICES.items():
        if key in low:
            return rec
    return None
