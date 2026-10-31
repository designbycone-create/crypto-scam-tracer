"""XRP Ledger support for shield.

The XRPL has no ERC-20-style approvals. What a drainer gets a victim to sign
instead (usually through a fake "connect / claim" sign request in Xaman):
  SetRegularKey   gives the attacker a key that can sign for the account
  SignerListSet   adds attacker signers (multi-sig takeover)
  CheckCreate     lets the destination cash up to SendMax
  NFT sell offer  for 0, or to a specific destination
  PaymentChannel  lets the destination claim funds
We list every such standing permission, flag it, and find payments that
happened after a takeover.
"""
LSF_DISABLE_MASTER = 0x00100000
RPC = None   # test hook: f(method, params) -> result


def rpc(method, params):
    if RPC:
        return RPC(method, params)
    from scam_investigator.attribution import _rpc
    return _rpc(method, params)


def _drops(v):
    return int(v) / 1e6 if isinstance(v, str) else float((v or {}).get("value", 0)) if isinstance(v, dict) else None


def _objects(wallet):
    out, marker = [], None
    for _ in range(5):
        p = {"account": wallet, "ledger_index": "validated", "limit": 400}
        if marker:
            p["marker"] = marker
        r = rpc("account_objects", p) or {}
        out += r.get("account_objects", [])
        marker = r.get("marker")
        if not marker:
            break
    return out


HINT = ("Remove it with a SetRegularKey / SignerListSet / CheckCancel / NFTokenCancelOffer / PaymentChannelClaim(close) "
        "transaction from Xaman or another XRPL wallet -- if your master key still works.")


def approvals(wallet):
    info = (rpc("account_info", {"account": wallet, "ledger_index": "validated"}) or {}).get("account_data") or {}
    out = []
    link = f"https://livenet.xrpl.org/accounts/{wallet}"
    if info.get("RegularKey"):
        out.append({"chain": "xrpl", "kind": "regular_key", "token": None, "symbol": "whole account",
                    "spender": info["RegularKey"], "amount": None, "unlimited": True, "spender_is_contract": None,
                    "master_disabled": bool(int(info.get("Flags") or 0) & LSF_DISABLE_MASTER),
                    "revoke": link, "revoke_hint": HINT})
    for o in _objects(wallet):
        t = o.get("LedgerEntryType")
        if t == "SignerList":
            for s in o.get("SignerEntries", []):
                e = s.get("SignerEntry", {})
                out.append({"chain": "xrpl", "kind": "signer", "token": None, "symbol": "whole account (multi-sig)",
                            "spender": e.get("Account"), "amount": None, "unlimited": True, "spender_is_contract": None,
                            "revoke": link, "revoke_hint": HINT})
        elif t == "Check" and o.get("Account") == wallet:
            amt = o.get("SendMax")
            out.append({"chain": "xrpl", "kind": "check", "token": None,
                        "symbol": "XRP" if isinstance(amt, str) else (amt or {}).get("currency"), "spender": o.get("Destination"),
                        "amount": _drops(amt), "unlimited": False, "spender_is_contract": None, "revoke": link, "revoke_hint": HINT})
        elif t == "PayChannel" and o.get("Account") == wallet:
            out.append({"chain": "xrpl", "kind": "pay_channel", "token": None, "symbol": "XRP", "spender": o.get("Destination"),
                        "amount": (int(o.get("Amount", 0)) - int(o.get("Balance", 0))) / 1e6, "unlimited": False,
                        "spender_is_contract": None, "revoke": link, "revoke_hint": HINT})
        elif t == "NFTokenOffer" and o.get("Owner") == wallet and int(o.get("Flags") or 0) & 1:   # sell offer
            amt = _drops(o.get("Amount"))
            if amt == 0 or o.get("Destination"):
                out.append({"chain": "xrpl", "kind": "nft_offer", "token": o.get("NFTokenID"), "symbol": "NFT",
                            "spender": o.get("Destination") or "anyone", "amount": amt, "unlimited": amt == 0,
                            "spender_is_contract": None, "revoke": link, "revoke_hint": HINT})
    return out


def takeover(wallet):
    found = []
    info = (rpc("account_info", {"account": wallet, "ledger_index": "validated"}) or {}).get("account_data") or {}
    flags = int(info.get("Flags") or 0)
    if info.get("RegularKey") and flags & LSF_DISABLE_MASTER:
        found.append(("danger", f"Master key is DISABLED and {info['RegularKey']} holds the regular key: whoever has that key "
                                "controls this account. If that isn't you, the account has been taken over."))
    elif info.get("RegularKey"):
        found.append(("high", f"A regular key is set ({info['RegularKey']}): it can sign for this account. If you didn't set it, "
                              "remove it now with your master key."))
    return found


def drains(wallet, limit=200):
    """Payments, check cashes and NFT sales after a key/signer change -- and by others cashing your checks."""
    r = rpc("account_tx", {"account": wallet, "ledger_index_min": -1, "ledger_index_max": -1, "limit": limit, "forward": False}) or {}
    takeover_at, out = None, []
    for t in reversed(r.get("transactions", [])):     # oldest -> newest
        tx = t.get("tx_json") or t.get("tx") or {}
        meta = t.get("meta") or {}
        if meta.get("TransactionResult") != "tesSUCCESS":
            continue
        typ = tx.get("TransactionType")
        ep = (tx.get("date") or 0) + 946684800
        if typ in ("SetRegularKey", "SignerListSet") and tx.get("Account") == wallet and takeover_at is None:
            takeover_at = ep
        cashed_by_other = typ in ("CheckCash", "NFTokenAcceptOffer", "PaymentChannelClaim") and tx.get("Account") != wallet
        outgoing = typ == "Payment" and tx.get("Account") == wallet and takeover_at is not None
        if not (cashed_by_other or outgoing):
            continue
        amt = meta.get("delivered_amount", tx.get("Amount"))
        to = tx.get("Destination") if outgoing else tx.get("Account")
        out.append({"chain": "xrpl", "hash": tx.get("hash") or t.get("hash"), "time": ep,
                    "tokens": [{"token": None, "symbol": "XRP" if isinstance(amt, str) or amt is None else amt.get("currency"),
                                "amount": _drops(amt) or 0.0, "to": to}],
                    "tx_sender": tx.get("Account"), "drainer_contract": to, "receivers": {to: 1},
                    "why": "after a key/signer change" if outgoing else f"{typ} by another account"})
    return out
