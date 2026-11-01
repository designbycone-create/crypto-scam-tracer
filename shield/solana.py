"""Solana support for shield (public JSON-RPC, key-less; set "solana_rpc" in
config.json for a faster free endpoint).

  approvals  SPL token-account DELEGATES (Solana's version of an approval)
  takeover   wallet account reassigned to a program ("Assign" drainer trick),
             token accounts whose close authority is someone else
  drains     recent transactions where the wallet's tokens/SOL went out but
             the wallet did NOT sign (a delegate or hijacked authority did)
  history    normalized movements for the pre-screen
"""
SYSTEM = "11111111111111111111111111111111"
TOKEN_PROGRAMS = ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"]
U64_MAX = 18446744073709551615
SYMBOLS = {"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": "USDC", "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB": "USDT"}

RPC = None   # test hook: f(method, params) -> result


def _personal():
    """A personal endpoint (Helius etc.) allows far more requests than the public RPC."""
    try:
        import scamconfig
        return bool((scamconfig.get("solana_rpc") or "").strip())
    except Exception:
        return False


def rpc(method, params):
    if RPC:
        return RPC(method, params)
    from multichain.adapters.solana import rpc as _rpc
    return _rpc(method, params)


def token_accounts(wallet):
    out = []
    for prog in TOKEN_PROGRAMS:
        try:
            r = rpc("getTokenAccountsByOwner", [wallet, {"programId": prog}, {"encoding": "jsonParsed"}]) or {}
        except Exception:
            continue
        for acc in r.get("value", []):
            info = (((acc.get("account") or {}).get("data") or {}).get("parsed") or {}).get("info") or {}
            info["_pubkey"] = acc.get("pubkey")
            out.append(info)
    return out


def approvals(wallet):
    out = []
    for info in token_accounts(wallet):
        dlg = info.get("delegate")
        if not dlg:
            continue
        da = info.get("delegatedAmount") or {}
        bal = info.get("tokenAmount") or {}
        raw = int(da.get("amount") or 0)
        mint = info.get("mint")
        out.append({"chain": "solana", "kind": "spl_delegate", "token": mint, "symbol": SYMBOLS.get(mint, "SPL token"),
                    "spender": dlg, "amount": None if raw >= U64_MAX // 2 else da.get("uiAmount"),
                    "unlimited": raw >= U64_MAX // 2 or raw >= int(bal.get("amount") or 0) > 0,
                    "spender_is_contract": None, "token_account": info.get("_pubkey"),
                    "revoke": f"https://solscan.io/account/{info.get('_pubkey')}",
                    "revoke_hint": "Revoke the delegate in your wallet (Phantom/Solflare security settings) or with a Solana "
                                   "token-approval revoker; Solana dApps rarely need a standing delegate."})
    return out


def takeover(wallet):
    found = []
    acct = (rpc("getAccountInfo", [wallet, {"encoding": "jsonParsed"}]) or {}).get("value")
    if acct and acct.get("owner") and acct["owner"] != SYSTEM:
        found.append(("danger", f"Your wallet account is now owned by program {acct['owner']} instead of the System Program "
                                "-- the 'Assign' drainer trick. Treat this wallet as lost; move anything you still can."))
    foreign = [(i.get("_pubkey"), i.get("closeAuthority")) for i in token_accounts(wallet)
               if i.get("closeAuthority") and i.get("closeAuthority") != wallet]
    if foreign:
        who = sorted({ca for _, ca in foreign})
        found.append(("high", f"{len(foreign)} token account(s) can be closed by someone other than you "
                              f"({', '.join(who[:3])}{'...' if len(who) > 3 else ''}). Normal wallets have none; "
                              "if you didn't set this up, move those tokens."))
    return found


def _tx(sig):
    import time as _t
    if RPC is None:
        _t.sleep(0.08 if _personal() else 0.35)   # the free public RPC rate-limits hard; pace requests
    try:
        return rpc("getTransaction", [sig, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}])
    except Exception:
        return None


def _deltas(tx, wallet):
    """(signed_by_wallet, sol_delta, token_deltas{mint: (delta, {owner: delta})})"""
    msg = (tx.get("transaction") or {}).get("message") or {}
    keys = msg.get("accountKeys") or []
    signers = {k.get("pubkey") for k in keys if isinstance(k, dict) and k.get("signer")}
    meta = tx.get("meta") or {}
    sol = 0.0
    for i, k in enumerate(keys):
        if (k.get("pubkey") if isinstance(k, dict) else k) == wallet:
            sol = ((meta.get("postBalances") or [0])[i] - (meta.get("preBalances") or [0])[i]) / 1e9
    tok = {}
    pre = {(b.get("accountIndex"), b.get("mint")): b for b in meta.get("preTokenBalances") or []}
    post = {(b.get("accountIndex"), b.get("mint")): b for b in meta.get("postTokenBalances") or []}
    for key in set(pre) | set(post):
        a, b = pre.get(key) or {}, post.get(key) or {}
        owner = b.get("owner") or a.get("owner")
        amt = float((b.get("uiTokenAmount") or {}).get("uiAmount") or 0) - float((a.get("uiTokenAmount") or {}).get("uiAmount") or 0)
        d = tok.setdefault(key[1], [0.0, {}])
        d[1][owner] = d[1].get(owner, 0.0) + amt
        if owner == wallet:
            d[0] += amt
    return wallet in signers, sol, tok


def drains(wallet, limit=None):
    limit = limit or (100 if _personal() else 25)
    out = []
    sigs = rpc("getSignaturesForAddress", [wallet, {"limit": limit}]) or []
    for s in sigs:
        if s.get("err"):
            continue
        tx = _tx(s["signature"])
        if not tx:
            continue
        signed, sol, tok = _deltas(tx, wallet)
        if signed:
            continue
        lost = [(m, d) for m, d in tok.items() if d[0] < 0]
        if not lost and sol >= 0:
            continue
        tokens, receivers = [], {}
        for mint, (delta, owners) in lost:
            tokens.append({"token": mint, "symbol": SYMBOLS.get(mint, "SPL token"), "amount": -delta, "to": None})
            for o, v in owners.items():
                if v > 0 and o != wallet:
                    receivers[o] = receivers.get(o, 0) + v
        if sol < 0:
            tokens.append({"token": None, "symbol": "SOL", "amount": -sol, "to": None})
        keys = ((tx.get("transaction") or {}).get("message") or {}).get("accountKeys") or []
        signer = next((k.get("pubkey") for k in keys if isinstance(k, dict) and k.get("signer")), None)
        out.append({"chain": "solana", "hash": s["signature"], "time": s.get("blockTime") or tx.get("blockTime"),
                    "tokens": tokens, "tx_sender": signer, "drainer_contract": signer, "receivers": receivers})
    return out


def history(addr, limit=None):
    limit = limit or (200 if _personal() else 30)
    acct = None
    try:
        acct = (rpc("getAccountInfo", [addr, {"encoding": "jsonParsed"}]) or {}).get("value")
    except Exception:
        pass
    sigs = rpc("getSignaturesForAddress", [addr, {"limit": limit}]) or []
    moves = []
    for s in sigs[:limit]:
        if s.get("err"):
            continue
        tx = _tx(s["signature"])
        if not tx:
            continue
        _, sol, tok = _deltas(tx, addr)
        t = s.get("blockTime") or tx.get("blockTime") or 0
        keys = ((tx.get("transaction") or {}).get("message") or {}).get("accountKeys") or []
        others = [k.get("pubkey") for k in keys if isinstance(k, dict) and k.get("pubkey") not in (addr, SYSTEM)]
        if abs(sol) > 0.001:
            moves.append({"dir": "in" if sol > 0 else "out", "cp": others[0] if others else None,
                          "amount": abs(sol), "asset": "SOL", "t": t})
        for mint, (delta, owners) in tok.items():
            if abs(delta) > 0:
                cp = next((o for o, v in owners.items() if o != addr and (v > 0) != (delta > 0)), None)
                moves.append({"dir": "in" if delta > 0 else "out", "cp": cp, "amount": abs(delta),
                              "asset": SYMBOLS.get(mint, "SPL"), "t": t})
    bal = ((acct or {}).get("lamports") or 0) / 1e9 if acct else 0.0
    return {"exists": bool(acct) or bool(sigs), "moves": moves, "balance": bal,
            "complete": len(sigs) < limit,
            "coverage": None if len(sigs) < limit else (
                f"Solana: last {limit} transactions reviewed; older activity wasn't checked." if _personal() else
                f"Solana: last {limit} transactions reviewed (public RPC is rate-limited; set \"solana_rpc\" to a free "
                "Helius/QuickNode endpoint for more).")}
