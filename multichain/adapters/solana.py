"""Solana adapter via public JSON-RPC (free, no API key).

Covers native SOL transfers and SPL token transfers (USDC/USDT on Solana are
freezable by Circle/Tether, so they become issuer-freeze opportunities like on
any other chain). Public RPC is rate-limited, so we page gently. Set
"solana_rpc" in config.json to use your own free endpoint (Helius, QuickNode...).
"""
import json
import time
import urllib.request

from ..core import Adapter, Transfer, iso_from_epoch

PUBLIC_RPC = "https://api.mainnet-beta.solana.com"
UA = {"User-Agent": "scam-investigator-multichain/1.0", "Content-Type": "application/json"}
SYMBOLS = {"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": "USDC",
           "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB": "USDT"}


def _endpoint():
    try:
        import scamconfig
        return (scamconfig.get("solana_rpc") or PUBLIC_RPC).strip()
    except Exception:
        return PUBLIC_RPC


def rpc(method, params, _post=None, retries=3):
    if _post:
        return _post(method, params)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(_endpoint(), data=body, headers=UA)
            with urllib.request.urlopen(req, timeout=30) as r:
                d = json.loads(r.read())
            if "error" in d:
                raise RuntimeError(d["error"].get("message"))
            return d.get("result")
        except Exception as e:
            last = e
            time.sleep(1.5 * (i + 1))      # public RPC 429s: back off
    raise last


def parse_transfers(tx, address=None, sig=None):
    """Transfers in a jsonParsed transaction (optionally only those FROM address)."""
    out = []
    if not tx or (tx.get("meta") or {}).get("err"):
        return out
    ep = tx.get("blockTime")
    sig = sig or (tx.get("transaction", {}).get("signatures") or [None])[0]
    meta = tx.get("meta") or {}
    # token account -> (owner, mint), from pre/post balances
    accts = tx.get("transaction", {}).get("message", {}).get("accountKeys", [])
    keys = [a.get("pubkey") if isinstance(a, dict) else a for a in accts]
    owner_of = {}
    for b in (meta.get("preTokenBalances") or []) + (meta.get("postTokenBalances") or []):
        try:
            owner_of[keys[b["accountIndex"]]] = (b.get("owner"), b.get("mint"))
        except Exception:
            pass
    ixs = list(tx.get("transaction", {}).get("message", {}).get("instructions", []))
    for inner in meta.get("innerInstructions") or []:
        ixs += inner.get("instructions", [])
    for ix in ixs:
        p = ix.get("parsed")
        if not isinstance(p, dict):
            continue
        info, typ, prog = p.get("info", {}), p.get("type"), ix.get("program")
        if prog == "system" and typ == "transfer":
            frm, to, amt, asset, mint = info.get("source"), info.get("destination"), (info.get("lamports") or 0) / 1e9, "SOL", None
        elif prog in ("spl-token", "spl-token-2022") and typ in ("transfer", "transferChecked"):
            src, dst = info.get("source"), info.get("destination")
            frm = info.get("authority") or info.get("multisigAuthority") or (owner_of.get(src) or (None,))[0]
            to = (owner_of.get(dst) or (None,))[0] or dst      # report the wallet that owns the token account
            mint = info.get("mint") or (owner_of.get(src) or owner_of.get(dst) or (None, None))[1]
            ta = info.get("tokenAmount") or {}
            amt = float(ta.get("uiAmount") or 0) if ta else None
            if amt is None:
                continue        # plain 'transfer' without decimals: amount unknown, skip
            asset = SYMBOLS.get(mint, (mint or "SPL")[:6])
        else:
            continue
        if address and frm != address:
            continue
        if not to or to == frm:
            continue
        out.append(Transfer(chain="solana", txid=sig, time=iso_from_epoch(ep), epoch=ep, frm=frm, to=to,
                            asset=asset, amount=amt, contract=mint))
    return out


class SolanaAdapter(Adapter):
    def outgoing(self, address, after_epoch=None, min_native=None, limit=200, _post=None):
        floor = self.info.min_native if min_native is None else min_native
        sigs = rpc("getSignaturesForAddress", [address, {"limit": 100}], _post) or []
        out = []
        for s in sigs:
            bt = s.get("blockTime")
            if after_epoch is not None and bt is not None and bt < after_epoch:
                continue
            if s.get("err"):
                continue
            tx = rpc("getTransaction", [s["signature"], {"encoding": "jsonParsed",
                                                        "maxSupportedTransactionVersion": 0}], _post)
            for t in parse_transfers(tx, address, s["signature"]):
                if t.asset == "SOL" and t.amount < floor:
                    continue
                out.append(t)
            if len(out) >= limit:
                break
            if not _post:
                time.sleep(0.25)
        return out
