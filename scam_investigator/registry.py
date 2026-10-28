"""Public scam registry on the XRP Ledger.

A registry is just an XRPL account you control. Each report is an AccountSet
transaction from that account carrying a small JSON memo. No XRP moves to
anyone (only the ~0.000012 XRP network fee is burned), and the record is
permanent and public. Anyone can check an address against your registry with
`registry check`, or read it from any explorer.

Your seed is read from the XRPL_REGISTRY_SEED environment variable at publish
time only. It is never written to disk or printed. Publishing is a dry run
unless you pass --submit.
"""
import json
import os
import time

from .ledger import Ledger, ripple_time

MEMO_TYPE = "scam-report/v1"
MAX_MEMO_BYTES = 900  # XRPL caps all memos on a transaction at 1 KB


def _hex(s):
    return s.encode("utf-8").hex().upper()


def build_record(address, domains=None, category="giveaway-scam", refs=None, note=None):
    rec = {"v": 1, "addr": address, "cat": category, "ts": int(time.time())}
    if domains:
        rec["dom"] = domains[:3]
    if refs:
        rec["ref"] = refs[:2]
    if note:
        rec["note"] = note[:160]
    data = json.dumps(rec, separators=(",", ":"))
    while len(data.encode()) > MAX_MEMO_BYTES and rec.get("note"):
        rec["note"] = rec["note"][:-20]
        data = json.dumps(rec, separators=(",", ":"))
    return rec, data


def publish(address, domains=None, category="giveaway-scam", refs=None, note=None, submit=False):
    rec, data = build_record(address, domains, category, refs, note)
    seed = os.environ.get("XRPL_REGISTRY_SEED")
    preview = {
        "TransactionType": "AccountSet",
        "Account": "<your registry account>",
        "Memos": [{"Memo": {"MemoType": _hex(MEMO_TYPE), "MemoFormat": _hex("application/json"), "MemoData": _hex(data)}}],
    }
    if not submit:
        return {"dry_run": True, "record": rec, "transaction": preview,
                "next": "Re-run with --submit and XRPL_REGISTRY_SEED set to publish."}
    if not seed:
        raise SystemExit("Set XRPL_REGISTRY_SEED in this terminal first (never paste it into a chat or a file).")
    try:
        from xrpl.clients import JsonRpcClient
        from xrpl.models.transactions import AccountSet, Memo
        from xrpl.transaction import submit_and_wait
        from xrpl.wallet import Wallet
    except ImportError:
        raise SystemExit("Publishing needs xrpl-py:  python -m pip install xrpl-py")
    wallet = Wallet.from_seed(seed)
    tx = AccountSet(account=wallet.address, memos=[Memo(memo_type=_hex(MEMO_TYPE),
                                                       memo_format=_hex("application/json"),
                                                       memo_data=_hex(data))])
    resp = submit_and_wait(tx, JsonRpcClient("https://xrplcluster.com/"), wallet)
    r = resp.result
    return {"dry_run": False, "record": rec, "registry_account": wallet.address,
            "hash": r.get("hash"), "result": (r.get("meta") or {}).get("TransactionResult")}


def _decode_memos(tx):
    out = []
    for m in tx.get("Memos", []) or []:
        memo = m.get("Memo", {})
        try:
            mtype = bytes.fromhex(memo.get("MemoType", "")).decode()
            if mtype != MEMO_TYPE:
                continue
            out.append(json.loads(bytes.fromhex(memo.get("MemoData", "")).decode()))
        except Exception:
            continue
    return out


async def read_registry(registry_account):
    async with Ledger() as L:
        txs = await L.account_tx(registry_account, forward=True)
    records = []
    for tx in txs:
        if tx.get("Account") != registry_account or tx.get("_meta", {}).get("TransactionResult") != "tesSUCCESS":
            continue
        for rec in _decode_memos(tx):
            rec["_tx"] = tx["hash"]
            rec["_time"] = ripple_time(tx.get("date"))
            records.append(rec)
    return records


async def check(address, registry_accounts):
    hits = []
    for reg in registry_accounts:
        for rec in await read_registry(reg):
            if rec.get("addr") == address or address in (rec.get("dom") or []):
                hits.append({**rec, "_registry": reg})
    return hits
