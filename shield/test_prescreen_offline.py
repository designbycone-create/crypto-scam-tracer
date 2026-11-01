"""Offline test for shield.prescreen (simulated XRPL history, no network): python shield/test_prescreen_offline.py"""
import json, os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(tempfile.mkdtemp())
from shield import prescreen, compromised, web
import scam_investigator.attribution as A
A._xrpscan = lambda a: None
now = int(time.time()); RE = 946684800
SCAM = "rwW2qTeD3dfk74bfURPrPAwfz2XADmocaN"      # collector + pass-through
EXCH = "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De"      # requires dest tag
ME = "rUrYCcn3UkgC2ZXDWDvWT1D8VmM2X5Yiws"
PAST = "rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh"      # someone I paid before
victims = [f"rVictim{i:02d}" for i in range(25)]
def rpc(method, p):
    a = p.get("account")
    if method == "account_info":
        if a == "rrrrrrrrrrrrrrrrrrrrrhoLvTp": return {}
        return {"account_data": {"Balance": "1500000" if a == SCAM else "90000000000",
                                 "Flags": 0x00020000 if a == EXCH else 0}}
    txs = []
    if a == SCAM:
        for i, v in enumerate(victims):
            t = now - 3 * 86400 + i * 3600
            txs.append({"tx_json": {"TransactionType": "Payment", "Account": v, "Destination": SCAM, "date": t - RE},
                        "meta": {"TransactionResult": "tesSUCCESS", "delivered_amount": str(500 * 10**6)}})
            txs.append({"tx_json": {"TransactionType": "Payment", "Account": SCAM, "Destination": "rHub1", "date": t + 900 - RE},
                        "meta": {"TransactionResult": "tesSUCCESS", "delivered_amount": str(495 * 10**6)}})
    if a == ME:
        txs.append({"tx_json": {"TransactionType": "Payment", "Account": ME, "Destination": PAST, "date": now - 90 * 86400 - RE},
                    "meta": {"TransactionResult": "tesSUCCESS", "delivered_amount": "1000000"}})
    return {"transactions": txs}
prescreen.XRPL_RPC = rpc
compromised.add("drainer hub rHub1xxxx", "test")  # not a valid address; ensures no crash
def show(r):
    print(r["verdict"], "|", "; ".join(f"[{f['level']}] {f['text'][:70]}" for f in r["findings"]))
show(prescreen.screen(SCAM))
show(prescreen.screen(EXCH))
show(prescreen.screen(EXCH, tag="12345"))
LOOK = PAST[:4] + "Q" * (len(PAST) - 8) + PAST[-4:]
# poisoning: a vanity lookalike of an address I paid before (checked directly; vanity addresses are valid on-chain)
for lvl, txt in prescreen.mistakes(LOOK, "xrpl", {"exists": True}, None, ME, prescreen.history_xrpl(ME)):
    print("POISONING CHECK:", lvl, txt[:90])
show(prescreen.screen("rrrrrrrrrrrrrrrrrrrrrhoLvTp"))
print(prescreen.screen("not-an-address"))
html = web.prescreen_page({"address": SCAM}, prescreen.screen(SCAM))
print("page ok", len(html), "log lines", sum(1 for _ in open(prescreen.LOG)))
json.dump({"wallet_group": {SCAM: "Operator A"}}, open("operators.json", "w"))
show(prescreen.screen(SCAM))
open(os.environ.get("PRESCREEN_HTML", os.devnull), "w").write(web.prescreen_page({"address": SCAM}, prescreen.screen(SCAM)))
