"""Offline smoke test: Desk routes for shield/prescreen/sitewatch/evidence, case sealing from
Desk files, and dollar-at-risk ranking. No network.
    python -m evidence.test_desk_integration_offline
"""
import json
import os
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="sh_desk_")
os.chdir(TMP)
os.environ["SCAMHUNTER_EVIDENCE_DIR"] = os.path.join(TMP, "evidence_store")

from evidence import capture, corroborate, case  # noqa: E402
VICTIM, SCAM = "rVictimXXXXXXXXXXXXXXXXXXXXXXXXXX", "rwW2qTeD3dfk74bfURPrPAwfz2XADmocaN"
EXCH, TX1, TX2 = "rExchangeHotWalletXXXXXXXXXXXXXXX", "A" * 64, "B" * 64


def ledger(server, body):
    h = body["params"][0]["transaction"]
    tx = {TX1: {"Account": VICTIM, "Destination": SCAM, "Amount": "500000000", "ledger_index": 90000001},
          TX2: {"Account": SCAM, "Destination": EXCH, "Amount": "499000000", "DestinationTag": 1234567,
                "ledger_index": 90000050}}[h]
    tx = dict(tx, TransactionType="Payment", Fee="12", Sequence=7, date=800000000)
    return {"result": {"tx_json": tx, "hash": h, "ledger_index": tx["ledger_index"], "validated": True,
                       "meta": {"TransactionResult": "tesSUCCESS", "delivered_amount": tx["Amount"]}}}
capture.STORE = os.environ["SCAMHUNTER_EVIDENCE_DIR"]
capture._state.update(seq=None, prev=None)
os.chdir(TMP)

passed = failed = 0


def ok(c, m):
    global passed, failed
    print(("PASS " if c else "FAIL ") + m)
    passed, failed = passed + bool(c), failed + (not c)


# --- dollar at risk
from shield import value, evm  # noqa: E402
value.PRICE_GET = lambda keys: {k: 1.0 for k in keys if "dac17" in k}
evm.RPC_POST = lambda chain, m, p: hex(250 * 10**6) if p[0]["data"].startswith("0x70a08231") else hex(6)
res = {"chains": {"ethereum": [
    {"kind": "erc20", "token": "0xdac17f958d2ee523a2206206994597c13d831ec7", "unlimited": True, "amount": None, "risk": "high"},
    {"kind": "erc20", "token": "0x1111111111111111111111111111111111111111", "unlimited": True, "amount": None, "risk": "danger"},
    {"kind": "erc20", "token": "0xdac17f958d2ee523a2206206994597c13d831ec7", "unlimited": False, "amount": 10.0, "risk": "high"}]}}
value.enrich(res, "0x" + "2" * 40)
rows = res["chains"]["ethereum"]
ok(rows[0]["risk"] == "danger" and rows[0]["usd_at_risk"] is None, "danger first; unknown price stays unknown, not $0")
ok(rows[1]["usd_at_risk"] == 250.0 and rows[2]["usd_at_risk"] == 10.0, "unlimited exposes full balance; capped allowance exposes the cap")
ok(res["usd_at_risk"] == 260.0, "total dollars at risk")
evm.RPC_POST = None

# --- seal a case from the Desk's own files
json.dump({"tx_hash": TX1, "scam_wallet": "rwW2qTeD3dfk74bfURPrPAwfz2XADmocaN", "ic3_id": "TEST"}, open("victim.json", "w"))
with open("cashouts.jsonl", "w") as f:
    f.write(json.dumps({"address": EXCH, "label": "ExampleExchange", "destination_tag": 1234567, "hash": TX2,
                        "detected": "2026-10-01 10:00:00"}) + "\n")
corroborate.POST = ledger
r = case.seal("Test Examiner", log=lambda *_: None)
ok(r["counts"] == {"FACT": 2, "DERIVED": 1, "INFERENCE": 1}, f"sealed from Desk files: {r['counts']}")
rep = open(os.path.join(r["dir"], "report.md"), encoding="utf-8").read()
ok("ExampleExchange" in rep and "destination tag 1234567" in rep and "tracing convention" in rep,
   "report names the exchange as an inference and states the tracing convention")

# --- desk routes
import desk  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402
srv = ThreadingHTTPServer(("127.0.0.1", 0), desk.Handler)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()


def get(path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=20) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


for pth, needle in [("/shield", "Wallet shield"), ("/prescreen", "send"), ("/sitewatch", "Sites I use"),
                    ("/compromised", "Compromised"), ("/evidence", "Court evidence bundle")]:
    try:
        st, body = get(pth)
        ok(st == 200 and needle.lower() in body.lower(), f"GET {pth}")
    except Exception as ex:
        ok(False, f"GET {pth}: {ex!r}")

# background check: first hit shows "checking", later hit shows the result
from shield import approvals  # noqa: E402
approvals.scan = lambda w, chains=None, log=print: (time.sleep(1), {"wallet": w, "chains": {}, "summary": {}, "notes": [],
                                                                  "takeover": [], "usd_at_risk": 0})[1]
st, b1 = get("/shield?wallet=0x" + "3" * 40 + "&mode=check")
time.sleep(2)
st, b2 = get("/shield?wallet=0x" + "3" * 40 + "&mode=check")
ok("Checking your wallet" in b1 and "Open approvals" in b2, "slow wallet check runs in background, then shows result")
srv.shutdown()

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
