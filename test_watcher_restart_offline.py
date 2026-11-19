"""Offline test: the wallet watcher alerts on an old scam-wallet transaction once, not after every restart.
    python test_watcher_restart_offline.py
"""
import asyncio, os, shutil, sys, tempfile
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
WORK = tempfile.mkdtemp(prefix="sh_watch_")
os.chdir(WORK)
import xrpl_watcher as W  # noqa: E402

ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []
SCAM = "rLrDarYHqNJnZwxuRXXuR1HHrBJKL7gbkm"
HIST = {"result": {"transactions": [{"hash": "AA" * 32, "validated": True, "meta": {},
         "tx_json": {"Account": SCAM, "Destination": "rNkdwsUbCfRbsArmkpmKLiykTgS2DoVqUf", "TransactionType": "Payment", "Amount": "6070749896"}}]}}

async def fake_rpc(ws, req):
    return {"result": {"account_data": {"Balance": "1000000"}}} if req["command"] == "account_info" else HIST

alerts = []
W.rpc = fake_rpc
W.handle_tx = lambda tx, meta, validated, src: alerts.append(tx["hash"])
W.WATCHED.clear(); W.WATCHED[SCAM] = "scam wallet"
W.print = lambda *a, **k: None

async def start():                     # what one Desk start does: load memory, take the snapshot
    seen = W.load_seen()
    await W.snapshot(None, seen)

asyncio.run(start())
r.append(ok(alerts == ["AA" * 32], "first start: the scam wallet's outgoing payment is alerted"))
asyncio.run(start())
asyncio.run(start())
r.append(ok(alerts == ["AA" * 32], "two restarts later: no repeat pop-ups for the same payment"))
HIST["result"]["transactions"].append({"hash": "BB" * 32, "validated": True, "meta": {},
    "tx_json": {"Account": SCAM, "Destination": "rX", "TransactionType": "Payment", "Amount": "1"}})
asyncio.run(start())
r.append(ok(alerts == ["AA" * 32, "BB" * 32], "a NEW payment made while the Desk was off is still alerted"))
os.chdir(ROOT); shutil.rmtree(WORK, ignore_errors=True)
print(f"{sum(r)}/{len(r)} passed"); sys.exit(0 if all(r) else 1)
