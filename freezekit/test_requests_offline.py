"""Offline test: exchange request kits and stablecoin freeze packets (no network).
    python freezekit/test_requests_offline.py
"""
import csv, json, os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(tempfile.mkdtemp())
json.dump({"tx_hash": "A" * 64, "scam_wallet": "rwW2qTeD3dfk74bfURPrPAwfz2XADmocaN", "ic3_id": "41abab4b"}, open("victim.json", "w"))
from freezekit import requests as rq
import subprocess
ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []
chan = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "channels.json")))
okx = {"id": "okx", "entry": chan["exchanges"]["okx"], "yours": True, "deposits": [
    {"chain": "xrpl", "address": "rs2dgzYeqYqsk8bvkQR5YPyqsXYcA24MP2", "tag": 742451, "amount": 10054.9, "asset": "XRP",
     "time": "2026-10-29 11:10:51 UTC", "hash": "3673D7B22664F0D3C05F9726EAB77DE4B193FEF66A542DFCDEBD1675F5D013B8", "yours": True}]}
pdf, csvp = rq.exchange_kit(okx)
txt = subprocess.run(["pdftotext", pdf, "-"], capture_output=True, text=True).stdout if os.system("which pdftotext >/dev/null") == 0 else ""
r.append(ok(os.path.exists(pdf) and os.path.getsize(pdf) > 2000, "exchange kit PDF written"))
rows = list(csv.reader(open(csvp)))
r.append(ok(rows[1][1] == "rs2dgzYeqYqsk8bvkQR5YPyqsXYcA24MP2" and rows[1][2] == "742451", "CSV lists address, tag and hash (exchanges ask for a copyable file)"))
if txt:
    r.append(ok("app.kodexglobal.com/okx" in txt and "verified 2026-11-01" in txt, "routing shows only the verified OKX channel, with its source"))
    r.append(ok("Attachment A" in txt and "742451" in txt and "preserve" in txt, "draft preservation request and records list include the case facts"))
unk = {"id": "svc-x", "entry": {"name": "SomeExchange"}, "deposits": okx["deposits"]}
pdf2, _ = rq.exchange_kit(unk)
t2 = subprocess.run(["pdftotext", pdf2, "-"], capture_output=True, text=True).stdout if txt else ""
if txt:
    r.append(ok("has been verified by ScamHunter yet" in t2 and "impersonate" in t2, "unverified exchange: no guessed address, warns about impersonators"))
rows_t = [{"chain": "tron", "address": "TXyz", "token_contract": rq.TOKENS["tether"]["tron"], "balance": 12500.0, "error": None},
          {"chain": "ethereum", "address": "0xabc", "token_contract": rq.TOKENS["tether"]["ethereum"], "balance": 0.0, "error": None}]
p, held = rq.stablecoin_packet("tether", rows=rows_t)
t3 = subprocess.run(["pdftotext", p, "-"], capture_output=True, text=True).stdout if txt else ""
r.append(ok(len(held) == 1, "packet lists only addresses actually holding USDT"))
if txt:
    r.append(ok("12,500.00" in t3 and "a victim" in t3 and "not verified by ScamHunter" in t3, "Tether packet: balances, who can request, no guessed channel"))
p2, _ = rq.stablecoin_packet("circle", rows=[])
t4 = subprocess.run(["pdftotext", p2, "-"], capture_output=True, text=True).stdout if txt else ""
if txt:
    r.append(ok("court order" in t4 and "No USDC found" in t4, "Circle packet: says a court order is usually needed; handles none held"))
print(f"{sum(r)}/{len(r)} passed")
sys.exit(0 if all(r) else 1)
