"""Offline test: Litecoin support (Esplora API shapes, same as mempool.space).
    python shield/test_litecoin_offline.py
"""
import os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(tempfile.mkdtemp())
from responder.addresses import extract
from freezekit.chainlookup import detect_address
from shield import prescreen, approvals
ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []
A = "LNz6qoXAu5XMvJVhNApjq7uz9wRnnN8jvk"      # from OKX's published reserve list
B = "MQd1fJwqBJvwLuyhr17PhEFx1swiqDbPQS"
r.append(ok(extract(f"pay {A} now") == [("litecoin", A)], "Litecoin L-address detected (checksum validated)"))
r.append(ok(extract("LNz6qoXAu5XMvJVhNApjq7uz9wRnnN8jvj") == [], "bad checksum rejected"))
r.append(ok(detect_address(A) == ["litecoin"] and approvals.family(A)[0] == "litecoin", "routed as Litecoin"))
now = int(time.time())
seen = []
def get(url):
    seen.append(url)
    if url.endswith(f"/address/{A}"):
        return {"chain_stats": {"tx_count": 2}}
    if url.endswith(f"/address/{A}/txs"):
        return [{"txid": "t1", "status": {"block_time": now - 100}, "vin": [{"prevout": {"scriptpubkey_address": B}}],
                 "vout": [{"scriptpubkey_address": A, "value": 250_000_000}]},
                {"txid": "t2", "status": {"block_time": now - 50}, "vin": [{"prevout": {"scriptpubkey_address": A}}],
                 "vout": [{"scriptpubkey_address": B, "value": 240_000_000}]}]
    return {}
prescreen._get = get
h = prescreen.history_btc(A, "litecoin")
r.append(ok(all("litecoinspace.org" in u for u in seen) and {m["asset"] for m in h["moves"]} == {"LTC"} and h["complete"],
            "history read from litecoinspace.org, amounts in LTC"))
p = prescreen.screen(A)
r.append(ok(p["ok"] and p["chain"] == "litecoin", f"pre-screen runs on Litecoin ({p['verdict']})"))
from multichain.registry import get_adapter
from multichain import util
util_http = util.http_json
import multichain.adapters.btc as btc
btc.http_json = lambda url, **k: get(url)
outs = get_adapter("litecoin").outgoing(A)
r.append(ok(len(outs) == 1 and outs[0].asset == "LTC" and outs[0].to == B and outs[0].chain == "litecoin", "tracer follows Litecoin payments"))
print(f"{sum(r)}/{len(r)} passed")
sys.exit(0 if all(r) else 1)
