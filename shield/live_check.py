"""LIVE smoke test against real chains (needs internet). Read-only.
    python shield/live_check.py
"""
import os, sys, time, traceback
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shield import approvals, drain, prescreen, sitewatch, evm

CASES = [
    ("approvals", "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", ["ethereum"]),
    ("approvals", "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", ["base", "arbitrum", "polygon", "optimism", "avalanche", "bsc"]),
    ("drain", "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", ["polygon"]),
    ("prescreen", "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", None),
    ("approvals", "TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TWc32G", None),
    ("prescreen", "TNXoiAJ3dct8Fjg4M9fkLFh9S2v9TWc32G", None),
    ("approvals", "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM", None),
    ("prescreen", "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM", None),
    ("approvals", "rwW2qTeD3dfk74bfURPrPAwfz2XADmocaN", None),
    ("prescreen", "rwW2qTeD3dfk74bfURPrPAwfz2XADmocaN", None),
    ("prescreen", "rM27yzkCw6WA3T4g1sPaeC1kpxHUhuxRWn", None),
    ("prescreen", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", None),
]
only = sys.argv[1:]
for i, (kind, addr, chains) in enumerate(CASES):
    if only and str(i) not in only:
        continue
    t0 = time.time()
    try:
        if kind == "approvals":
            r = approvals.scan(addr, chains)
            items = [a for v in r["chains"].values() for a in v]
            msg = (f"family={r.get('family')} items={len(items)} summary={r.get('summary')} takeover={len(r.get('takeover', []))} "
                   f"errors={r.get('errors')} notes={len(r.get('notes', []))}")
            if items:
                a = items[0]
                msg += f" | first: {a['chain']} {a['kind']} {a['symbol']} -> {a['spender'][:12]} {a['risk']}"
        elif kind == "drain":
            r = drain.analyze(addr, chains)
            msg = f"drains={len(r['drains'])} receivers={len(r['receivers'])} notes={r.get('notes')}"
        else:
            r = prescreen.screen(addr)
            msg = (f"chain={r.get('chain')} verdict={r.get('verdict')} moves={r.get('stats', {}).get('movements')} | "
                   + "; ".join(f"[{f['level']}] {f['text'][:70]}" for f in r.get("findings", [])[:5]))
        print(f"[{i}] OK  {kind:9} {addr[:12]}  {time.time()-t0:5.1f}s  {msg}", flush=True)
    except Exception as e:
        print(f"[{i}] ERR {kind:9} {addr[:12]}  {time.time()-t0:5.1f}s  {e!r}", flush=True)
        traceback.print_exc(limit=2)
if not only or "site" in only:
    for dom in ("app.uniswap.org", "pickle.finance"):
        t0 = time.time()
        try:
            s = sitewatch.snapshot(dom)
            print(f"[site] OK {dom} {time.time()-t0:.1f}s ns={s['ns']} a={len(s['a'] or [])} registrar={(s['rdap'] or {}).get('registrar')} "
                  f"locked={(s['rdap'] or {}).get('locked')} issuers={(s['certs'] or {}).get('issuers')} scripts={len(s['scripts'] or {})}", flush=True)
        except Exception as e:
            print(f"[site] ERR {dom} {e!r}", flush=True)
