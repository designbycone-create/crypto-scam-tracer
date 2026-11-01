"""Offline test: shield on every chain family (simulated data, no network).
    python shield/test_allchains_offline.py
"""
import os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(tempfile.mkdtemp())
from shield import evm, approvals, drain, prescreen, tron, solana, xrpl
from responder.addresses import b58check_encode
ok = lambda c, msg: print(("PASS " if c else "FAIL ") + msg) or bool(c)
results = []
now = int(time.time())

# ---------------- Avalanche via the key-less RPC log window (BNB has no free endpoint) ----------------
V = "0x1111111111111111111111111111111111111111"; BAD = "0x5555555555555555555555555555555555555555"
TOK = "0x55d398326f99059ff775485246999027b3197955"; RCV = "0x7777777777777777777777777777777777777777"
def bsc_rpc(chain, method, p):
    if chain != "avalanche":
        if method in ("eth_getTransactionCount", "eth_getBalance"): return "0x0"
        if method == "eth_blockNumber": return hex(10_000_000)
        if method == "eth_getLogs": return []
        return "0x"
    if method == "eth_blockNumber": return hex(60_000_000)
    if method == "eth_getLogs":
        t = p[0]["topics"]
        if t[0] == approvals.APPROVAL and p[0]["toBlock"] == hex(60_000_000 - 20) and p[0].get("address"):
            return [{"address": TOK, "topics": [approvals.APPROVAL, evm.pad(V), evm.pad(BAD)], "blockNumber": hex(59_999_000)}]
        if t[0] == evm.TRANSFER and len(t) == 2 and p[0]["toBlock"] == hex(60_000_000 - 20) and p[0].get("address"):
            return [{"address": TOK, "topics": [evm.TRANSFER, evm.pad(V), evm.pad(RCV)], "data": hex(500 * 10**18),
                     "transactionHash": "0xd1", "blockNumber": hex(59_999_500)}]
        return []
    if method == "eth_call":
        d = p[0]["data"]
        if d.startswith("0xdd62ed3e"): return hex(2**256 - 1)
        if d == "0x313ce567": return hex(18)
        if d == "0x95d89b41": s=b"USDT"; return "0x"+(32).to_bytes(32,'big').hex()+len(s).to_bytes(32,'big').hex()+s.ljust(32,b'\0').hex()
        return "0x0"
    if method == "eth_getCode": return "0x6080" if p[0] == BAD else "0x"
    if method == "eth_getBlockByNumber": return {"timestamp": hex(now - 3600)}
    if method == "eth_getTransactionByHash": return {"from": "0x9999999999999999999999999999999999999999", "to": BAD}
    if method == "eth_getTransactionReceipt": return {"logs": []}
    if method in ("eth_getTransactionCount",): return hex(12)
    if method == "eth_getBalance": return hex(10**17)
    return None
evm.RPC_POST = bsc_rpc
# Routescan (key-less) is Avalanche's first choice; simulate it being down so the RPC window is exercised
def _http(url):
    if "routescan" in url:
        raise OSError("503 simulated outage")
    return {"result": []}
evm.HTTP_GET = _http
results.append(ok(evm.provider("avalanche") == "routescan" and evm.provider("base") == "blockscout" and evm.provider("bsc") == "none",
                  "Avalanche uses key-less Routescan, Base uses Blockscout, BNB flagged as needing an endpoint"))
results.append(ok(evm.explorer("base", module="account", action="tokentx", address=V) == [], "explorer call works on Base"))
try:
    evm.explorer("avalanche", module="account", action="tokentx", address=V)
    results.append(ok(False, "Routescan outage falls through"))
except LookupError:
    results.append(ok(evm.provider("avalanche") == "rpc_window" and "avalanche" in evm.FALLBACK,
                      "Routescan outage falls through to the RPC window and is noted"))
# free Blockscout PRO key is preferred over the public instance, and a 403 there falls back
import scamconfig
_orig_get = scamconfig.get
scamconfig.get = lambda k, d=None: "proapi_test" if k == "blockscout_key" else _orig_get(k, d)
seen = []
def _http2(url):
    seen.append(url)
    if "api.blockscout.com" in url:
        raise OSError("HTTP 403 simulated")
    return {"status": "1", "result": [{"hash": "0xabc"}]}
evm.HTTP_GET = _http2
results.append(ok(evm.provider("ethereum") == "blockscout_pro", "free Blockscout key is used first when set"))
rows = evm.explorer("ethereum", module="account", action="tokentx", address=V)
results.append(ok(rows and "chainid=1" in seen[0] and "proapi_test" in seen[0] and "eth.blockscout.com" in seen[1],
                  "Blockscout key request carries chainid+key; on 403 it falls back to the public instance"))
scamconfig.get = _orig_get
evm.HTTP_GET = lambda url: {"result": []}
results.append(ok("bsc_rpc" in evm.coverage_note("bsc"), "BNB coverage note tells the user exactly what to add"))
r = approvals.scan(V, ["avalanche"])
results.append(ok(any(a["spender"] == BAD for a in r["chains"]["avalanche"]) and r["notes"], "Avalanche approvals found via filtered RPC window + coverage note"))
d = drain.analyze(V, ["avalanche"])
results.append(ok(len(d["drains"]) == 1 and d["drains"][0]["tokens"][0]["symbol"] == "USDT", "Avalanche drain detected (tokens pulled by someone else's tx)"))
p = prescreen.screen(RCV)
results.append(ok(p["ok"] and p["chain"] == "avalanche", f"pre-screen picks the EVM chain the address is active on ({p.get('chain')})"))
p2 = prescreen.screen(RCV, chain="ethereum")
results.append(ok(any("IS active on" in f["text"] for f in p2["findings"]), "pre-screen warns about wrong network"))

# ---------------- Tron ----------------
W = b58check_encode(bytes.fromhex("41" + "11" * 20)); SP = b58check_encode(bytes.fromhex("41" + "22" * 20))
ATT = b58check_encode(bytes.fromhex("41" + "33" * 20)); USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
def tget(path):
    if "only_from=true" in path:
        return {"data": [{"raw_data": {"contract": [{"type": "TriggerSmartContract", "parameter": {"value": {
            "contract_address": USDT, "data": "095ea7b3" + "0" * 24 + "22" * 20 + "f" * 64}}}]}}]}
    if "/transactions/trc20" in path:
        return {"data": [{"from": W, "to": ATT, "value": str(900 * 10**6), "transaction_id": "tx1", "block_timestamp": now * 1000,
                          "token_info": {"symbol": "USDT", "decimals": 6, "address": USDT}}]}
    return {"data": []}
def tpost(path, body):
    if path.endswith("triggerconstantcontract"): return {"constant_result": ["f" * 64]}
    if path.endswith("getcontract"): return {}
    if path.endswith("getaccount"): return {"owner_permission": {"threshold": 1, "keys": [{"address": ATT, "weight": 1}]}}
    if path.endswith("gettransactionbyid"): return {"raw_data": {"contract": [{"parameter": {"value": {"owner_address": ATT, "contract_address": USDT}}}]}}
    return {}
tron.GET, tron.POST = tget, tpost
r = approvals.scan(W)
results.append(ok(r["family"] == "tron" and r["chains"]["tron"] and r["chains"]["tron"][0]["spender"] == SP, "Tron TRC-20 approval found and decoded"))
results.append(ok(any(l == "danger" for l, _ in r["takeover"]), "Tron permission-hijack detected"))
d = drain.analyze(W)
results.append(ok(len(d["drains"]) == 1 and d["next_steps"][0].startswith("ACCOUNT TAKEN OVER"), "Tron drain found; steps switch to takeover mode"))

# ---------------- Solana ----------------
SW = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"; DLG = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
SYS = solana.SYSTEM; MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
def srpc(method, p):
    if method == "getTokenAccountsByOwner":
        if p[1]["programId"] != solana.TOKEN_PROGRAMS[0]: return {"value": []}
        return {"value": [{"pubkey": "TokAcc1", "account": {"data": {"parsed": {"info": {
            "mint": MINT, "delegate": DLG, "delegatedAmount": {"amount": str(solana.U64_MAX), "uiAmount": 1.8e13},
            "tokenAmount": {"amount": "5000000", "uiAmount": 5.0}}}}}}]}
    if method == "getAccountInfo": return {"value": {"owner": "DrainProg1111111111111111111111111111111111", "lamports": 10**9}}
    if method == "getSignaturesForAddress": return [{"signature": "sig1", "blockTime": now - 600}]
    if method == "getTransaction":
        return {"blockTime": now - 600, "transaction": {"message": {"accountKeys": [
            {"pubkey": DLG, "signer": True}, {"pubkey": SW, "signer": False}, {"pubkey": "TokAcc1", "signer": False}]}},
            "meta": {"preBalances": [1, 10**9, 0], "postBalances": [1, 10**9, 0],
                     "preTokenBalances": [{"accountIndex": 2, "mint": MINT, "owner": SW, "uiTokenAmount": {"uiAmount": 5.0}}],
                     "postTokenBalances": [{"accountIndex": 2, "mint": MINT, "owner": SW, "uiTokenAmount": {"uiAmount": 0.0}},
                                           {"accountIndex": 3, "mint": MINT, "owner": DLG, "uiTokenAmount": {"uiAmount": 5.0}}]}}
    return None
solana.RPC = srpc
r = approvals.scan(SW)
results.append(ok(r["family"] == "solana" and r["chains"]["solana"][0]["kind"] == "spl_delegate", "Solana delegate (approval) found"))
results.append(ok(any("Assign" in t for _, t in r["takeover"]), "Solana account-owner hijack detected"))
d = drain.analyze(SW)
results.append(ok(len(d["drains"]) == 1 and DLG in d["drains"][0]["receivers"], "Solana drain found (moved without wallet signature)"))
p = prescreen.screen(SW)
results.append(ok(p["ok"] and p["chain"] == "solana" and p["stats"]["movements"] >= 1, "Solana pre-screen reads behavior"))

# ---------------- XRP Ledger ----------------
XW = "rUrYCcn3UkgC2ZXDWDvWT1D8VmM2X5Yiws"; XK = "rwW2qTeD3dfk74bfURPrPAwfz2XADmocaN"
def xrpc(method, p):
    if method == "account_info": return {"account_data": {"RegularKey": XK, "Flags": 0x00100000, "Balance": "1000000"}}
    if method == "account_objects":
        return {"account_objects": [{"LedgerEntryType": "Check", "Account": XW, "Destination": XK, "SendMax": "500000000"},
                                    {"LedgerEntryType": "NFTokenOffer", "Owner": XW, "Flags": 1, "Amount": "0", "NFTokenID": "N1"}]}
    if method == "account_tx":
        return {"transactions": [
            {"tx_json": {"TransactionType": "Payment", "Account": XW, "Destination": XK, "Amount": "400000000", "date": now - 946684800 - 100, "hash": "P2"},
             "meta": {"TransactionResult": "tesSUCCESS", "delivered_amount": "400000000"}},
            {"tx_json": {"TransactionType": "SetRegularKey", "Account": XW, "RegularKey": XK, "date": now - 946684800 - 500, "hash": "K1"},
             "meta": {"TransactionResult": "tesSUCCESS"}}]}
    return {}
xrpl.RPC = xrpc
r = approvals.scan(XW)
kinds = {a["kind"] for a in r["chains"]["xrpl"]}
results.append(ok({"regular_key", "check", "nft_offer"} <= kinds, f"XRPL standing permissions found ({', '.join(sorted(kinds))})"))
results.append(ok(any(l == "danger" for l, _ in r["takeover"]), "XRPL master-disabled + regular key takeover detected"))
d = drain.analyze(XW)
results.append(ok(len(d["drains"]) == 1 and d["drains"][0]["receivers"] == {XK: 1}, "XRPL payment after key change flagged as drain"))

# ---------------- Bitcoin ----------------
BW = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
r = approvals.scan(BW)
results.append(ok(r["family"] == "bitcoin" and r["notes"], "Bitcoin: explains there are no approvals"))
prescreen.HTTP_GET = lambda url: []
p = prescreen.screen(BW)
results.append(ok(p["ok"] and p["chain"] == "bitcoin", "Bitcoin pre-screen runs"))

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
