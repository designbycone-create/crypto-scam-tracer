"""Shared EVM access for shield, working on EVERY major EVM chain without paid keys.

Provider order per chain (first that applies):
  1. Etherscan V2 key   -- only for chains its FREE tier still covers
                           (Ethereum, Polygon, Arbitrum ...). Since late 2025 BNB,
                           Base, OP and Avalanche need a paid Etherscan plan.
  2. Blockscout         -- key-less: Ethereum, Base, Optimism, Arbitrum, Polygon, Gnosis
  3. Routescan          -- Avalanche, if "routescan_key" is set (free signup)
  4. RPC log window     -- key-less fallback for ANY chain (BNB, Avalanche...):
                           scans the recent block window with eth_getLogs. Covers
                           token movements/approvals; history is RECENT ONLY
                           (default ~30 days) and native-coin transfers aren't in logs.
Every result says which provider produced it, so the UI can be honest.
"""
import json
import time
import urllib.parse
import urllib.request

CHAINS = {  # key: (chainid, rpc, avg block seconds)
    "ethereum": (1, "https://ethereum-rpc.publicnode.com", 12),
    "bsc": (56, "https://bsc-rpc.publicnode.com", 0.75),
    "polygon": (137, "https://polygon-bor-rpc.publicnode.com", 2),
    "arbitrum": (42161, "https://arbitrum-one-rpc.publicnode.com", 0.25),
    "base": (8453, "https://base-rpc.publicnode.com", 2),
    "optimism": (10, "https://optimism-rpc.publicnode.com", 2),
    "avalanche": (43114, "https://avalanche-c-chain-rpc.publicnode.com", 2),
}
BLOCKSCOUT = {
    "ethereum": "https://eth.blockscout.com/api",
    "base": "https://base.blockscout.com/api",
    "optimism": "https://optimism.blockscout.com/api",
    "arbitrum": "https://arbitrum.blockscout.com/api",
    "polygon": "https://polygon.blockscout.com/api",
}
ETHERSCAN = "https://api.etherscan.io/v2/api"
ETHERSCAN_FREE = {1, 137, 42161}          # free-tier chain ids we use (per api.etherscan.io/v2/chainlist)
ROUTESCAN = "https://api.routescan.io/v2/network/mainnet/evm/{cid}/etherscan/api"
WINDOW_DAYS = 30
UA = {"User-Agent": "ScamHunter-Shield/0.2", "Content-Type": "application/json"}
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# test hooks
HTTP_GET = None   # f(url) -> parsed json
RPC_POST = None   # f(chain, method, params) -> result


def _cfg(k):
    try:
        import scamconfig
        return (scamconfig.get(k) or "").strip()
    except Exception:
        return ""


def _etherscan_key():
    try:
        from multichain.adapters.evm import api_key
        return api_key()
    except Exception:
        return _cfg("etherscan_key")


def provider(chain):
    cid = CHAINS[chain][0]
    if _etherscan_key() and (cid in ETHERSCAN_FREE or _cfg("etherscan_paid") == "yes"):
        return "etherscan"
    if chain in BLOCKSCOUT:
        return "blockscout"
    if chain == "avalanche" and _cfg("routescan_key"):
        return "routescan"
    return "rpc_window"


def available(chain):
    return chain in CHAINS


def coverage_note(chain):
    p = provider(chain)
    if p == "rpc_window":
        return (f"{chain}: recent {WINDOW_DAYS} days of token activity checked (no free full-history API for this chain; "
                "add a paid Etherscan key or Routescan key for full history).")
    return ""


def _get(url):
    if HTTP_GET:
        return HTTP_GET(url)
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=40) as r:
        return json.loads(r.read())


def explorer(chain, **params):
    """Etherscan-compatible explorer call; raises LookupError if this chain has no explorer provider."""
    p = provider(chain)
    cid = CHAINS[chain][0]
    if p == "etherscan":
        params.update({"chainid": cid, "apikey": _etherscan_key()})
        url = ETHERSCAN + "?" + urllib.parse.urlencode(params)
    elif p == "blockscout":
        url = BLOCKSCOUT[chain] + "?" + urllib.parse.urlencode(params)
    elif p == "routescan":
        params["apikey"] = _cfg("routescan_key")
        url = ROUTESCAN.format(cid=cid) + "?" + urllib.parse.urlencode(params)
    else:
        raise LookupError("no explorer")
    d = _get(url)
    res = d.get("result") if isinstance(d, dict) else None
    return res if isinstance(res, list) else []


def rpc(chain, method, params):
    if RPC_POST:
        return RPC_POST(chain, method, params)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    with urllib.request.urlopen(urllib.request.Request(CHAINS[chain][1], data=body, headers=UA), timeout=25) as r:
        d = json.loads(r.read())
    if "error" in d:
        raise RuntimeError(d["error"].get("message", "rpc error"))
    return d.get("result")


def call(chain, to, data):
    return rpc(chain, "eth_call", [{"to": to, "data": data}, "latest"])


def pad(addr):
    return "0x" + "0" * 24 + addr.lower().replace("0x", "")


def topic_addr(t):
    return "0x" + t[-40:].lower()


def get_code(chain, addr):
    try:
        return rpc(chain, "eth_getCode", [addr, "latest"]) or "0x"
    except Exception:
        return None


def rpc_window_logs(chain, topics, address=None, days=None, max_requests=160):
    """eth_getLogs over the recent window, adaptively chunked (public RPCs cap the range)."""
    days = days or WINDOW_DAYS
    latest = int(rpc(chain, "eth_blockNumber", []), 16)
    start = max(0, latest - int(days * 86400 / CHAINS[chain][2]))
    out, hi, step, n = [], latest, 50_000, 0
    while hi > start and n < max_requests:
        lo = max(start, hi - step + 1)
        flt = {"fromBlock": hex(lo), "toBlock": hex(hi), "topics": topics}
        if address:
            flt["address"] = address
        try:
            res = rpc(chain, "eth_getLogs", [flt]) or []
            out += res
            hi = lo - 1
            if len(res) < 500 and step < 200_000:
                step = int(step * 1.5)
        except Exception:
            if step <= 1000:
                hi = lo - 1          # give up on this slice
            step = max(1000, step // 4)
        n += 1
    for lg in out:
        lg.setdefault("blockNumber", lg.get("blockNumber"))
    return out


def logs(chain, topic0, topic1=None, topic2=None, address=None):
    """Logs by topic, via the explorer when there is one, else the RPC window."""
    if provider(chain) != "rpc_window":
        p = {"module": "logs", "action": "getLogs", "fromBlock": 0, "toBlock": "latest", "topic0": topic0}
        if topic1:
            p.update({"topic1": topic1, "topic0_1_opr": "and"})
        if topic2:
            p.update({"topic2": topic2, "topic0_2_opr": "and"})
        if address:
            p["address"] = address
        return explorer(chain, **p)
    return rpc_window_logs(chain, [topic0, topic1, topic2] if topic2 else ([topic0, topic1] if topic1 else [topic0]),
                           address)


def _block_time(chain, bn, _cache={}):
    k = (chain, bn)
    if k not in _cache:
        try:
            _cache[k] = int((rpc(chain, "eth_getBlockByNumber", [bn, False]) or {}).get("timestamp", "0x0"), 16)
        except Exception:
            _cache[k] = 0
    return _cache[k]


def token_transfers(chain, addr):
    """Etherscan-'tokentx'-shaped rows for any chain (explorer or RPC window)."""
    a = addr.lower()
    if provider(chain) != "rpc_window":
        return explorer(chain, module="account", action="tokentx", address=a, page=1, offset=1000, sort="desc")
    rows = []
    for direction, lg_list in (("out", logs(chain, TRANSFER, pad(a))), ("in", logs(chain, TRANSFER, None, pad(a)))):
        for lg in lg_list:
            tp = lg.get("topics") or []
            if len(tp) != 3:
                continue          # ERC-721 has 4 topics; skip NFTs here
            sym, dec = token_meta(chain, lg["address"])
            rows.append({"hash": lg.get("transactionHash"), "from": topic_addr(tp[1]), "to": topic_addr(tp[2]),
                         "value": str(int(lg.get("data") or "0x0", 16)), "tokenDecimal": str(dec), "tokenSymbol": sym,
                         "contractAddress": lg["address"].lower(),
                         "timeStamp": str(_block_time(chain, lg.get("blockNumber")))})
    return rows


def native_txs(chain, addr):
    """Native-coin txs (explorer only; the RPC window can't list them)."""
    if provider(chain) == "rpc_window":
        return []
    return explorer(chain, module="account", action="txlist", address=addr.lower(), page=1, offset=1000, sort="desc")


def token_meta(chain, token, _cache={}):
    k = (chain, token.lower())
    if k in _cache:
        return _cache[k]
    sym, dec = "token", 18
    try:
        dec = int(call(chain, token, "0x313ce567"), 16)
    except Exception:
        pass
    try:
        raw = bytes.fromhex((call(chain, token, "0x95d89b41") or "0x")[2:])
        if len(raw) >= 64:
            n = int.from_bytes(raw[32:64], "big")
            sym = raw[64:64 + n].decode("utf-8", "ignore") or sym
        elif raw:
            sym = raw.rstrip(b"\0").decode("utf-8", "ignore") or sym
    except Exception:
        pass
    _cache[k] = (sym, dec)
    return sym, dec
