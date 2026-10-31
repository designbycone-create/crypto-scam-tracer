"""Shared EVM access for shield: explorer API (logs, token transfers, tx lists)
and JSON-RPC eth_call, with test hooks.

Explorer: Etherscan V2 when a key is configured (all EVM chains), otherwise the
key-less Blockscout API (Ethereum, Base, Optimism, Arbitrum, Polygon).
RPC: publicnode endpoints (no key).
"""
import json
import urllib.parse
import urllib.request

CHAINS = {  # key: (chainid, rpc)
    "ethereum": (1, "https://ethereum-rpc.publicnode.com"),
    "bsc": (56, "https://bsc-rpc.publicnode.com"),
    "polygon": (137, "https://polygon-bor-rpc.publicnode.com"),
    "arbitrum": (42161, "https://arbitrum-one-rpc.publicnode.com"),
    "base": (8453, "https://base-rpc.publicnode.com"),
    "optimism": (10, "https://optimism-rpc.publicnode.com"),
    "avalanche": (43114, "https://avalanche-c-chain-rpc.publicnode.com"),
}
BLOCKSCOUT = {
    "ethereum": "https://eth.blockscout.com/api",
    "base": "https://base.blockscout.com/api",
    "optimism": "https://optimism.blockscout.com/api",
    "arbitrum": "https://arbitrum.blockscout.com/api",
    "polygon": "https://polygon.blockscout.com/api",
}
ETHERSCAN = "https://api.etherscan.io/v2/api"
UA = {"User-Agent": "ScamHunter-Shield/0.1", "Content-Type": "application/json"}

# test hooks: set to callables to run offline
HTTP_GET = None   # f(url) -> parsed json
RPC_POST = None   # f(chain, method, params) -> result


def _key():
    try:
        from multichain.adapters.evm import api_key
        return api_key()
    except Exception:
        return ""


def available(chain):
    return bool(_key()) or chain in BLOCKSCOUT


def explorer(chain, **params):
    """Etherscan-compatible explorer call. Returns the 'result' list ([] on none)."""
    if _key():
        params.update({"chainid": CHAINS[chain][0], "apikey": _key()})
        url = ETHERSCAN + "?" + urllib.parse.urlencode(params)
    elif chain in BLOCKSCOUT:
        url = BLOCKSCOUT[chain] + "?" + urllib.parse.urlencode(params)
    else:
        raise RuntimeError(f"{chain} needs a free Etherscan API key")
    if HTTP_GET:
        d = HTTP_GET(url)
    else:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=40) as r:
            d = json.loads(r.read())
    res = d.get("result") if isinstance(d, dict) else None
    return res if isinstance(res, list) else []


def rpc(chain, method, params):
    if RPC_POST:
        return RPC_POST(chain, method, params)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    with urllib.request.urlopen(urllib.request.Request(CHAINS[chain][1], data=body, headers=UA), timeout=20) as r:
        return json.loads(r.read()).get("result")


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
