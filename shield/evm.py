"""Shared EVM access for shield, working on EVERY major EVM chain without paid keys.

Provider order per chain (first that applies):
  1. Etherscan V2 key   -- only for chains its FREE tier still covers
                           (Ethereum, Polygon, Arbitrum ...). Since late 2025 BNB,
                           Base, OP and Avalanche need a paid Etherscan plan.
  2. Blockscout         -- key-less: Ethereum, Base, Optimism, Arbitrum, Polygon, Gnosis
  3. Routescan          -- Avalanche, if "routescan_key" is set (free signup)
  4. RPC log window     -- key-less fallback (Avalanche today): eth_getLogs over
                           the recent block window, filtered to the chain's major
                           tokens (public RPCs refuse unfiltered log queries).
                           RECENT ONLY (~30 days), major tokens only, no native coin.
  BNB Chain: no free public endpoint answers log queries reliably (tested Nov 2026),
  so set "bsc_rpc" in config.json to a free personal endpoint (NodeReal, Ankr,
  QuickNode free tiers) or use a paid Etherscan key. Without it, BNB gets
  balance / contract / nonce checks only.
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
# Major tokens per chain for filtered log queries (public RPCs require an address filter)
MAJOR_TOKENS = {
    "ethereum": ["0xdac17f958d2ee523a2206206994597c13d831ec7", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                 "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", "0x6b175474e89094c44da98b954eedeac495271d0f",
                 "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"],
    "base": ["0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "0x4200000000000000000000000000000000000006",
             "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca", "0x50c5725949a6f0c72e6c4a641f24049a917db0cb"],
    "polygon": ["0xc2132d05d31c914a87c6611c10748aeb04b58e8f", "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
                "0x2791bca1f2de4661ed88a30c99a7a9449aa84174", "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619",
                "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270"],
    "arbitrum": ["0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
                 "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8", "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
                 "0x912ce59144191c1204e64559fe8253a0e49e6548"],
    "optimism": ["0x94b008aa00579c1307b0ef2c499ad98a8ce58e58", "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
                 "0x4200000000000000000000000000000000000006", "0x4200000000000000000000000000000000000042"],
    "bsc": ["0x55d398326f99059ff775485246999027b3197955", "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
            "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c", "0xe9e7cea3dedca5984780bafc599bd69add087d56",
            "0x2170ed0880ac9a755fd29b2688956bd959f933f8", "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c",
            "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82", "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409"],
    "avalanche": ["0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7", "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e",
                  "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7", "0xa7d7079b0fead91f3e65f86e8915cb59c1a4c664",
                  "0xc7198437980c041c805a1edcba50c1ce5db95118", "0x49d5c2bdffac6ce2bfdb6640f4f80f226bc10bab",
                  "0x152b9d0fdc40c096757f570a51e494bd4b943e50"],
}
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
    if chain == "bsc" and not _cfg("bsc_rpc"):
        return "none"
    return "rpc_window"


FALLBACK = {}   # chain -> why its explorer failed this run (Cloudflare challenge, 5xx, rate limit)


def _explorer_ok(chain):
    return provider(chain) not in ("rpc_window", "none") and chain not in FALLBACK


def _note_fallback(chain, err):
    FALLBACK.setdefault(chain, str(err)[:100])


def available(chain):
    return chain in CHAINS


def coverage_note(chain):
    p = provider(chain)
    if chain in FALLBACK and p != "none":
        return (f"{chain}: the free history service didn't answer ({FALLBACK[chain]}); checked the last "
                f"{COVERED.get(chain, WINDOW_DAYS)} days of major-token activity instead. Re-run later for full history.")
    if p == "none":
        return (f"{chain}: transaction history NOT checked -- no free public BNB Chain endpoint answers history queries. "
                "Add a free personal endpoint as \"bsc_rpc\" in config.json (NodeReal / Ankr / QuickNode free tier).")
    if p == "rpc_window" and COVERED.get(chain, WINDOW_DAYS) < WINDOW_DAYS - 0.5:
        return (f"{chain}: only the last {COVERED[chain]} days of major-token activity could be checked in time "
                "(slow free endpoint). Re-run later or add a free personal RPC endpoint for this chain.")
    if p == "rpc_window":
            return (f"{chain}: last {WINDOW_DAYS} days of major-token activity checked (no free full-history API for this chain; "
                "a Routescan key or paid Etherscan key gives full history).")
    return ""


def _get(url):
    if HTTP_GET:
        return HTTP_GET(url)
    import urllib.error
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=40) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 3:      # free explorers rate-limit: back off and retry
                time.sleep(2 * 2 ** attempt)
                continue
            raise


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


def rpc_url(chain):
    return _cfg(f"{chain}_rpc") or CHAINS[chain][1]


def rpc(chain, method, params, timeout=25):
    if RPC_POST:
        return RPC_POST(chain, method, params)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    with urllib.request.urlopen(urllib.request.Request(rpc_url(chain), data=body, headers=UA), timeout=timeout) as r:
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


_STEP = {}       # chain -> block range the endpoint accepted last time
COVERED = {}     # chain -> days of history actually covered by the last window scan
WINDOW_BUDGET = 25   # seconds per window scan; a slow public endpoint must not hang the page


def rpc_window_logs(chain, topics, address=None, days=None, max_requests=160, budget=None):
    """eth_getLogs over the recent window, adaptively chunked (public RPCs cap the range).
    Stops at the time budget and records how many days were really covered."""
    days = days or WINDOW_DAYS
    budget = budget or WINDOW_BUDGET
    if not address and not _cfg(f"{chain}_rpc"):
        address = MAJOR_TOKENS.get(chain)       # public endpoints refuse unfiltered queries
    latest = int(rpc(chain, "eth_blockNumber", []), 16) - 20   # margin: load-balanced nodes lag
    start = max(0, latest - int(days * 86400 / CHAINS[chain][2]))
    out, hi, n = [], latest, 0
    step = _STEP.get(chain, 20_000)
    t0 = time.time()
    while hi > start and n < max_requests and (RPC_POST or time.time() - t0 < budget):
        lo = max(start, hi - step + 1)
        flt = {"fromBlock": hex(lo), "toBlock": hex(hi), "topics": topics}
        if address:
            flt["address"] = address
        try:
            res = rpc(chain, "eth_getLogs", [flt], timeout=12) or []
            out += res
            hi = lo - 1
            _STEP[chain] = step
            if len(res) < 500 and step < 100_000:
                step = int(step * 1.5)
        except Exception:
            if step <= 1000:
                hi = lo - 1          # give up on this slice
            step = max(1000, step // 4)
        n += 1
    covered = (latest - max(hi, start)) * CHAINS[chain][2] / 86400
    COVERED[chain] = min(COVERED.get(chain, days), round(covered, 1))
    return out


def logs(chain, topic0, topic1=None, topic2=None, address=None):
    """Logs by topic: the explorer when it answers, else the RPC window."""
    if provider(chain) == "none":
        return []
    if _explorer_ok(chain):
        p = {"module": "logs", "action": "getLogs", "fromBlock": 0, "toBlock": "latest", "topic0": topic0}
        if topic1:
            p.update({"topic1": topic1, "topic0_1_opr": "and"})
        if topic2:
            p.update({"topic2": topic2, "topic0_2_opr": "and"})
        if address:
            p["address"] = address
        out, seen = [], set()
        try:
            for _ in range(20):                       # explorers cap a page at 1,000 logs
                page = explorer(chain, **p)
                for lg in page:
                    k = (lg.get("transactionHash"), lg.get("logIndex"), lg.get("address"), tuple(lg.get("topics") or []))
                    if k not in seen:
                        seen.add(k)
                        out.append(lg)
                if len(page) < 1000:
                    break
                p["fromBlock"] = int(str(page[-1].get("blockNumber") or "0"), 0)
            return out
        except Exception as e:
            if out:
                return out        # partial is better than nothing
            _note_fallback(chain, e)
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
    if provider(chain) == "none":
        return []
    if _explorer_ok(chain):
        try:
            return explorer(chain, module="account", action="tokentx", address=a, page=1, offset=1000, sort="desc")
        except Exception as e:
            _note_fallback(chain, e)
    rows = []
    for direction, lg_list in (("out", logs(chain, TRANSFER, pad(a))), ("in", logs(chain, TRANSFER, None, pad(a)))):
        for lg in lg_list:
            tp = [x for x in (lg.get("topics") or []) if x]
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
    if not _explorer_ok(chain):
        return []
    try:
        return explorer(chain, module="account", action="txlist", address=addr.lower(), page=1, offset=1000, sort="desc")
    except Exception as e:
        _note_fallback(chain, e)
        return []


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
