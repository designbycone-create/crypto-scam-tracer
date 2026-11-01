"""Build the benchmark's ground-truth set from public sources, recording provenance for each.

Writes benchmark/data/truth.jsonl (one case per line) and benchmark/data/sources.json
(URL, SHA-256 of the exact bytes used, retrieval time, licence note).
"""
import hashlib
import json
import os
import re
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from responder.addresses import is_btc_legacy, is_tron, is_xrpl  # noqa: E402

DATA = os.path.join(HERE, "data")
DL = "https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/{}/index.js"
# DefiLlama project file -> canonical exchange name (proof-of-reserves wallets published by the exchange)
EXCHANGES = {"okex": "okx", "huobi": "htx", "gate-io": "gate", "bitget": "bitget", "bitstamp": "bitstamp",
             "kucoin": "kucoin", "bitfinex": "bitfinex", "binance": "binance"}
BAD = {
    "ofac_eth": ("https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.txt", "ethereum", "OFAC sanctions list (US Treasury)"),
    "ofac_xbt": ("https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_XBT.txt", "bitcoin", "OFAC sanctions list (US Treasury)"),
    "ofac_trx": ("https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_TRX.txt", "tron", "OFAC sanctions list (US Treasury)"),
    "scamsniffer": ("https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json", "ethereum", "ScamSniffer scam database (GPL-3.0 data)"),
}
FETCH = None   # test hook: f(url) -> bytes


def _get(url):
    if FETCH:
        return FETCH(url)
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "ScamHunter-benchmark"}), timeout=60) as r:
        return r.read()


def _chain_of(a):
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", a):
        return "ethereum"
    if a.startswith("r") and is_xrpl(a):
        return "xrpl"
    if a.startswith("T") and is_tron(a):
        return "tron"
    if a.startswith("bc1") or is_btc_legacy(a):
        return "bitcoin"
    return None


def exchange_addresses(js):
    """Wallet addresses in a DefiLlama CEX adapter, skipping token-contract lines."""
    out = []
    for line in js.splitlines():
        low = line.lower()
        if "owntokens" in low or "tokens:" in low or "require(" in low or low.strip().startswith("//"):
            continue
        for a in re.findall(r"['\"]([0-9A-Za-z]{25,64})['\"]", line):
            ch = _chain_of(a)
            if ch:
                out.append((ch, a.lower() if ch == "ethereum" else a))
    return out


def _pick(items, n):
    """Deterministic sample: the n items with the smallest SHA-256 of the address."""
    return sorted(items, key=lambda x: hashlib.sha256(x[1].encode()).hexdigest())[:n]


def build(per_exchange_chain=4, per_bad_source=20, log=print):
    os.makedirs(DATA, exist_ok=True)
    sources, cases, seen = {}, [], set()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for proj, name in EXCHANGES.items():
        url = DL.format(proj)
        try:
            raw = _get(url)
        except Exception as e:
            log(f"skip {proj}: {e}")
            continue
        sources[f"defillama_{proj}"] = {"url": url, "sha256": hashlib.sha256(raw).hexdigest(), "retrieved": stamp,
                                        "what": f"{name} proof-of-reserves wallets published by the exchange (via DefiLlama)"}
        by_chain = {}
        for ch, a in exchange_addresses(raw.decode("utf-8", "replace")):
            by_chain.setdefault(ch, []).append((ch, a))
        for ch, items in by_chain.items():
            for ch2, a in _pick(list(dict.fromkeys(items)), per_exchange_chain):
                if a in seen:
                    continue
                seen.add(a)
                cases.append({"id": f"ex-{name}-{ch2}-{a[:10]}", "group": "exchange", "truth": "legit",
                              "exchange": name, "chain": ch2, "address": a, "source": f"defillama_{proj}"})
    for key, (url, ch, what) in BAD.items():
        try:
            raw = _get(url)
        except Exception as e:
            log(f"skip {key}: {e}")
            continue
        sources[key] = {"url": url, "sha256": hashlib.sha256(raw).hexdigest(), "retrieved": stamp, "what": what}
        txt = raw.decode("utf-8", "replace")
        addrs = json.loads(txt) if txt.lstrip().startswith("[") else [l.strip() for l in txt.splitlines() if l.strip()]
        items = [(ch, a.lower() if ch == "ethereum" else a) for a in addrs if _chain_of(a.strip()) == ch]
        for ch2, a in _pick(items, per_bad_source):
            if a in seen:
                continue
            seen.add(a)
            cases.append({"id": f"bad-{key}-{a[:10]}", "group": "known_bad", "truth": "bad", "chain": ch2,
                          "address": a, "source": key})
    with open(os.path.join(DATA, "truth.jsonl"), "w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c) + "\n")
    with open(os.path.join(DATA, "sources.json"), "w", encoding="utf-8") as f:
        json.dump(sources, f, indent=1)
    log(f"{len(cases)} cases from {len(sources)} sources -> {DATA}")
    return cases, sources


def load():
    with open(os.path.join(DATA, "truth.jsonl"), encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


if __name__ == "__main__":
    build()
