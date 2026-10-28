"""Who owns an address: exchange, bridge, mixer, stablecoin issuer, or unknown.

Accuracy rule (important): we NEVER hardcode guessed exchange "deposit"
addresses. Falsely labeling a wallet as "Binance" could send a victim's freeze
request at an innocent third party. So the only addresses hardcoded here are
published, singular, protocol/issuer contracts that do not change and cannot be
confused with a user wallet:

  * stablecoin token contracts (USDT, USDC) -> these tell us the issuer
    (Tether / Circle) can freeze ANY holder of that token, on that chain.
  * OFAC-sanctioned addresses and Tornado Cash routers (published lists).

Everything else (exchange hot wallets, bridges) is classified from PUBLIC,
community-maintained label datasets fetched from GitHub and cached locally, and
from a user-editable overrides file. An address we cannot identify is flagged
"unidentified custodial / investigate" -- never given a company name we are not
sure of.

Fully automated: labels auto-download and cache on first use and refresh when
stale; no manual setup. The cache lives next to the tool as entity_cache/.
"""
import json
import os
import time
import urllib.request

CACHE_DIR = "entity_cache"
OVERRIDES = "entities_overrides.json"   # user-editable: {chain: {addr: {name,type}}}
REFRESH_DAYS = 14

# ---- published, safe-to-hardcode contracts -------------------------------
# Stablecoin token contracts by chain -> (symbol, issuer key). Issuer can freeze
# any address holding the token. These are the well-known canonical contracts.
STABLECOINS = {
    "ethereum": {
        "0xdac17f958d2ee523a2206206994597c13d831ec7": ("USDT", "tether"),
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": ("USDC", "circle"),
    },
    "tron": {
        "tr7nhqjekqxgtci8q8zy4pl8otszgjlj6t": ("USDT", "tether"),
        "tekxitehnzsmse2xqrbj4w32run966rdz8": ("USDC", "circle"),
    },
    "polygon": {
        "0xc2132d05d31c914a87c6611c10748aeb04b58e8f": ("USDT", "tether"),
        "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359": ("USDC", "circle"),
    },
    "bsc": {
        "0x55d398326f99059ff775485246999027b3197955": ("USDT", "tether"),
        "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": ("USDC", "circle"),
    },
    "arbitrum": {
        "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9": ("USDT", "tether"),
        "0xaf88d065e77c8cc2239327c5edb3a432268e5831": ("USDC", "circle"),
    },
    "avalanche": {
        "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7": ("USDT", "tether"),
        "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e": ("USDC", "circle"),
    },
    "optimism": {
        "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58": ("USDT", "tether"),
        "0x0b2c639c533813f4aa9d7837caf62653d097ff85": ("USDC", "circle"),
    },
    "base": {
        "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": ("USDC", "circle"),
    },
}

ISSUERS = {
    "tether": {"name": "Tether (USDT issuer)",
               "contact": "https://tether.to/en/contact-us/ (law-enforcement / compliance); Tether can freeze USDT at any address on request from law enforcement.",
               "email": None},
    "circle": {"name": "Circle (USDC issuer)",
               "contact": "https://www.circle.com/legal/law-enforcement-guidelines and compliance channel; Circle can blacklist/freeze USDC at any address.",
               "email": None},
}

# Label datasets fetched from GitHub (public, community-maintained).
LABEL_SOURCES = {
    # EVM address -> {name, labels[]}; huge, covers exchanges/bridges/mixers.
    "evm_labels": "https://raw.githubusercontent.com/brianleect/etherscan-labels/main/data/etherscan/combined/combinedAllLabels.json",
    # OFAC sanctioned addresses, per asset.
    "ofac_eth": "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.json",
    "ofac_xbt": "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_XBT.json",
    "ofac_trx": "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_TRX.json",
}

# Keywords in a label's text that imply a type (checked in order).
_TYPE_HINTS = [
    ("mixer", ["tornado", "mixer", "blender", "sinbad", "wasabi", "coinjoin"]),
    ("bridge", ["bridge", "wormhole", "multichain", "celer", "cbridge", "across", "stargate",
                "synapse", "hop protocol", "allbridge", "orbit"]),
    ("exchange", ["binance", "coinbase", "kraken", "okx", "kucoin", "bybit", "huobi", "htx",
                  "bitfinex", "gate.io", "gate.com", "mexc", "crypto.com", "bitstamp", "gemini",
                  "bitget", "exchange", "changenow", "changelly", "simpleswap", "stealthex",
                  "sideshift", "fixedfloat", "swft", "uphold", "robinhood"]),
    ("service", ["deployer", "router", "hot wallet", "cold wallet", "payment", "service"]),
]


def _cache_path(name):
    return os.path.join(CACHE_DIR, name + ".json")


def _fresh(path):
    return os.path.exists(path) and (time.time() - os.path.getmtime(path)) < REFRESH_DAYS * 86400


def _fetch_json(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "scam-investigator/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def refresh(force=False, log=print):
    """Download and cache every label dataset if missing or stale. Safe to call
    on every startup; only hits the network when something is stale."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    for name, url in LABEL_SOURCES.items():
        path = _cache_path(name)
        if not force and _fresh(path):
            continue
        try:
            data = _fetch_json(url)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
            n = len(data) if isinstance(data, (list, dict)) else "?"
            log(f"  entity data '{name}': {n} records cached")
        except Exception as e:
            log(f"  entity data '{name}': fetch failed ({e}); using cached copy if present")


def _load_cache(name):
    path = _cache_path(name)
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None


_CACHE = {}


def _get(name):
    if name not in _CACHE:
        _CACHE[name] = _load_cache(name)
    return _CACHE[name]


def _load_overrides():
    if os.path.exists(OVERRIDES):
        try:
            with open(OVERRIDES, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _type_from_labels(name, labels):
    hay = " ".join([name or ""] + list(labels or [])).lower()
    for typ, kws in _TYPE_HINTS:
        if any(k in hay for k in kws):
            return typ
    return "service"


def stablecoin_for(chain, contract):
    """If `contract` is a known stablecoin on `chain`, return (symbol, issuer_key)."""
    if not contract:
        return None
    return STABLECOINS.get(chain, {}).get(contract.lower())


def is_sanctioned(chain, address):
    a = (address or "").lower()
    for key in ("ofac_eth", "ofac_xbt", "ofac_trx"):
        lst = _get(key) or []
        if any(a == str(x).lower() for x in lst):
            return True
    return False


def classify(chain, address):
    """Return {name, type, source} for an address, or None if unidentified.
    type in {exchange, bridge, mixer, service}."""
    if not address:
        return None
    a = address.lower()

    # 1. user overrides win
    ov = _load_overrides().get(chain, {}) or _load_overrides().get("*", {})
    if a in {k.lower(): v for k, v in ov.items()}:
        rec = {k.lower(): v for k, v in ov.items()}[a]
        return {"name": rec.get("name"), "type": rec.get("type", "service"), "source": "override"}

    # 2. OFAC sanctioned
    if is_sanctioned(chain, address):
        return {"name": "OFAC-sanctioned address", "type": "mixer", "source": "ofac"}

    # 3. EVM community labels (ethereum + most EVM chains share address space)
    info = chain  # noqa
    evm = _get("evm_labels") or {}
    rec = evm.get(a)
    if rec:
        nm = rec.get("name") or ""
        labels = rec.get("labels") or []
        return {"name": nm or (labels[0] if labels else "labeled address"),
                "type": _type_from_labels(nm, labels), "source": "etherscan-labels"}
    return None
