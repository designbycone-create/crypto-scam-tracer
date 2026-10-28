"""User configuration loader.

Copy config.example.json to config.json and fill in your own case. Nothing
here is personal to any one case -- the repository ships with no real wallet,
victim, or topic. Every field is optional; sensible defaults apply.

Both the XRPL tools and the multi-chain tracer import this. It is kept at the
repo root so `python -m scam_investigator ...`, `python -m multichain ...` and
`python xrpl_watcher.py`, all run from the repo root, can find it.
"""
import json
import os

_DEFAULTS = {
    "watched_wallets": {},   # {xrpl_address: "short description"} -- what xrpl_watcher watches
    "scam_wallet": "",       # the primary scam receiving wallet (root of the network map)
    "ntfy_topic": "",        # phone-push topic (ntfy.sh); may also be set via NTFY_TOPIC env
    "min_xrp": 25,           # ignore XRP movements smaller than this
    "servers": ["wss://xrplcluster.com", "wss://s1.ripple.com", "wss://s2.ripple.com"],
    "victim_file": "victim.json",   # your case details for report drafts (see victim.example.json)
    "etherscan_key": "",     # free Etherscan V2 key, enables the EVM chains in the multi-chain tracer
}

_cache = None


def load(path="config.json"):
    global _cache
    if _cache is not None:
        return _cache
    cfg = dict(_DEFAULTS)
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                for k, v in json.load(f).items():
                    if v not in (None, ""):
                        cfg[k] = v
        except Exception:
            pass
    if os.environ.get("NTFY_TOPIC", "").strip():
        cfg["ntfy_topic"] = os.environ["NTFY_TOPIC"].strip()
    if os.environ.get("ETHERSCAN_API_KEY", "").strip():
        cfg["etherscan_key"] = os.environ["ETHERSCAN_API_KEY"].strip()
    _cache = cfg
    return cfg


def get(key, default=None):
    return load().get(key, default)


def scam_wallet():
    """The network-map root: the configured scam_wallet, else the first watched wallet."""
    return get("scam_wallet") or next(iter(get("watched_wallets") or {}), "")
