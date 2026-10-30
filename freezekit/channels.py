"""Verified channel directory (channels.json) + lookups.

Users can override / extend with channels_overrides.json next to the tool
(same shape, merged on top).
"""
import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_DIR = None


def _merge(a, b):
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict):
            _merge(a[k], v)
        else:
            a[k] = v
    return a


def directory():
    global _DIR
    if _DIR is None:
        with open(os.path.join(_HERE, "channels.json"), encoding="utf-8") as f:
            d = json.load(f)
        if os.path.exists("channels_overrides.json"):
            try:
                with open("channels_overrides.json", encoding="utf-8-sig") as f:
                    _merge(d, json.load(f))
            except Exception:
                pass
        _DIR = d
    return _DIR


def exchange_for(label):
    """Return (key, entry) for an explorer label like 'MEXC (deposit)', else (None, unknown)."""
    low = (label or "").lower()
    for key, ent in directory()["exchanges"].items():
        if any(m in low for m in ent.get("match", [key])):
            return key, ent
    return None, dict(directory()["unknown"])


def verified_email(entry, who=("victim", "both")):
    """A verified email this sender may use, or None. Never guesses."""
    for ch in entry.get("channels", []):
        if ch.get("type") == "email" and ch.get("verified") and ch.get("email") and ch.get("who") in who:
            return ch["email"]
    return None


def network_channels():
    n = directory()["network"]
    return sorted(n.items(), key=lambda kv: kv[1].get("order", 99))


def issuers():
    return directory()["issuers"]


def issuer_for_xrpl(addr):
    for key, ent in issuers().items():
        if ent.get("xrpl_issuer") == addr:
            return key, ent
    return None, None
