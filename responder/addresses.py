"""Find and VALIDATE crypto addresses in free text (checksums, not just regex)."""
import hashlib
import re

_XRPL_ALPHA = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
_BTC_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58check(s, alpha):
    n = 0
    for ch in s:
        i = alpha.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip(alpha[0]))
    raw = b"\x00" * pad + raw
    if len(raw) < 5:
        return None
    body, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != chk:
        return None
    return body


def is_xrpl(a):
    b = _b58check(a, _XRPL_ALPHA) if a.startswith("r") else None
    return bool(b) and len(b) == 21 and b[0] == 0


def is_tron(a):
    b = _b58check(a, _BTC_ALPHA) if a.startswith("T") else None
    return bool(b) and len(b) == 21 and b[0] == 0x41


def is_btc_legacy(a):
    b = _b58check(a, _BTC_ALPHA) if a[:1] in ("1", "3") else None
    return bool(b) and len(b) == 21 and b[0] in (0x00, 0x05)


def _b58decode(s):
    n = 0
    for ch in s:
        i = _BTC_ALPHA.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


def b58check_encode(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _BTC_ALPHA[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def is_solana(a):
    if not (32 <= len(a) <= 44) or is_tron(a) or is_btc_legacy(a) or is_xrpl(a):
        return False
    raw = _b58decode(a)
    return raw is not None and len(raw) == 32


_RX = {
    "xrpl": re.compile(r"\br[1-9A-HJ-NP-Za-km-z]{24,34}\b"),
    "tron": re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b"),
    "bitcoin": re.compile(r"\b(?:[13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[02-9ac-hj-np-z]{11,71})\b"),
    "ethereum": re.compile(r"\b0x[0-9a-fA-F]{40}\b"),
    "solana": re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b"),
}


def extract(text):
    """Return [(chain, address)] -- validated, de-duplicated, in order found.
    EVM addresses are reported as 'ethereum' (same address on every EVM chain);
    any EVM chain can be passed as the hint when seeding the tracer."""
    out, seen = [], set()
    text = text or ""
    for chain, rx in _RX.items():
        for m in rx.finditer(text):
            a = m.group(0)
            ok = {"xrpl": is_xrpl, "tron": is_tron,
                  "bitcoin": lambda x: x.startswith("bc1") or is_btc_legacy(x),
                  "ethereum": lambda x: True, "solana": is_solana}[chain](a)
            key = (chain, a.lower() if chain == "ethereum" else a)
            if ok and key not in seen:
                seen.add(key)
                out.append((chain, a))
    return out
