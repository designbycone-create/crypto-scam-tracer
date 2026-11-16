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


def is_ltc_legacy(a):
    """Litecoin P2PKH (L...) / P2SH (M...): version bytes 0x30 / 0x32."""
    b = _b58check(a, _BTC_ALPHA) if a[:1] in ("L", "M") else None
    return bool(b) and len(b) == 21 and b[0] in (0x30, 0x32)


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


# ---- Keccak-256 (pure Python, for EIP-55 checksums; no extra packages needed) ----
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = (1 << 64) - 1


def _keccak_f(A):
    for rc in _RC:
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ (((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63)) & _M64) for x in range(5)]
        A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _ROT[x][y]
                B[y][(2 * x + 3 * y) % 5] = ((A[x][y] << r) | (A[x][y] >> (64 - r))) & _M64 if r else A[x][y]
        A = [[B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        A[0][0] ^= rc
    return A


def keccak256(data):
    rate = 136
    msg = bytearray(data) + b"\x01"
    msg += b"\x00" * ((-len(msg)) % rate)
    msg[-1] |= 0x80
    A = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        blk = msg[off:off + rate]
        for i in range(rate // 8):
            A[i % 5][i // 5] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
        A = _keccak_f(A)
    out = b"".join(A[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out


def is_evm(a):
    """0x + 40 hex. Mixed case must match the EIP-55 checksum (a one-character typo is caught);
    all-lowercase / all-uppercase carry no checksum and are accepted."""
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", a or ""):
        return False
    body = a[2:]
    if body == body.lower() or body == body.upper():
        return True
    h = keccak256(body.lower().encode()).hex()
    return all((c.upper() if int(h[i], 16) >= 8 else c.lower()) == c for i, c in enumerate(body))


# ---- Bech32 / Bech32m (BIP-173 / BIP-350): bc1..., ltc1... ----
_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _b32_polymod(values):
    g = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= g[i] if (b >> i) & 1 else 0
    return chk


def is_segwit(a, hrp):
    """Full checksum + witness-program check for a SegWit address with this prefix (bc / ltc)."""
    if not a or a.lower() != a and a.upper() != a:
        return False
    a = a.lower()
    pos = a.rfind("1")
    if a[:pos] != hrp or pos + 7 > len(a) or len(a) > 90 or any(c not in _B32 for c in a[pos + 1:]):
        return False
    data = [_B32.find(c) for c in a[pos + 1:]]
    const = _b32_polymod([ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + data)
    ver = data[0]
    if const not in (1, 0x2bc830a3) or (ver == 0) != (const == 1) or ver > 16:
        return False
    acc, bits, prog = 0, 0, []
    for v in data[1:-6]:
        acc, bits = (acc << 5) | v, bits + 5
        while bits >= 8:
            bits -= 8
            prog.append((acc >> bits) & 0xff)
    if bits >= 5 or (acc << (8 - bits)) & 0xff:
        return False
    return 2 <= len(prog) <= 40 and (ver != 0 or len(prog) in (20, 32))


# ---- Dogecoin (D... / A... / 9...) ----
def is_doge(a):
    b = _b58check(a, _BTC_ALPHA) if a[:1] in ("D", "A", "9") else None
    return bool(b) and len(b) == 21 and b[0] in (0x1e, 0x16)


# ---- Bitcoin Cash CashAddr (bitcoincash:q... / p..., prefix optional) ----
def is_bch(a):
    a = (a or "").strip()
    if a.lower() != a and a.upper() != a:
        return False
    a = a.lower()
    prefix, _, payload = a.rpartition(":")
    prefix = prefix or "bitcoincash"
    if prefix != "bitcoincash" or len(payload) != 42 or payload[0] not in "qp" or any(c not in _B32 for c in payload):
        return False
    vals = [ord(c) & 31 for c in prefix] + [0] + [_B32.find(c) for c in payload]
    c = 1
    for d in vals:
        c0 = c >> 35
        c = ((c & 0x07ffffffff) << 5) ^ d
        for i, k in enumerate((0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470)):
            if c0 & (1 << i):
                c ^= k
    return c ^ 1 == 0


# ---- TON user-friendly address (48 chars base64/base64url, CRC16-XMODEM) ----
def _crc16(data):
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
            crc &= 0xffff
    return crc


def is_ton(a):
    import base64
    if not a or len(a) != 48 or not re.fullmatch(r"[A-Za-z0-9_\-+/]{48}", a):
        return False
    try:
        raw = base64.urlsafe_b64decode(a.replace("+", "-").replace("/", "_"))
    except Exception:
        return False
    return len(raw) == 36 and raw[0] & 0x3f == 0x11 and raw[1] in (0x00, 0xff) and \
        _crc16(raw[:34]) == int.from_bytes(raw[34:], "big")


_RX = {
    "xrpl": re.compile(r"\br[1-9A-HJ-NP-Za-km-z]{24,34}\b"),
    "tron": re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b"),
    "bitcoin": re.compile(r"\b(?:[13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[02-9ac-hj-np-z]{11,71})\b"),
    "litecoin": re.compile(r"\b(?:[LM][1-9A-HJ-NP-Za-km-z]{25,34}|ltc1[02-9ac-hj-np-z]{11,71})\b"),
    "ethereum": re.compile(r"\b0x[0-9a-fA-F]{40}\b"),
    "aptos": re.compile(r"\b0x[0-9a-fA-F]{62,64}\b"),   # Aptos accounts (EVM addresses are 40 hex)
    "dogecoin": re.compile(r"\b[DA9][1-9A-HJ-NP-Za-km-z]{25,34}\b"),
    "bitcoin-cash": re.compile(r"(?<![0-9a-z])(?:bitcoincash:)?[qp][02-9ac-hj-np-z]{41}(?![0-9a-z])", re.I),
    "ton": re.compile(r"(?<![A-Za-z0-9_\-+/])[EU]Q[A-Za-z0-9_\-+/]{46}(?![A-Za-z0-9_\-+/])"),
    "solana": re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b"),
}

# chains the tracer, freeze kits and wallet lookups support (others are recognised for warnings only)
TRACEABLE = {"xrpl", "tron", "bitcoin", "litecoin", "ethereum", "aptos", "solana"}


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
                  "bitcoin": lambda x: is_segwit(x, "bc") if x.lower().startswith("bc1") else is_btc_legacy(x),
                  "litecoin": lambda x: is_segwit(x, "ltc") if x.lower().startswith("ltc1") else is_ltc_legacy(x),
                  "ethereum": is_evm, "aptos": lambda x: True, "dogecoin": is_doge,
                  "bitcoin-cash": is_bch, "ton": is_ton, "solana": is_solana}[chain](a)
            if chain == "solana" and (is_doge(a) or is_ltc_legacy(a)):
                ok = False
            key = (chain, a.lower() if chain in ("ethereum", "aptos", "bitcoin-cash") else a)
            if ok and key not in seen:
                seen.add(key)
                out.append((chain, a))
    return out
