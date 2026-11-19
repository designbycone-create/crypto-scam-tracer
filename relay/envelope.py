"""End-to-end encryption between the Desk and the paired phone (AES-256-GCM).

blob = 0x01 | nonce (12 random bytes) | ciphertext+tag
AAD  = "shtd1|<channel>|req|"      for requests (the request id is inside, checked after decrypting)
       "shtd1|<channel>|res|<id>"  for responses (bound to the request they answer)
So a captured blob can't be replayed on another channel, turned around in the other direction, or
used as the answer to a different request. Requests also carry a timestamp; the Desk refuses any
older than 2 minutes and any id it has already seen.
"""
import base64
import json
import os
import threading
import time
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = b"\x01"
MAX_AGE = 120
MAX_BODY = 4 * 1024 * 1024


class EnvelopeError(Exception):
    pass


def _aad(channel, direction, rid=""):
    return f"shtd1|{channel}|{direction}|{rid}".encode()


def seal(key, channel, direction, obj, rid=""):
    nonce = os.urandom(12)
    return VERSION + nonce + AESGCM(key).encrypt(nonce, json.dumps(obj, separators=(",", ":")).encode(), _aad(channel, direction, rid))


def unseal(key, channel, direction, blob, rid=""):
    if not blob or blob[:1] != VERSION or len(blob) < 1 + 12 + 16:
        raise EnvelopeError("not a ScamHunter message")
    try:
        pt = AESGCM(key).decrypt(blob[1:13], blob[13:], _aad(channel, direction, rid))
    except Exception:
        raise EnvelopeError("message failed its integrity check (wrong key, altered, or for another channel)")
    return json.loads(pt)


def pack_body(data):
    """bytes -> (base64 text, compressed?)"""
    z = zlib.compress(data, 6)
    return (base64.b64encode(z).decode(), 1) if len(z) < len(data) else (base64.b64encode(data).decode(), 0)


def unpack_body(b64, z):
    raw = base64.b64decode(b64 or "")
    if z:
        d = zlib.decompressobj()
        raw = d.decompress(raw, MAX_BODY + 1)
        if len(raw) > MAX_BODY or d.unconsumed_tail:
            raise EnvelopeError("body too large")
    return raw


class ReplayGuard:
    def __init__(self, window=MAX_AGE):
        self.window, self.seen, self.lock = window, {}, threading.Lock()

    def check(self, rid, ts, now=None):
        now = time.time() if now is None else now
        if not isinstance(rid, str) or not 16 <= len(rid) <= 64:
            raise EnvelopeError("bad request id")
        if not isinstance(ts, (int, float)) or abs(now - ts) > self.window:
            raise EnvelopeError("request too old or clock badly wrong (check the phone's date and time)")
        with self.lock:
            for k in [k for k, t in self.seen.items() if now - t > 2 * self.window]:
                del self.seen[k]
            if rid in self.seen:
                raise EnvelopeError("request replayed")
            self.seen[rid] = now


def make_request(key, channel, method, path, body=b"", ctype="", ts=None):
    """What the phone sends (used by tests and the Kotlin parity vectors)."""
    rid = os.urandom(12).hex()
    b, z = pack_body(body)
    obj = {"v": 1, "id": rid, "ts": int(time.time() if ts is None else ts), "m": method, "p": path, "ct": ctype, "b": b, "z": z}
    return rid, seal(key, channel, "req", obj)
