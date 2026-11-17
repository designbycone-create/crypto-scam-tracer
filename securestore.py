"""Keys and tokens in config.json are stored encrypted, not as plain text.

Why: tools that steal keys copy settings files and search them for anything that looks like a
token (see 1Password, "After the breach, attackers go credential harvesting", Nov 2026). An
encrypted value is useless to them.

How: on Windows each secret is sealed with DPAPI (the protection Windows uses for its own saved
passwords). Only your Windows account on this computer can unlock it, so a copy of config.json
taken to another machine, a backup or a cloud-synced folder reveals nothing. Values look like
"dpapi:AQAAANCMnd8B...". Everything else in config.json (wallets, cases, switches) stays readable.

What it does NOT stop: malware already running as you can ask Windows to unlock them too. It
stops the common case: a script that grabs files and leaves.

On Mac and Linux there is no DPAPI, so values stay as they are and the file is made readable
by your account only (chmod 600).

    python securestore.py status      # how many secrets are encrypted / still plain text
    python securestore.py migrate     # encrypt any plain-text secrets now (the Desk does this on start)
    python securestore.py selftest    # prove encryption works on this computer (prints no secrets)
"""
import base64
import copy
import json
import os
import sys

PREFIX = "dpapi:"
_ENTROPY = b"ScamHunter-config-v1"
CFG = "config.json"

# top-level keys that are secrets (keys, tokens, endpoints that embed a key, the private ntfy topic)
SECRET_KEYS = {"ntfy_topic", "ftc_api_key", "etherscan_key", "blockscout_key", "routescan_key", "ankr_key",
               "aptos_indexer_key", "bithomp_token", "extension_token", "agentguard_token"}
NESTED = {"telegram": {"bot_token"}, "alert_email": {"app_password"}}


def _is_secret(key):
    return key in SECRET_KEYS or key.endswith("_rpc")      # personal RPC URLs usually carry the key in the path


# ---------------------------------------------------------------- Windows DPAPI ----

def _dpapi():
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32

        def _blob(b):
            buf = ctypes.create_string_buffer(b, len(b))
            return BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

        def _run(fn, data):
            src, _k1 = _blob(data)
            ent, _k2 = _blob(_ENTROPY)
            out = BLOB()
            if not fn(ctypes.byref(src), None, ctypes.byref(ent), None, None, 0x1, ctypes.byref(out)):   # 0x1 = no UI
                raise OSError("Windows could not " + ("seal" if fn is crypt32.CryptProtectData else "unlock") + " the value")
            try:
                return ctypes.string_at(out.pbData, out.cbData)
            finally:
                kernel32.LocalFree(out.pbData)

        def protect(b):
            return _run(crypt32.CryptProtectData, b)

        def unprotect(b):
            return _run(crypt32.CryptUnprotectData, b)
        return protect, unprotect
    except Exception:
        return None


BACKEND = _dpapi()          # (protect(bytes)->bytes, unprotect(bytes)->bytes) or None; tests swap in a fake


def available():
    return BACKEND is not None


def protect(value):
    """Seal one secret string. Empty, non-string and already-sealed values are returned unchanged."""
    if not isinstance(value, str) or not value or value.startswith(PREFIX) or BACKEND is None:
        return value
    return PREFIX + base64.b64encode(BACKEND[0](value.encode("utf-8"))).decode("ascii")


def reveal(value):
    """Plain text of a sealed secret ("" if this account can't unlock it); anything else unchanged."""
    if not isinstance(value, str) or not value.startswith(PREFIX):
        return value
    if BACKEND is None:
        return ""
    try:
        return BACKEND[1](base64.b64decode(value[len(PREFIX):])).decode("utf-8")
    except Exception:
        return ""           # sealed by another account or computer: treated as "not set", never guessed


def _walk(cfg, fn):
    out = copy.deepcopy(cfg) if isinstance(cfg, dict) else {}
    for k, v in list(out.items()):
        if _is_secret(k) and isinstance(v, str):
            out[k] = fn(v)
        elif k in NESTED and isinstance(v, dict):
            for nk in NESTED[k]:
                if isinstance(v.get(nk), str):
                    v[nk] = fn(v[nk])
    return out


def reveal_config(cfg):
    return _walk(cfg, reveal)


def protect_config(cfg):
    return _walk(cfg, protect)


def _plain_secrets(cfg):
    n = 0
    for k, v in (cfg or {}).items():
        if _is_secret(k) and isinstance(v, str) and v and not v.startswith(PREFIX):
            n += 1
        elif k in NESTED and isinstance(v, dict):
            n += sum(1 for nk in NESTED[k] if isinstance(v.get(nk), str) and v[nk] and not v[nk].startswith(PREFIX))
    return n


def status(path=CFG):
    try:
        with open(path, encoding="utf-8-sig") as f:
            cfg = json.load(f)
    except Exception:
        return {"exists": os.path.exists(path), "plain": 0, "sealed": 0, "available": available()}
    sealed = json.dumps(cfg).count('"' + PREFIX)
    return {"exists": True, "plain": _plain_secrets(cfg), "sealed": sealed, "available": available()}


def save(cfg, path=CFG):
    """Write config.json with every secret sealed (callers pass plain or sealed values)."""
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(protect_config(cfg), f, indent=2)
    if os.name != "nt":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def migrate(path=CFG, log=None):
    """Seal any plain-text secrets in config.json. Proves a round trip first; changes nothing if
    encryption doesn't work here. Returns the number of secrets sealed."""
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8-sig") as f:
        cfg = json.load(f)
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    n = _plain_secrets(cfg)
    if not n or not available():
        return 0
    sealed = protect_config(cfg)
    if reveal_config(sealed) != reveal_config(cfg):          # every value must come back exactly before we write
        raise RuntimeError("encryption round-trip failed; config.json left unchanged")
    save(sealed, path)
    if log:
        log(f"Encrypted {n} secret(s) in {path} (Windows account protection).")
    return n


def selftest():
    if not available():
        return False, "no Windows account protection on this system (values stay plain; file limited to your account)"
    probe = base64.b32encode(os.urandom(15)).decode()
    s = protect(probe)
    return (reveal(s) == probe and probe not in s), "seal and unlock round trip"


if __name__ == "__main__":
    cmd = (sys.argv[1:] or ["status"])[0]
    if cmd == "migrate":
        print(migrate(log=print), "secret(s) encrypted")
    elif cmd == "selftest":
        ok, why = selftest()
        print("OK" if ok else "NOT AVAILABLE", "-", why)
    else:
        print(status())
