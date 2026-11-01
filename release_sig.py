"""Signed releases for ScamHunter (Ed25519, RFC 8032), standard library only.

A release is a manifest (RELEASE.json) listing the SHA-256 of every file, signed with the maintainer's
private key (RELEASE.sig). The public key ships with the app (RELEASE_PUBKEY below and SECURITY.md).
The Desk's updater refuses to install a version whose signature or any file hash doesn't check out.

Anyone can verify a downloaded copy:   python release_sig.py verify <folder>
Maintainer (on the machine that holds the private key):
    python release_sig.py keygen                 -> creates the private key outside the repo, prints the public key
    python release_sig.py sign <folder>          -> writes RELEASE.json + RELEASE.sig into <folder>

Ed25519 here is the RFC 8032 reference algorithm in pure Python: slow (fractions of a second per
signature) but dependency-free, which matters for a tool that must install anywhere.
"""
import hashlib
import json
import os
import sys
import time

# Maintainer's public key (hex). Empty until the first signed release; then fixed. Installed copies trust
# exactly this key; changing it requires an update signed by the old key.
RELEASE_PUBKEY = ""

SKIP_DIRS = {".git", "__pycache__", "backups", "entity_cache", "evidence_store", "evidence_bundles", "cases",
             "benchmark/data/results"}
MANIFEST, SIGFILE = "RELEASE.json", "RELEASE.sig"

# ------------------------------------------------------------ Ed25519 (RFC 8032) ---
p = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, p - 2, p) % p
I = pow(2, (p - 1) // 4, p)


def _H(m):
    return hashlib.sha512(m).digest()


def _xrecover(y):
    xx = (y * y - 1) * pow(d * y * y + 1, p - 2, p)
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = (x * I) % p
    if x % 2 != 0:
        x = p - x
    return x


By = 4 * pow(5, p - 2, p) % p
B = (_xrecover(By), By, 1, _xrecover(By) * By % p)     # extended coordinates (X, Y, Z, T)


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    Bb = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G, Hh = Bb - A, D - C, D + C, Bb + A
    return (E * F % p, G * Hh % p, F * G % p, E * Hh % p)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _encode(P):
    zi = pow(P[2], p - 2, p)
    x, y = P[0] * zi % p, P[1] * zi % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decode(s):
    if len(s) != 32:
        raise ValueError("bad point length")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= p:
        raise ValueError("bad point")
    x = _xrecover(y)
    if (x & 1) != sign:
        x = p - x
    P = (x, y, 1, x * y % p)
    if (-x * x + y * y - 1 - d * x * x * y * y) % p != 0:
        raise ValueError("point not on curve")
    return P


def _expand(sk):
    h = _H(sk)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(sk):
    a, _ = _expand(sk)
    return _encode(_mul(a, B))


def sign(sk, msg):
    a, prefix = _expand(sk)
    A = _encode(_mul(a, B))
    r = int.from_bytes(_H(prefix + msg), "little") % L
    R = _encode(_mul(r, B))
    k = int.from_bytes(_H(R + A + msg), "little") % L
    S = (r + k * a) % L
    return R + int.to_bytes(S, 32, "little")


def verify(pk, msg, sig):
    if len(sig) != 64:
        return False
    try:
        A = _decode(pk)
        R = _decode(sig[:32])
    except ValueError:
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= L:
        return False
    k = int.from_bytes(_H(sig[:32] + pk + msg), "little") % L
    lhs = _mul(S, B)
    rhs = _add(R, _mul(k, A))
    return _encode(lhs) == _encode(rhs)


# ------------------------------------------------------------ manifests ---
def fingerprint(pk_hex):
    return hashlib.sha256(bytes.fromhex(pk_hex)).hexdigest()[:16]


def file_hashes(root):
    out = {}
    for d_, dirs, files in os.walk(root):
        rel_d = os.path.relpath(d_, root).replace(os.sep, "/")
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS and f"{rel_d}/{x}".lstrip("./") not in SKIP_DIRS]
        for fn in files:
            rel = os.path.relpath(os.path.join(d_, fn), root).replace(os.sep, "/")
            if rel in (MANIFEST, SIGFILE) or fn.endswith(".pyc"):
                continue
            with open(os.path.join(d_, fn), "rb") as f:
                out[rel] = hashlib.sha256(f.read()).hexdigest()
    return dict(sorted(out.items()))


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def check_folder(root, pubkey_hex=None, repo_files=None):
    """(ok, reason, manifest). `repo_files`: the set of files that the release ships (e.g. names in the
    downloaded zip); every one must be listed and match. Extra local files (user data) are ignored."""
    pubkey_hex = pubkey_hex or RELEASE_PUBKEY
    mp, sp = os.path.join(root, MANIFEST), os.path.join(root, SIGFILE)
    if not (os.path.exists(mp) and os.path.exists(sp)):
        return False, "this version is not signed", None
    raw = open(mp, "rb").read()
    try:
        man = json.loads(raw)
        sig = bytes.fromhex(open(sp).read().strip())
    except Exception:
        return False, "signature files are damaged", None
    if not pubkey_hex:
        return False, "no trusted public key to check against", man
    if man.get("pubkey") != pubkey_hex:
        return False, "signed with a different key than the one this copy trusts", man
    if not verify(bytes.fromhex(pubkey_hex), canonical(man["files"]) + canonical(man.get("meta", {})), sig):
        return False, "signature does not match (release was altered or not signed by the maintainer)", man
    names = repo_files if repo_files is not None else set(man["files"])
    for rel in names:
        if rel in (MANIFEST, SIGFILE):
            continue
        if rel not in man["files"]:
            return False, f"{rel} is not part of the signed release", man
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            return False, f"{rel} is missing", man
        if hashlib.sha256(open(path, "rb").read()).hexdigest() != man["files"][rel]:
            return False, f"{rel} does not match the signed release", man
    return True, f"signed by key {fingerprint(pubkey_hex)}; {len(names)} files verified", man


# ------------------------------------------------------------ maintainer tools ---
def keyfile():
    return os.path.join(os.path.expanduser("~"), ".scamhunter_signing", "ed25519_private.key")


def keygen():
    path = keyfile()
    if os.path.exists(path):
        sk = bytes.fromhex(open(path).read().strip())
        print("Key already exists.")
    else:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        sk = os.urandom(32)
        with open(path, "w") as f:
            f.write(sk.hex())
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        print(f"Private key created at {path}. Back it up somewhere safe and offline; never share or commit it.")
    pk = public_key(sk).hex()
    print(f"PUBLIC KEY: {pk}\nFingerprint: {fingerprint(pk)}")
    return pk


def sign_folder(root, note=""):
    sk = bytes.fromhex(open(keyfile()).read().strip())
    pk = public_key(sk).hex()
    files = file_hashes(root)
    meta = {"signed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "note": note}
    sig = sign(sk, canonical(files) + canonical(meta))
    with open(os.path.join(root, MANIFEST), "w", encoding="utf-8") as f:
        json.dump({"pubkey": pk, "files": files, "meta": meta}, f, indent=1)
    with open(os.path.join(root, SIGFILE), "w") as f:
        f.write(sig.hex())
    print(f"Signed {len(files)} files with key {fingerprint(pk)}")


if __name__ == "__main__":
    cmd = sys.argv[1:2]
    if cmd == ["keygen"]:
        keygen()
    elif cmd == ["sign"]:
        sign_folder(sys.argv[2], " ".join(sys.argv[3:]))
    elif cmd == ["verify"]:
        root = sys.argv[2] if len(sys.argv) > 2 else "."
        man = json.load(open(os.path.join(root, MANIFEST))) if os.path.exists(os.path.join(root, MANIFEST)) else {}
        ok, why, _ = check_folder(root, RELEASE_PUBKEY or man.get("pubkey"))
        print(("VERIFIED: " if ok else "NOT VERIFIED: ") + why)
        if ok and not RELEASE_PUBKEY:
            print("(checked against the key in RELEASE.json; compare its fingerprint with the one in SECURITY.md)")
        sys.exit(0 if ok else 1)
    else:
        print(__doc__)
