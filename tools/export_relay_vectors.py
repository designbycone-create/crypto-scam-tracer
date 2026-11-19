"""Fixed test vectors so the phone app's encryption is proven identical to the Desk's (relay/envelope.py).

    python tools/export_relay_vectors.py          # writes android/desk/src/test/resources/relay_vectors.json
    python tools/export_relay_vectors.py --check  # exit 1 if it's out of date (used by the tests)

The key and nonces are fixed, public test values. They are never used for a real pairing.
"""
import base64
import json
import os
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from relay import envelope  # noqa: E402

OUT = os.path.join(ROOT, "android", "desk", "src", "test", "resources", "relay_vectors.json")
KEY = bytes(range(32))
CH = "0123456789abcdef0123456789abcdef"
N1, N2 = bytes([1] * 12), bytes([2] * 12)
RID = "00112233445566778899aabb"


def build():
    page = ("<!doctype html><h1>Threat Desk</h1>" + "<p>café ✓</p>" * 50).encode("utf-8")
    zb = base64.b64encode(zlib.compress(page, 6)).decode()
    req_pt = json.dumps({"v": 1, "id": RID, "ts": 1795000000, "m": "POST", "p": "/msgcheck", "ct": "application/x-www-form-urlencoded",
                         "b": base64.b64encode(b"text=hello").decode(), "z": 0}, separators=(",", ":"))
    res_pt = json.dumps({"id": RID, "s": 200, "ct": "text/html; charset=utf-8", "loc": "", "b": zb, "z": 1}, separators=(",", ":"))
    return {"_about": "Fixed public test values for the phone app's unit tests; never a real key.",
            "key": base64.b64encode(KEY).decode(), "channel": CH,
            "request": {"nonce": base64.b64encode(N1).decode(), "plaintext": req_pt,
                        "blob": base64.b64encode(envelope.seal_bytes(KEY, CH, "req", req_pt.encode(), "", N1)).decode()},
            "response": {"nonce": base64.b64encode(N2).decode(), "rid": RID, "plaintext": res_pt, "page": page.decode("utf-8"),
                         "blob": base64.b64encode(envelope.seal_bytes(KEY, CH, "res", res_pt.encode(), RID, N2)).decode()}}


def dumps(o):
    return json.dumps(o, indent=1, ensure_ascii=True, sort_keys=True) + "\n"


if __name__ == "__main__":
    v = dumps(build())
    if "--check" in sys.argv:
        # compressed bytes differ between zlib builds, so check what matters: the saved vectors still open with
        # today's code, and the (uncompressed) request seals to exactly the same bytes
        try:
            saved = json.load(open(OUT, encoding="utf-8"))
            key, ch = base64.b64decode(saved["key"]), saved["channel"]
            rq, rs = saved["request"], saved["response"]
            same = (envelope.seal_bytes(key, ch, "req", rq["plaintext"].encode(), "", base64.b64decode(rq["nonce"]))
                    == base64.b64decode(rq["blob"]))
            res = envelope.unseal(key, ch, "res", base64.b64decode(rs["blob"]), rid=rs["rid"])
            same = same and envelope.unpack_body(res["b"], res["z"]).decode("utf-8") == rs["page"] and key == KEY and ch == CH
        except Exception as ex:
            print("vectors unreadable:", ex)
            same = False
        print("up to date" if same else "OUT OF DATE: run python tools/export_relay_vectors.py")
        sys.exit(0 if same else 1)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(v)
    print("wrote", OUT)
