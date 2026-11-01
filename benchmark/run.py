"""Run ScamHunter's real methods on every ground-truth case. Resumable: finished cases are skipped.

Each case runs in a worker thread with a time limit; a timeout or error is recorded as such (never as
a pass). Results: benchmark/data/results.jsonl
"""
import json
import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from benchmark import truth  # noqa: E402

RESULTS = os.path.join(truth.DATA, "results.jsonl")
LIMIT = 150     # seconds per case
VERSION = None


def _version():
    try:
        with open(os.path.join(os.path.dirname(HERE), "VERSION")) as f:
            return f.read().strip()[:12]
    except Exception:
        return "unknown"


def _with_limit(fn, limit):
    box = {}

    def go():
        try:
            box["v"] = fn()
        except Exception as e:
            box["e"] = repr(e)[:200]
    t = threading.Thread(target=go, daemon=True)
    t.start()
    t.join(limit)
    if t.is_alive():
        return None, "timeout"
    return box.get("v"), box.get("e")


def identify(case):
    """exchange-label/1 as the pre-screen uses it."""
    from shield import prescreen
    key = case["address"]
    return prescreen._identity(key, case["chain"])


def behaviour_only(case):
    """Pre-screen verdict with every list and identity lookup switched off."""
    from shield import prescreen
    kb, ident = prescreen._known_bad, prescreen._identity
    prescreen._known_bad = lambda a: []
    prescreen._identity = lambda a, c: None
    try:
        r = prescreen.screen(case["address"], case["chain"])
    finally:
        prescreen._known_bad, prescreen._identity = kb, ident
    return {"verdict": r.get("verdict"), "findings": [f"{f['level']}|{f['section']}|{f['text'][:140]}" for f in r.get("findings", [])],
            "movements": (r.get("stats") or {}).get("movements")}


def as_deployed(case):
    """Pre-screen exactly as users get it (lists and identity on)."""
    from shield import prescreen
    r = prescreen.screen(case["address"], case["chain"])
    return {"verdict": r.get("verdict"), "identity": r.get("identity")}


TESTS = {"identify": identify, "behaviour_only": behaviour_only, "as_deployed": as_deployed}
PLAN = {"exchange": ["identify", "behaviour_only", "as_deployed"], "known_bad": ["identify", "behaviour_only"]}


def done():
    out = set()
    if os.path.exists(RESULTS):
        with open(RESULTS, encoding="utf-8") as f:
            for l in f:
                try:
                    r = json.loads(l)
                    out.add((r["case"], r["test"]))
                except Exception:
                    pass
    return out


def run(cases=None, log=print, limit=LIMIT):
    cases = cases or truth.load()
    finished = done()
    ver = _version()
    n = 0
    for c in cases:
        for test in PLAN[c["group"]]:
            if (c["id"], test) in finished:
                continue
            t0 = time.time()
            val, err = _with_limit(lambda: TESTS[test](c), limit)
            rec = {"case": c["id"], "test": test, "value": val, "error": err, "seconds": round(time.time() - t0, 1),
                   "tool_version": ver, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            with open(RESULTS, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
            n += 1
            log(f"{c['id']:40} {test:15} {('ERR ' + err) if err else str(val)[:70]}")
    log(f"ran {n} tests")


if __name__ == "__main__":
    os.chdir(os.path.dirname(HERE))
    run()
