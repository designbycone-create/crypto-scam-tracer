"""Capture every external read as evidence.

Call `record(...)` wherever the tool talks to the outside world. Each call:
  * writes the raw response bytes to evidence_store/blobs/<sha256>  (once; content-addressed)
  * appends a hash-chained entry to evidence_store/capture_log.jsonl:
      seq, time_utc (local clock, labelled as such), source, method, request,
      response_sha256, size, status, from_cache, ledger_index/block (when known),
      prev_entry_hash, entry_hash
Thread-safe. Never raises into the caller: evidence capture must not break tracing,
but a failure to capture is itself logged.

Activated by default; set SCAMHUNTER_EVIDENCE=0 to turn off (e.g. in tests).
"""
import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone

STORE = os.environ.get("SCAMHUNTER_EVIDENCE_DIR", "evidence_store")
LOG = "capture_log.jsonl"
_lock = threading.Lock()
_state = {"seq": None, "prev": None}


def enabled():
    return os.environ.get("SCAMHUNTER_EVIDENCE", "1") != "0"


def _paths():
    os.makedirs(os.path.join(STORE, "blobs"), exist_ok=True)
    return os.path.join(STORE, LOG)


def _tail():
    """Recover seq + last entry hash from the log (once per process)."""
    if _state["seq"] is not None:
        return
    seq, prev = 0, "0" * 64
    p = os.path.join(STORE, LOG)
    if os.path.exists(p):
        with open(p, "rb") as f:
            for line in f:
                try:
                    e = json.loads(line)
                    seq, prev = e["seq"], e["entry_hash"]
                except Exception:
                    pass
    _state["seq"], _state["prev"] = seq, prev


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _ledger_marker(resp):
    """Pull the ledger/block the answer was read at, if the response says."""
    try:
        d = json.loads(resp) if isinstance(resp, (bytes, str)) else resp
    except Exception:
        return None
    if not isinstance(d, dict):
        return None
    r = d.get("result", d) if isinstance(d.get("result", d), dict) else d
    for k in ("ledger_index", "ledger_current_index", "validated_ledger_index", "blockNumber", "block_number"):
        v = r.get(k) if isinstance(r, dict) else None
        if v is not None:
            return v
    return None


def record(source, method, request, response, status="ok", from_cache=False, note=""):
    """Save one external read. `response` may be bytes, str or a JSON-able object.
    Returns the response sha256 (or None if capture is off/failed)."""
    if not enabled():
        return None
    try:
        if isinstance(response, bytes):
            raw = response
        elif isinstance(response, str):
            raw = response.encode("utf-8")
        else:
            raw = canonical(response).encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        with _lock:
            logp = _paths()
            blob = os.path.join(STORE, "blobs", digest)
            if not os.path.exists(blob):
                tmp = blob + ".tmp"
                with open(tmp, "wb") as f:
                    f.write(raw)
                os.replace(tmp, blob)
            _tail()
            seq = _state["seq"] + 1
            entry = {"seq": seq, "time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                     "clock": "local system clock (not authoritative; ledger close times are)",
                     "source": source, "method": method, "request": request,
                     "response_sha256": digest, "size": len(raw), "status": status,
                     "from_cache": bool(from_cache), "ledger_or_block": _ledger_marker(raw), "note": note,
                     "prev_entry_hash": _state["prev"]}
            entry["entry_hash"] = hashlib.sha256(canonical(entry).encode()).hexdigest()
            with open(logp, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            _state["seq"], _state["prev"] = seq, entry["entry_hash"]
        return digest
    except Exception as e:     # never break the caller
        try:
            with open(os.path.join(STORE, "capture_errors.log"), "a", encoding="utf-8") as f:
                f.write(f"{time.time()} {source} {method} capture failed: {e!r}\n")
        except Exception:
            pass
        return None


def blob(digest):
    with open(os.path.join(STORE, "blobs", digest), "rb") as f:
        return f.read()


def verify_log(path=None):
    """(ok, entries, first_bad_seq_or_None, reason)."""
    path = path or os.path.join(STORE, LOG)
    prev, n = "0" * 64, 0
    if not os.path.exists(path):
        return True, 0, None, "no log"
    with open(path, encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            h = e.pop("entry_hash")
            if e["prev_entry_hash"] != prev:
                return False, n, e["seq"], "chain broken (entry removed or reordered)"
            if hashlib.sha256(canonical(e).encode()).hexdigest() != h:
                return False, n, e["seq"], "entry altered"
            prev, n = h, n + 1
    return True, n, None, "intact"
