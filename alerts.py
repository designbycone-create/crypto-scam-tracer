"""Reliable phone alerts (ntfy) shared by every watcher.

Why this exists: a free ntfy.sh topic has a daily message quota. If low-value
alerts use it up, a critical one (funds reaching an exchange) gets rejected
with HTTP 429 and is silently lost. This module makes alerts reliable:

  * every alert has a priority: "critical" (cash-outs) or "normal",
  * duplicate alerts (same key) within a window are suppressed,
  * anything that fails to send goes into an outbox on disk
    (alerts_outbox.json) and is retried -- critical first -- until delivered,
  * delivery state is recorded in alerts_state.json so the Desk can show a
    red banner listing anything still undelivered.

Standard-library only. Safe to call from several processes (simple file
locking via atomic replace; worst case an alert is sent twice, never lost).
"""
import json
import os
import time
import urllib.request
from datetime import datetime

OUTBOX = "alerts_outbox.json"
STATE = "alerts_state.json"
DEDUP_SECONDS = 7 * 24 * 3600   # tx-hash keys: never re-alert the same transaction within a week

try:
    import scamconfig
except Exception:
    scamconfig = None


def _topic():
    t = (scamconfig.get("ntfy_topic") if scamconfig else "") or os.environ.get("NTFY_TOPIC", "")
    return (t or "").strip()


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save(path, data):
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass


def _post(item):
    topic = _topic()
    if not topic:
        return False, "no ntfy topic configured"
    payload = {"topic": topic, "title": item["title"], "message": item["message"],
               "priority": 5 if item.get("critical") else 3,
               "tags": ["rotating_light"] if item.get("critical") else ["mag"]}
    if item.get("actions"):
        payload["actions"] = [{"action": "view", "label": l, "url": u, "clear": True}
                              for (l, u) in item["actions"][:3]]
    try:
        req = urllib.request.Request("https://ntfy.sh/", data=json.dumps(payload).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
        return True, ""
    except Exception as e:
        return False, str(e)


def _record(ok, err, item):
    st = _load(STATE, {})
    if ok:
        st["last_delivered"] = _now()
        st["last_delivered_title"] = item["title"]
        st["delivered_total"] = st.get("delivered_total", 0) + 1
    else:
        st["last_error"] = err
        st["last_error_at"] = _now()
    sent = st.setdefault("sent_keys", {})
    if ok and item.get("key"):
        sent[item["key"]] = time.time()
        for k in [k for k, t in sent.items() if time.time() - t > DEDUP_SECONDS]:
            sent.pop(k, None)
    _save(STATE, st)


def _seen(key):
    if not key:
        return False
    t = _load(STATE, {}).get("sent_keys", {}).get(key)
    if t and time.time() - t < DEDUP_SECONDS:
        return True
    return any(i.get("key") == key for i in _load(OUTBOX, []))


def send(title, message, critical=False, actions=None, key=None):
    """Send an alert now; if that fails, queue it for retry. Returns True if delivered now."""
    if _seen(key):
        return True
    item = {"title": title, "message": message, "critical": bool(critical),
            "actions": actions or [], "key": key, "queued_at": _now(), "attempts": 0}
    flush()  # deliver older queued alerts first, so order is preserved
    if _load(OUTBOX, []):
        _enqueue(item)
        return False
    ok, err = _post(item)
    _record(ok, err, item)
    if not ok:
        item["attempts"] = 1
        item["last_error"] = err
        _enqueue(item)
    return ok


def _enqueue(item):
    box = _load(OUTBOX, [])
    box.append(item)
    _save(OUTBOX, box)


def flush(max_items=10):
    """Retry queued alerts, critical first. Stops at the first failure (quota)."""
    box = _load(OUTBOX, [])
    if not box:
        return 0
    box.sort(key=lambda i: (not i.get("critical"), i.get("queued_at", "")))
    sent = 0
    remaining = []
    stop = False
    for item in box:
        if stop or sent >= max_items:
            remaining.append(item)
            continue
        ok, err = _post(item)
        _record(ok, err, item)
        if ok:
            sent += 1
        else:
            item["attempts"] = item.get("attempts", 0) + 1
            item["last_error"] = err
            remaining.append(item)
            stop = True
    _save(OUTBOX, remaining)
    return sent


def pending():
    return _load(OUTBOX, [])


def state():
    return _load(STATE, {})
