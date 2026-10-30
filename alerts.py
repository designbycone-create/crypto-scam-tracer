"""Reliable alerts shared by every watcher: ntfy push + Telegram + email.

Why this exists: a free ntfy.sh topic has a daily message quota. If low-value
alerts use it up, a critical one (funds reaching an exchange) gets rejected
with HTTP 429 and is silently lost. This module makes alerts reliable:

  * every alert has a priority: "critical" (cash-outs) or "normal",
  * duplicate alerts (same key) within a window are suppressed,
  * anything that fails to send goes into an outbox on disk
    (alerts_outbox.json) and is retried -- critical first -- until delivered,
  * delivery state is recorded in alerts_state.json so the Desk can show a
    red banner listing anything still undelivered.

Channels (configure any in config.json; critical alerts go to ALL of them, so
one channel being down or over quota never loses a cash-out alert):
  "ntfy_topic": "your-topic"
  "telegram": {"bot_token": "...", "chat_id": "..."}          (free; @BotFather)
  "alert_email": {"smtp_host": "smtp.gmail.com", "smtp_port": 465,
                  "username": "you@gmail.com", "app_password": "16-char app password",
                  "to": "you@gmail.com"}                        (critical only)

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
        with open(path, encoding="utf-8-sig") as f:   # tolerate a BOM (Windows editors)
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


def _cfg(key):
    return (scamconfig.get(key) if scamconfig else None) or {}


def channels(critical):
    """Configured channels for an alert of this priority."""
    out = []
    if _topic():
        out.append("ntfy")
    tg = _cfg("telegram")
    if tg.get("bot_token") and tg.get("chat_id"):
        out.append("telegram")
    em = _cfg("alert_email")
    if critical and em.get("smtp_host") and em.get("username") and em.get("app_password"):
        out.append("email")
    return out


def _post_ntfy(item):
    topic = _topic()
    payload = {"topic": topic, "title": item["title"], "message": item["message"],
               "priority": 5 if item.get("critical") else 3,
               "tags": ["rotating_light"] if item.get("critical") else ["mag"]}
    if item.get("actions"):
        payload["actions"] = [{"action": "view", "label": l, "url": u, "clear": True}
                              for (l, u) in item["actions"][:3]]
    req = urllib.request.Request("https://ntfy.sh/", data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10)


def _post_telegram(item):
    tg = _cfg("telegram")
    text = f"{'🚨 ' if item.get('critical') else ''}{item['title']}\n\n{item['message']}"
    for (l, u) in (item.get("actions") or [])[:3]:
        text += f"\n{l}: {u}"
    data = json.dumps({"chat_id": tg["chat_id"], "text": text[:4000],
                       "disable_web_page_preview": True}).encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{tg['bot_token']}/sendMessage", data=data,
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=10)


def _post_email(item):
    import smtplib
    import ssl
    from email.message import EmailMessage
    em = _cfg("alert_email")
    msg = EmailMessage()
    msg["Subject"] = ("[URGENT] " if item.get("critical") else "") + item["title"]
    msg["From"] = em["username"]
    msg["To"] = em.get("to") or em["username"]
    body = item["message"] + "".join(f"\n{l}: {u}" for (l, u) in (item.get("actions") or []))
    msg.set_content(body)
    port = int(em.get("smtp_port") or 465)
    if port == 465:
        with smtplib.SMTP_SSL(em["smtp_host"], port, context=ssl.create_default_context(), timeout=20) as s:
            s.login(em["username"], em["app_password"])
            s.send_message(msg)
    else:
        with smtplib.SMTP(em["smtp_host"], port, timeout=20) as s:
            s.starttls(context=ssl.create_default_context())
            s.login(em["username"], em["app_password"])
            s.send_message(msg)


_SENDERS = {"ntfy": _post_ntfy, "telegram": _post_telegram, "email": _post_email}


def _post(item):
    """Try every channel still pending for this item. Returns (all_done, error)."""
    pend = item.get("pending_channels")
    if pend is None:
        pend = channels(item.get("critical"))
    if not pend:
        return False, "no alert channel configured (set ntfy_topic / telegram / alert_email)"
    left, errs = [], []
    for ch in pend:
        try:
            _SENDERS[ch](item)
            item.setdefault("delivered_via", []).append(ch)
        except Exception as e:
            left.append(ch)
            errs.append(f"{ch}: {e}")
    item["pending_channels"] = left
    return (not left), "; ".join(errs)


def _record(ok, err, item):
    st = _load(STATE, {})
    if item.get("delivered_via"):
        st["last_delivered_via"] = item["delivered_via"][-1]
    if err:
        st["last_error"] = err
        st["last_error_at"] = _now()
    if ok:
        st["last_delivered"] = _now()
        st["last_delivered_title"] = item["title"]
        st["delivered_total"] = st.get("delivered_total", 0) + 1
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
    flush()  # retry older queued alerts first
    # Always try now: channels are independent, so ntfy being over quota must
    # not stop Telegram / email from delivering this alert immediately.
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
            # stop when nothing at all is getting through (all channels failing)
            stop = not item.get("delivered_via")
    _save(OUTBOX, remaining)
    return sent


def pending():
    return _load(OUTBOX, [])


def state():
    return _load(STATE, {})


def test():
    """Send a test alert to every configured channel and report each result."""
    item = {"title": "ScamHunter test alert", "message": "If you can read this, this alert channel works.",
            "critical": True, "actions": [], "key": None}
    chans = channels(True)
    if not chans:
        print("No alert channels configured. Add ntfy_topic, telegram, or alert_email to config.json.")
        return
    for ch in chans:
        try:
            _SENDERS[ch](item)
            print(f"  {ch:9} OK")
        except Exception as e:
            print(f"  {ch:9} FAILED: {e}")


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["test"]:
        test()
    else:
        print("usage: python alerts.py test")
