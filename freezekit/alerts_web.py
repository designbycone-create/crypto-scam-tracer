"""Desk page /alerts: connect phone alerts with no command line.

Telegram, in the browser:
  1. User creates a bot with @BotFather (Telegram's official bot) and pastes the token here.
  2. We check it (getMe) and show a link to the new bot: the user presses START.
  3. "I pressed Start": we read the bot's updates, take the user's chat id, save both to
     config.json, send a test message, and restart the watchers so they pick it up.
The token stays in this computer's config.json and is only ever sent to api.telegram.org.

Each channel also has an on/off switch (pause without losing its settings). The switch is
config.json "alerts_enabled"; alerts.py reads it on every alert, so no restart is needed.
"""
import html
import json
import os
import threading
import time
import urllib.error
import urllib.request

CFG = "config.json"
API = None   # test hook: f(token, method, params) -> result
_pending = {}   # token waiting for START -> bot username


def _api(token, method, **params):
    if API:
        return API(token, method, params)
    data = json.dumps(params).encode() if params else None
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/{method}", data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            out = json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            out = json.loads(e.read())
        except Exception:
            raise RuntimeError(f"Telegram answered HTTP {e.code}")
    if not out.get("ok"):
        raise RuntimeError(out.get("description") or "Telegram refused the request")
    return out["result"]



def _cfg():
    try:
        with open(CFG, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(cfg):
    tmp = CFG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CFG)
    try:
        import scamconfig
        scamconfig._cache = None
    except Exception:
        pass


def _restart_later():
    def go():
        time.sleep(1)
        try:
            import desk
            desk.restart_all()
        except Exception:
            pass
    threading.Thread(target=go, daemon=True).start()


CSS = """<style>body{font:15px/1.55 system-ui,sans-serif;background:#0f1115;color:#e8eaf0;margin:0}
.w{max-width:780px;margin:0 auto;padding:22px 16px}a{color:#5aa2ff}.card{background:#151922;border:1px solid #262b36;
border-radius:12px;padding:16px 18px;margin:14px 0}.btn{display:inline-block;background:#3b6cff;color:#fff;border:0;border-radius:8px;
padding:10px 16px;font-size:15px;cursor:pointer;text-decoration:none}.ghost{background:#262b36}.mut{color:#9aa1b2}
input{background:#0f1115;color:#e8eaf0;border:1px solid #33406b;border-radius:8px;padding:9px;width:100%;box-sizing:border-box;margin:6px 0 10px;
font-family:ui-monospace,Consolas,monospace}.ok{color:#86efac}.bad{color:#ff8a7a}ol li{margin:6px 0}</style>"""


def _shell(body):
    return (f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>Alerts</title>{CSS}<div class=w><p><a href='/'>&larr; Desk</a></p>{body}</div>")


def _flags(c):
    raw = c.get("alerts_enabled") or {}
    return {ch: raw.get(ch, True) is not False for ch in ("ntfy", "telegram")}


def _switch(channel, on):
    """A one-button form that turns `channel` the other way."""
    label = f"Turn {'ntfy' if channel == 'ntfy' else 'Telegram'} {'off' if on else 'on'}"
    return (f"<form method=post action='/alerts' style='display:inline'><input type=hidden name=do value=switch>"
            f"<input type=hidden name=channel value={channel}><input type=hidden name=to value={'off' if on else 'on'}>"
            f"<button class='btn{' ghost' if on else ''}'>{label}</button></form>")


def _badge(configured, on, yes="&#10003; on"):
    if not configured:
        return "<span class=bad>off</span>"
    return f"<span class=ok>{yes}</span>" if on else "<span class=bad>paused</span>"


def page(msg="", err=""):
    e = html.escape
    c = _cfg()
    flags = _flags(c)
    tg = c.get("telegram") or {}
    topic = c.get("ntfy_topic") or ""
    connected = bool(tg.get("bot_token") and tg.get("chat_id"))
    out = ["<h1>&#128276; Phone alerts</h1>",
           "<p class=mut>Get a message the moment the scammer moves money, above all when it reaches an exchange, "
           "which is when a freeze is possible. Two channels are better than one.</p>"]
    if msg:
        out.append(f"<div class=card>{msg}</div>")
    if err:
        out.append(f"<div class=card><span class=bad>{e(err)}</span></div>")
    if (topic or connected) and not any(flags[ch] for ch, ok in (("ntfy", topic), ("telegram", connected)) if ok):
        out.append("<div class=card><span class=bad><b>Every phone channel is turned off.</b> Alerts will only show "
                   "on the Desk until you turn one back on.</span></div>")
    # ntfy
    out.append(f"<div class=card><h3>ntfy {_badge(bool(topic), flags['ntfy'])}</h3>"
               + (f"<p>Your private topic: <b>{e(topic)}</b>. In the free ntfy app, subscribe to it. "
                  f"<a href='https://ntfy.sh/{e(topic)}' target=_blank>Open in browser</a></p>"
                  + ("" if flags["ntfy"] else "<p class=mut>Paused: nothing is sent to ntfy (it does not use the "
                     "free daily ntfy allowance). Your topic is kept.</p>")
                  + _switch("ntfy", flags["ntfy"]) if topic
                  else "<p>Set up during first-run setup.</p>") + "</div>")
    # telegram
    if connected:
        out.append(f"<div class=card><h3>Telegram {_badge(True, flags['telegram'], '&#10003; connected')}</h3>"
                   + ("" if flags["telegram"] else "<p class=mut>Paused: nothing is sent to Telegram. "
                      "Your bot stays connected.</p>")
                   + _switch("telegram", flags["telegram"]) + " "
                   "<form method=post action='/alerts' style='display:inline'><input type=hidden name=do value=test>"
                   "<button class=btn>Send a test alert</button></form> "
                   "<form method=post action='/alerts' style='display:inline'><input type=hidden name=do value=tg_off>"
                   "<button class='btn ghost'>Disconnect Telegram</button></form></div>")
    else:
        pend = next(iter(_pending.items()), None)
        if pend:
            out.append(f"""<div class=card><h3>Telegram: last step</h3>
<ol><li>Open your bot: <a class=btn href='https://t.me/{e(pend[1])}' target=_blank>@{e(pend[1])}</a></li>
<li>Press <b>START</b> (or send it any message).</li><li>Come back and press:</li></ol>
<form method=post action='/alerts'><input type=hidden name=do value=tg_link><button class=btn>I pressed Start</button></form></div>""")
        out.append("""<div class=card><h3>Connect Telegram (about 2 minutes, free)</h3><ol>
<li>In Telegram, open <a href='https://t.me/BotFather' target=_blank>@BotFather</a> (Telegram's official bot-maker; it has a blue check).</li>
<li>Send <b>/newbot</b>, pick any name, then any username ending in <b>bot</b>.</li>
<li>BotFather replies with a token like <span class=mut>123456789:AA...</span>. Copy it and paste it here:</li></ol>
<form method=post action='/alerts'><input type=hidden name=do value=tg_token>
<input name=token placeholder='123456789:AA...' autocomplete=off required><button class=btn>Check token</button></form>
<p class=mut><small>The token stays in config.json on this computer and is only sent to Telegram. ScamHunter never asks for your
Telegram login, phone code, or password, and never messages anyone but you.</small></p></div>""")
    out.append("<div class=card><form method=post action='/alerts'><input type=hidden name=do value=test>"
               "<button class='btn ghost'>Test every channel</button></form></div>")
    return _shell("".join(out))


def post(form):
    do = form.get("do")
    try:
        if do == "tg_token":
            token = (form.get("token") or "").strip()
            if ":" not in token:
                return page(err="That doesn't look like a bot token. It looks like 123456789:AA... and comes from @BotFather.")
            me = _api(token, "getMe")
            _pending.clear()
            _pending[token] = me.get("username")
            return page()
        if do == "tg_link":
            if not _pending:
                return page(err="Paste your bot token first.")
            token, uname = next(iter(_pending.items()))
            chat = None
            for u in _api(token, "getUpdates", timeout=5):
                m = u.get("message") or u.get("my_chat_member") or {}
                if (m.get("chat") or {}).get("type") == "private":
                    chat = m["chat"]
            if not chat:
                return page(err=f"No message from you yet. Open @{uname}, press START, then try again.")
            cfg = _cfg()
            cfg["telegram"] = {"bot_token": token, "chat_id": str(chat["id"])}
            _save(cfg)
            _pending.clear()
            _api(token, "sendMessage", chat_id=chat["id"],
                 text="✅ ScamHunter alerts connected. Cash-out alerts will arrive here.")
            _restart_later()
            return page(msg="<b>Telegram connected.</b> A test message was sent to your bot chat. "
                            "The watchers are restarting to pick it up (about 10 seconds).")
        if do == "switch":
            ch, to = form.get("channel"), form.get("to")
            if ch not in ("ntfy", "telegram") or to not in ("on", "off"):
                return page(err="Unknown switch.")
            import alerts
            alerts.set_enabled(ch, to == "on")
            name = "ntfy" if ch == "ntfy" else "Telegram"
            return page(msg=f"<b>{name} turned {to}.</b> " + (
                "Alerts will go there again from the next one." if to == "on"
                else "Nothing more will be sent there until you turn it back on."))
        if do == "tg_off":
            cfg = _cfg()
            cfg.pop("telegram", None)
            _save(cfg)
            _restart_later()
            return page(msg="Telegram disconnected.")
        if do == "test":
            import alerts
            try:
                import scamconfig
                scamconfig._cache = None
            except Exception:
                pass
            item = {"title": "ScamHunter test alert", "message": "If you can read this, this alert channel works.",
                    "critical": True, "actions": [], "key": None}
            res = []
            for ch in alerts.channels(True):
                try:
                    alerts._SENDERS[ch](item)
                    res.append(f"{ch}: <span class=ok>sent</span>")
                except Exception as ex:
                    res.append(f"{ch}: <span class=bad>failed ({html.escape(str(ex)[:100])})</span>")
            return page(msg="<br>".join(res) or "No alert channels are set up yet.")
    except Exception as ex:
        return page(err=f"Telegram said: {str(ex)[:160]}")
    return page()
