"""Offline test of the Desk's Telegram connect flow (no network).
    python freezekit/test_alerts_web_offline.py
"""
import json, os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(tempfile.mkdtemp())
json.dump({"ntfy_topic": "scamhunter-test"}, open("config.json", "w"))
from freezekit import alerts_web as aw
calls = []
def api(token, method, p):
    calls.append(method)
    if token != "123:GOOD":
        raise RuntimeError("Unauthorized")
    if method == "getMe": return {"username": "my_alerts_bot"}
    if method == "getUpdates": return [{"update_id": 1, "message": {"chat": {"id": 555, "type": "private"}}}]
    if method == "sendMessage": return {"message_id": 1}
aw.API = api
aw._restart_later = lambda: None
ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []
r.append(ok("Connect Telegram" in aw.page() and "scamhunter-test" in aw.page(), "page shows ntfy topic and Telegram connect steps"))
r.append(ok("look like a bot token" in aw.post({"do": "tg_token", "token": "hello"}), "rejects non-token input"))
r.append(ok("Unauthorized" in aw.post({"do": "tg_token", "token": "123:BAD"}), "bad token: Telegram's answer shown"))
h = aw.post({"do": "tg_token", "token": "123:GOOD"})
r.append(ok("t.me/my_alerts_bot" in h and "I pressed Start" in h, "good token: shows the bot link and last step"))
h = aw.post({"do": "tg_link"})
cfg = json.load(open("config.json"))
r.append(ok(cfg["telegram"] == {"bot_token": "123:GOOD", "chat_id": "555"} and cfg["ntfy_topic"] == "scamhunter-test",
            "saves token + chat id, keeps other settings"))
r.append(ok("Telegram connected" in h and calls.count("sendMessage") == 1, "sends a confirmation message"))
r.append(ok("connected" in aw.page() and "123:GOOD" not in aw.page(), "page shows connected and never displays the token"))
aw.post({"do": "tg_off"})
r.append(ok("telegram" not in json.load(open("config.json")), "disconnect removes it"))
print(f"{sum(r)}/{len(r)} passed")
sys.exit(0 if all(r) else 1)
