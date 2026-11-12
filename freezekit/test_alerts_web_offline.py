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
# --- on/off switches (ntfy + Telegram), pause without losing settings
import alerts
h = aw.page()
r.append(ok("Turn ntfy off" in h and "Turn Telegram off" in h, "page offers an off switch for each channel"))
r.append(ok(alerts.channels(True) == ["ntfy", "telegram"], "both channels on by default (no alerts_enabled key)"))
h = aw.post({"do": "switch", "channel": "ntfy", "to": "off"})
cfg = json.load(open("config.json"))
r.append(ok(cfg["alerts_enabled"]["ntfy"] is False and cfg["ntfy_topic"] == "scamhunter-test"
            and cfg["telegram"]["chat_id"] == "555", "ntfy off: saved, topic and Telegram kept"))
r.append(ok("ntfy turned off" in h and "paused" in h and "Turn ntfy on" in h, "page shows ntfy paused + an on switch"))
r.append(ok(alerts.channels(True) == ["telegram"], "paused ntfy is not used for new alerts"))
queued = {"title": "t", "message": "m", "critical": True, "pending_channels": ["ntfy"], "delivered_via": ["telegram"]}
done, err = alerts._post(queued)
r.append(ok(done and queued["pending_channels"] == [] and queued["skipped_channels"] == ["ntfy"],
            "queued alert stops retrying a paused channel"))
stuck = {"title": "t", "message": "m", "critical": False, "pending_channels": ["ntfy"]}
r.append(ok(alerts._post(stuck)[0] is False, "never-delivered alert stays queued (not silently dropped)"))
h = aw.post({"do": "switch", "channel": "telegram", "to": "off"})
r.append(ok(alerts.channels(True) == [] and "Every phone channel is turned off" in h, "both off: warning shown"))
aw.post({"do": "switch", "channel": "ntfy", "to": "on"})
aw.post({"do": "switch", "channel": "telegram", "to": "on"})
r.append(ok(alerts.channels(True) == ["ntfy", "telegram"], "switches turn both back on"))
r.append(ok("Unknown switch" in aw.post({"do": "switch", "channel": "email", "to": "off"}), "rejects unknown channel"))
alerts.set_enabled("ntfy", False)
r.append(ok(aw._flags(json.load(open("config.json")))["ntfy"] is False, "command-line switch writes the same setting"))
alerts.set_enabled("ntfy", True)
aw.post({"do": "tg_off"})
r.append(ok("telegram" not in json.load(open("config.json")), "disconnect removes it"))
print(f"{sum(r)}/{len(r)} passed")
sys.exit(0 if all(r) else 1)
