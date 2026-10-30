"""One-time Telegram alert setup.

    python telegram_setup.py

1. In Telegram, open @BotFather, send /newbot, pick any name, and copy the token.
2. Run this script and paste the token when asked.
3. Open your new bot in Telegram and press START (or send it any message).
The script finds your chat id, saves both into config.json, and sends a test.
Standard library only. Your token stays on this computer.
"""
import getpass
import json
import os
import sys
import time
import urllib.request

CFG = "config.json"


def api(token, method, **params):
    data = json.dumps(params).encode() if params else None
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/{method}", data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=40) as r:
        out = json.loads(r.read())
    if not out.get("ok"):
        raise RuntimeError(out.get("description"))
    return out["result"]


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    token = (sys.argv[1] if len(sys.argv) > 1 else getpass.getpass("Paste your bot token (hidden): ")).strip()
    try:
        me = api(token, "getMe")
    except Exception as e:
        sys.exit(f"That token didn't work ({e}). Copy it again from @BotFather.")
    print(f"Bot OK: @{me['username']}")
    print(f"Now open https://t.me/{me['username']} in Telegram and press START (or send any message).")
    print("Waiting up to 3 minutes...")
    chat_id, offset, deadline = None, None, time.time() + 180
    while time.time() < deadline and chat_id is None:
        params = {"timeout": 25}
        if offset:
            params["offset"] = offset
        for u in api(token, "getUpdates", **params):
            offset = u["update_id"] + 1
            msg = u.get("message") or u.get("my_chat_member") or {}
            chat = msg.get("chat") or {}
            if chat.get("id"):
                chat_id = chat["id"]
                who = chat.get("first_name") or chat.get("title") or ""
    if chat_id is None:
        sys.exit("No message received. Run this again and press START in the bot.")
    cfg = {}
    if os.path.exists(CFG):
        with open(CFG, encoding="utf-8-sig") as f:
            cfg = json.load(f)
    cfg["telegram"] = {"bot_token": token, "chat_id": str(chat_id)}
    tmp = CFG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CFG)
    api(token, "sendMessage", chat_id=chat_id,
        text="✅ ScamHunter alerts connected. Cash-out alerts will arrive here as well as ntfy.")
    print(f"Saved. Chat {chat_id} ({who}) will receive alerts. A test message was sent.")
    print("Restart the Desk (or wait for the next alert) - every service reads config.json on start.")


if __name__ == "__main__":
    main()
