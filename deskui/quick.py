"""The Overview's quick check: one box, and the Desk opens the right check for what was pasted.
A recovery phrase is refused on sight: not stored, not sent, not shown back."""
import re

from deskui import icons, seedguard

B58 = "1-9A-HJ-NP-Za-km-z"
ADDRESS = re.compile(rf"(r[{B58}]{{24,34}}|0x[0-9a-fA-F]{{40}}|bc1[0-9a-z]{{25,62}}|[13][{B58}]{{25,34}}|T[{B58}]{{33}}|[{B58}]{{32,44}})")


def route(text):
    t = (text or "").strip()
    if not t:
        return "empty", ""
    if seedguard.looks_like_seed(t):
        return "seed", ""
    if " " not in t and ADDRESS.fullmatch(t):
        return "address", t
    digits = re.sub(r"\D", "", t)
    if re.fullmatch(r"[+\d\s().-]{10,20}", t) and 10 <= len(digits) <= 11:
        return "number", digits[-10:]
    return "message", t


def page(kind):
    if kind == "seed":
        card = icons.result("stop", sentence="Those look like recovery words. The Desk does not need them, and they were not kept or sent.",
                            why=["Never paste a recovery phrase into a website, an app or a chat.",
                                 "Do not give those words to anyone, even someone who says they are support.",
                                 "If you already gave them to someone, open Wallet compromised? now."],
                            actions="<a class='btn btn-primary' href='/'>Clear the box</a>"
                                    "<a class='btn btn-secondary' href='/compromised'>Wallet compromised?</a>")
    else:
        card = icons.result("info", "Nothing to check", "Paste a wallet address, a phone number, or a message, then press Check this.",
                            actions="<a class='btn btn-primary' href='/'>Back to the quick check</a>")
    return f"<!doctype html><html><head><meta charset=utf-8><title>Quick check</title></head><body><h1>Quick check</h1>{card}</body></html>"
