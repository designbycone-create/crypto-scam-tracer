"""What a paired phone may do on the Desk (fail closed: anything not allowed here is refused).

The phone can read the Desk and run checks. It can't change settings, keys or updates, can't make a
share copy, can't scan this computer's folders for secrets, and can't open the pairing page itself.
Those stay at the computer.
"""
import re
from urllib.parse import parse_qs, urlsplit

BLOCKED = ("/relay", "/setup", "/update", "/share", "/alerts", "/secretscan", "/extension", "/agentguard")
POST_OK = {"/msgcheck", "/numbercheck", "/prescreen", "/check", "/lookup", "/malware", "/clipguard", "/compromised",
           "/incident", "/sitewatch", "/submit/status", "/exposure", "/threatmap"}
SECRET_FIELDS = re.compile(r"(^|_)(key|token|password|secret|pin|seed|phrase)($|_)", re.I)
SECRET_ACTIONS = {"key", "token", "save_key", "setkey"}


def check(method, path, body=b"", ctype=""):
    """None if allowed, else the reason it's refused."""
    if method not in ("GET", "POST"):
        return "only reading pages and running checks is allowed from the phone"
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or any(c in path for c in "\r\n\\") or len(path) > 4000:
        return "bad address"
    p = urlsplit(path).path
    if re.search(r"/\.\.?(/|$)", p):
        return "bad address"
    if any(p == b or p.startswith(b + "/") for b in BLOCKED):
        return "that part of the Desk only works at the computer"
    if method == "POST":
        if p not in POST_OK:
            return "that action only works at the computer"
        if "multipart" in (ctype or "").lower():
            return "uploading files from the phone isn't supported"
        try:
            form = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
        except Exception:
            return "unreadable form"
        if any(SECRET_FIELDS.search(k) for k in form) or any(v in SECRET_ACTIONS for v in form.get("do", [])):
            return "keys and passwords can only be entered at the computer"
    return None
