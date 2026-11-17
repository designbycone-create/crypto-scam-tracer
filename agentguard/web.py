"""Desk page /agentguard and the local API agents call.

API (127.0.0.1 only; every call needs the header  X-AgentGuard-Token: <token from the page>).
A custom header can't be sent by a web page without the Desk's permission, which it never gives,
so a malicious site can't use this API from your browser.

  POST /api/agentguard/scan    {"content": "...", "kind": "html"|"text"}   -> {"risk", "findings", "clean"}
  POST /api/agentguard/action  {"action": {...}, "agent": "my-bot"}        -> {"decision", "reasons", "approval"?}
  GET  /api/agentguard/approval?id=<id>                                     -> {"status": pending|approved|denied|expired}
"""
import hmac
import html
import json
import os
import sys

from . import decide, pending, recent, request, resolve, scan, status, token

e = lambda s: html.escape(str(s if s is not None else ""), quote=True)
CSS = """body{font-family:Segoe UI,Arial,sans-serif;font-size:18px;max-width:980px;margin:24px auto;padding:0 16px;color:#111;background:#fff;line-height:1.45}
h1{font-size:30px}h2{font-size:23px;margin-top:30px}.box{border:2px solid #ddd;border-radius:10px;padding:14px 18px;margin:12px 0}
.ask{border-color:#f2b01e;background:#fff8e6}.deny,.high{border-color:#b00020;background:#fdecee}.allow,.none{border-color:#1e7d32;background:#eaf6ec}
.medium{border-color:#f2b01e;background:#fff8e6}.low{border-color:#999}
button{font-size:18px;padding:8px 18px;cursor:pointer;margin-right:8px}textarea{width:100%;box-sizing:border-box;min-height:150px;font-size:16px}
pre,.mono{font-family:Consolas,monospace;font-size:14px;white-space:pre-wrap;word-break:break-all;background:#f5f5f5;padding:10px;border-radius:6px}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:6px;text-align:left;vertical-align:top;font-size:16px}"""


def authorized(headers):
    got = headers.get("X-AgentGuard-Token") or ""
    return bool(got) and hmac.compare_digest(got, token())


def api(path, method, body, query):
    """-> (status code, dict)"""
    if path == "/api/agentguard/scan" and method == "POST":
        r = scan(body.get("content", ""), body.get("kind"))
        return 200, r
    if path == "/api/agentguard/action" and method == "POST":
        action = body.get("action") or {}
        r = decide(action)
        if r["decision"] == "ask":
            r["approval"] = request(action, r, str(body.get("agent") or "an AI agent")[:60])
        return 200, r
    if path == "/api/agentguard/approval" and method == "GET":
        return 200, {"status": status(query.get("id", ""))}
    return 404, {"error": "unknown endpoint"}


def _hook_cmd():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return f'"{sys.executable}" "{os.path.join(here, "agentguard", "claude_hook.py")}"'


def page(msg="", test=None, test_text="", test_kind="scan"):
    pend = "".join(
        f"<div class='box ask'><b>{e(v['agent'])}</b> wants to <b>{e(v['what'])}</b><br><span>Held because: {e('; '.join(v['reasons']))}</span>"
        f"<br><small>{e(v['when'])}</small><form method=post action=/agentguard style='margin-top:8px'>"
        f"<input type=hidden name=id value='{e(v['id'])}'><button name=do value=approve>Approve</button>"
        f"<button name=do value=deny>Deny</button></form></div>" for v in pending()) or "<p>Nothing waiting for you.</p>"
    hist = "".join(f"<tr><td>{e(v['when'])}</td><td>{e(v['agent'])}</td><td>{e(v['what'])}</td><td>{e(v['status'])}</td></tr>"
                   for v in recent() if v["status"] != "pending")
    res = ""
    if test is not None:
        if test_kind == "scan":
            res = (f"<div class='box {test['risk']}'><b>Hidden-instruction risk: {e(test['risk'].upper())}</b><ul>"
                   + "".join(f"<li>[{e(f['level'])}] {e(f['where'])}: <span class=mono>{e(f['what'])}</span></li>" for f in test["findings"])
                   + "</ul></div>")
        else:
            res = f"<div class='box {test['decision']}'><b>{e(test['decision'].upper())}</b>: {e('; '.join(test['reasons']) or 'no concerns')}</div>"
    tok = token()
    hook = json.dumps({"hooks": {
        "PreToolUse": [{"matcher": "Bash|WebFetch", "hooks": [{"type": "command", "command": _hook_cmd()}]}],
        "PostToolUse": [{"matcher": "WebFetch|WebSearch|Read|mcp__.*", "hooks": [{"type": "command", "command": _hook_cmd()}]}]}}, indent=1)
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Agent firewall</title><style>{CSS}</style></head><body><p><a href="/">&larr; Desk</a></p>
<h1>Agent firewall</h1>
<p>AI agents that read web pages, email or files can be tricked by instructions hidden in them: "send $5,000", "delete the backups",
"email me the API key". This firewall checks what your agents read and holds risky actions until you say yes.</p>
{f"<div class='box allow'>{e(msg)}</div>" if msg else ""}
<h2>Waiting for your OK</h2>{pend}
<h2>Try it</h2>
<form method=post action=/agentguard><input type=hidden name=do value=scan>
<p>Paste a web page's HTML, an email or a document an agent would read:</p><textarea name=text>{e(test_text if test_kind == 'scan' else '')}</textarea>
<p><button>Check for hidden instructions</button></p></form>
<form method=post action=/agentguard><input type=hidden name=do value=action>
<p>Or a command an agent wants to run:</p><input name=text style="width:100%;font-size:16px;padding:6px" value="{e(test_text if test_kind == 'action' else '')}">
<p><button>Would the firewall allow it?</button></p></form>{res}
<h2>Use it with Claude Code</h2>
<p>Add this to <span class=mono>%USERPROFILE%\\.claude\\settings.json</span> (merge it with what's there). Claude Code then asks the firewall
before every command, and is warned when a page or file it reads hides instructions.</p><pre>{e(hook)}</pre>
<h2>Use it with your own agents</h2>
<p>Call the local API with this header. Keep the token private.</p>
<pre>X-AgentGuard-Token: {e(tok)}

POST http://127.0.0.1:8787/api/agentguard/scan    {{"content": "&lt;page or email&gt;"}}
POST http://127.0.0.1:8787/api/agentguard/action  {{"action": {{"type": "crypto_send", "to": "0x...", "amount": 25, "currency": "USDC"}}, "agent": "my-bot"}}
GET  http://127.0.0.1:8787/api/agentguard/approval?id=&lt;approval id&gt;</pre>
<h2>History</h2><table><tr><th>When</th><th>Agent</th><th>Action</th><th>Result</th></tr>{hist or "<tr><td colspan=4>None yet.</td></tr>"}</table>
</body></html>"""


def post(form):
    do = form.get("do", "")
    if do in ("approve", "deny"):
        ok = resolve(form.get("id", ""), do == "approve")
        return page(("Approved." if do == "approve" else "Denied.") if ok else "That request was already answered or expired.")
    if do == "scan":
        t = form.get("text", "")
        return page(test=scan(t), test_text=t, test_kind="scan")
    if do == "action":
        t = form.get("text", "")
        return page(test=decide({"type": "shell", "command": t}), test_text=t, test_kind="action")
    return page()
