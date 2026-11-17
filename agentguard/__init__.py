"""Agent firewall: protects you from your own AI agents being turned against you.

AI agents that read the web, email or documents can be steered by instructions hidden in that
content ("indirect prompt injection"): send a payment, delete files, leak keys. Agent Guard
sits between the agent and the world:

  scan(content)      what the agent reads -> hidden instructions found, risk, cleaned text
  decide(action)     what the agent wants to do -> allow / ask you / deny (with reasons)
  request(action)    "ask" -> an approval waits on the Desk page /agentguard and your phone

Ways to use it:
  * Claude Code: agentguard/claude_hook.py checks every command before it runs and every web
    page or file after it's read (setup on the /agentguard page).
  * Any agent you write: call the Desk's local API (http://127.0.0.1:8787/api/agentguard/...)
    with the token shown on /agentguard, or import this package.
  * By hand: python -m agentguard scan page.html | python -m agentguard action '{"type":"shell","command":"..."}'
"""
import json
import os
import secrets
import time
from datetime import datetime

from .policy import decide, load_policy  # noqa: F401
from .scan import scan  # noqa: F401

APPROVALS = "agent_approvals.json"
CFG = "config.json"
EXPIRE_S = 3600


def _load(path, default):
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return default


def _save(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, path)


def token():
    """The secret local programs must present to the Desk's agent API (created on first use)."""
    cfg = _load(CFG, {})
    if not cfg.get("agentguard_token"):
        cfg["agentguard_token"] = secrets.token_urlsafe(24)
        _save(CFG, cfg)
    return cfg["agentguard_token"]


def describe(action):
    t = action.get("type", "action")
    if t in ("crypto_send", "payment"):
        return f"send {action.get('amount', '?')} {action.get('currency', '')} to {action.get('to', '?')}".strip()
    if t == "shell":
        return f"run: {str(action.get('command', ''))[:300]}"
    if t == "install":
        return f"install {action.get('manager', '')} package {action.get('package', '?')}"
    if t == "file_delete":
        return f"delete {action.get('count', 1)} file(s) at {action.get('path', '?')}"
    if t in ("browse", "login"):
        return f"{t} {action.get('url', '?')}"
    if t in ("email_send", "message_send", "post"):
        return f"send a message to {action.get('to', '?')}: {str(action.get('subject') or action.get('text') or '')[:120]}"
    return json.dumps(action)[:300]


def _all():
    d = _load(APPROVALS, {})
    now = time.time()
    for k, v in d.items():
        if v["status"] == "pending" and now - v["created"] > EXPIRE_S:
            v["status"], v["decided"] = "expired", now     # no answer = no
    return d


def request(action, decision, agent="an AI agent", notify=True):
    """Queue an 'ask' for the owner. Returns the approval id."""
    d = _all()
    aid = secrets.token_hex(8)
    d[aid] = {"id": aid, "agent": agent, "action": action, "what": describe(action), "reasons": decision.get("reasons", []),
              "status": "pending", "created": time.time(), "when": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    _save(APPROVALS, d)
    if notify:
        try:
            import alerts
            alerts.send("Agent wants to act", f"{agent} wants to {d[aid]['what']}\nWhy it's held: {'; '.join(d[aid]['reasons'])}\n"
                        "Approve or deny on the Desk: Agent firewall.", key="agentguard-" + aid)
        except Exception:
            pass
    return aid


def status(aid):
    v = _all().get(aid)
    return v["status"] if v else "unknown"


def resolve(aid, approve):
    d = _all()
    v = d.get(aid)
    if not v or v["status"] != "pending":
        return False
    v["status"], v["decided"] = ("approved" if approve else "denied"), time.time()
    _save(APPROVALS, d)
    return True


def pending():
    return [v for v in _all().values() if v["status"] == "pending"]


def recent(n=30):
    return sorted(_all().values(), key=lambda v: -v["created"])[:n]


def wait(aid, timeout=300, poll=2):
    """Block until the owner answers (or timeout -> 'expired' for the caller to treat as no)."""
    end = time.time() + timeout
    while time.time() < end:
        s = status(aid)
        if s != "pending":
            return s
        time.sleep(poll)
    return "pending"


def guard(action, agent="an AI agent", wait_s=0):
    """One call for agents: returns {"decision": allow|deny|ask, "reasons", "approval": id?, "status"?}."""
    r = decide(action)
    if r["decision"] == "ask":
        r["approval"] = request(action, r, agent)
        if wait_s:
            r["status"] = wait(r["approval"], wait_s)
            r["decision"] = "allow" if r["status"] == "approved" else ("deny" if r["status"] in ("denied", "expired") else "ask")
    return r
