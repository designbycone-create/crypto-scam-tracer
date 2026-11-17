"""Decide whether an AI agent may take an action: allow, ask the owner, or deny.

    decide({"type": "crypto_send", "to": "0x...", "amount": 50, "currency": "USDC"})
    decide({"type": "shell", "command": "rm -rf ~/projects"})
    decide({"type": "install", "manager": "pip", "package": "requests-secure-v2"})
    decide({"type": "browse", "url": "https://debank-login.xyz"})

Action types: crypto_send, payment, shell, file_delete, install, browse, login, email_send,
message_send, share_secret, other. Any action may carry "context_risk" (the agentguard.scan risk
of what the agent just read): after a "high" result, nothing that moves money, sends messages or
shares secrets runs without the owner, however harmless it looks.

The owner can loosen or tighten the defaults in agent_policy.json (local, private):
  {"auto_pay_limit": 0, "shell_default": "allow", "trusted_hosts": ["github.com"], "max_auto_delete": 0}
"""
import json
import re
import urllib.parse

POLICY_FILE = "agent_policy.json"
DEFAULTS = {"auto_pay_limit": 0,          # agent may send up to this much to a SAVED address without asking (0 = always ask)
            "shell_default": "allow",      # commands not matched below
            "max_auto_delete": 0,          # files an agent may delete without asking
            "trusted_hosts": []}           # extra hosts allowed for login/browse

SHELL_DENY = [
    (r"\brm\s+-[a-z]*r[a-z]*f?\s+(/|~|\$home|/\*|\.\s*$)(\s|$)", "deletes a whole home or system folder"),
    (r"\b(mkfs|format\s+[a-z]:|diskpart|dd\s+if=.*of=/dev/)", "wipes or formats a disk"),
    (r"\b(curl|wget|iwr|invoke-webrequest|irm)\b[^\n|]*\|\s*(sh|bash|zsh|iex|invoke-expression|python3?|powershell)\b",
     "downloads code and runs it without looking"),
    (r"-enc(odedcommand)?\s+[a-z0-9+/=]{20,}|\bfrombase64string\b.*\b(iex|invoke-expression)\b", "runs hidden (encoded) commands"),
    (r"\bvssadmin\b.*\bdelete\s+shadows\b|\bwbadmin\b.*\bdelete\b|\bbcdedit\b.*\brecoveryenabled\s+no", "destroys backups (a ransomware step)"),
    (r"\bset-mppreference\b.*-disable|\bnetsh\s+(adv)?firewall\b.*\b(off|disable)", "turns off antivirus or the firewall"),
    (r"\breg\s+(add|delete)\b.*\\(run|runonce|winlogon|policies)\\?", "changes startup / security settings in the registry"),
    (r"(cat|type|get-content|copy|cp)\b[^\n]*(\.ssh[/\\]id_\w*|\.env\b|wallet\.dat|keystore|\.aws[/\\]credentials|login data|cookies)[^\n]*"
     r"(\||>|curl|wget|nc |invoke-webrequest|scp|ftp)", "reads secrets and sends them somewhere"),
    (r"\bcipher\s+/w\b|\bshred\b.*-u", "permanently erases data"),
]
SHELL_ASK = [
    (r"\b(rm|del|erase|rmdir|rd|remove-item)\b", "deletes files"),
    (r"\bgit\s+(push|reset\s+--hard|clean\s+-[a-z]*f)", "pushes or discards code"),
    (r"\b(sudo|runas|chmod|chown|icacls|takeown)\b", "changes permissions or runs as administrator"),
    (r"\b(ssh|scp|sftp|ftp|nc|ncat|netcat|rsync)\b", "connects to another computer"),
    (r"\b(pip|npm|pnpm|yarn|cargo|gem|choco|winget|apt|brew)\s+(install|add|i)\b", "installs software"),
    (r"\b(shutdown|restart-computer|stop-computer|taskkill|kill\s+-9)\b", "stops programs or the computer"),
    (r"\b(crontab|schtasks|new-scheduledtask|systemctl\s+enable)\b", "sets up something that runs on its own later"),
    (r"(\.ssh|\.env\b|wallet|keystore|credentials|password|seed)", "touches secrets"),
]
# names of popular packages; a look-alike (requests-secure-v2, reqeusts) is how attackers plant code
POPULAR = {"pip": ["requests", "numpy", "pandas", "urllib3", "boto3", "flask", "django", "openai", "anthropic", "web3",
                   "cryptography", "pyyaml", "setuptools", "ccxt", "solana", "python-dotenv", "beautifulsoup4", "selenium"],
           "npm": ["react", "lodash", "axios", "express", "ethers", "web3", "chalk", "commander", "next", "vue", "typescript",
                   "dotenv", "@solana/web3.js", "viem", "wagmi", "puppeteer", "playwright"]}


def load_policy():
    try:
        with open(POLICY_FILE, encoding="utf-8-sig") as f:
            p = json.load(f)
    except Exception:
        p = {}
    return {**DEFAULTS, **p}


def _out(decision, *reasons):
    return {"decision": decision, "reasons": [r for r in reasons if r]}


def _edit_distance1(a, b):
    if abs(len(a) - len(b)) > 1 or a == b:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    s, l = (a, b) if len(a) < len(b) else (b, a)
    return any(l[:i] + l[i + 1:] == s for i in range(len(l)))


def check_package(name, manager="pip"):
    n = (name or "").lower().strip()
    n = re.split(r"[=<>!~\[ ]", n)[0]                      # drop version pins: requests==2.0
    if not n.startswith("@") and "@" in n:                 # npm: lodash@4
        n = n.split("@")[0]
    pop = POPULAR.get("npm" if manager in ("npm", "pnpm", "yarn") else "pip", [])
    if n in pop:
        return None
    for p in pop:
        if _edit_distance1(n, p):
            return f"'{name}' is one letter away from the popular package '{p}' (a common trick to plant malware)"
        base = p.split("/")[-1]
        if n.startswith(base + "-") or n.startswith(base + "_") or n.endswith("-" + base):
            return f"'{name}' borrows the name of the popular package '{p}' but isn't it"
    return None


def _host(url):
    try:
        return (urllib.parse.urlsplit(url if "//" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""


def _bad_host(url, pol):
    h = _host(url)
    if not h:
        return "no valid web address"
    if h in pol["trusted_hosts"]:
        return None
    try:
        from shield.msgcheck import check_link
        flags = [why for w, why in check_link(url) if w >= 3]
        if flags:
            return flags[0]
    except Exception:
        pass
    return None


def decide(action, policy=None):
    pol = policy or load_policy()
    t = (action.get("type") or "other").lower()
    ctx = (action.get("context_risk") or "none").lower()
    tainted = ctx == "high"
    taint_why = "the agent just read content with hidden instructions, so this needs your OK" if tainted else None

    if t in ("crypto_send", "payment"):
        to = str(action.get("to") or "")
        try:
            from shield.clipguard import bad_reasons, book, _k
            bad = bad_reasons(to) if to else []
            saved = book().get(_k(to)) if to else None
        except Exception:
            bad, saved = [], None
        if bad:
            return _out("deny", f"the recipient is a known scammer's address: {bad[0]}")
        if action.get("url"):
            hb = _bad_host(action["url"], pol)
            if hb:
                return _out("deny", f"the payment page is not trustworthy: {hb}")
        try:
            amount = float(action.get("amount") or 0)
        except (TypeError, ValueError):
            amount = float("inf")
        if tainted:
            return _out("deny", "a payment requested right after reading content with hidden instructions is how agent-payment scams work")
        if saved and amount <= float(pol["auto_pay_limit"] or 0) and amount > 0:
            return _out("allow", f"to your saved address '{saved['label']}', within your auto-pay limit")
        return _out("ask", "payments always need your OK" + ("" if saved else "; the recipient isn't in your address book"))

    if t == "share_secret":
        return _out("deny", "agents never share passwords, keys, codes or seed phrases")

    if t == "shell":
        cmd = str(action.get("command") or "")
        low = cmd.lower()
        for rx, why in SHELL_DENY:
            if re.search(rx, low, re.I | re.S):
                return _out("deny", f"this command {why}")
        try:
            from agentguard.scan import scan
            r = scan(cmd, kind="text")
            if r["risk"] == "high":
                return _out("deny", "the command carries hidden instructions")
        except Exception:
            pass
        for rx, why in SHELL_ASK:
            if re.search(rx, low, re.I):
                return _out("deny" if tainted and why in ("touches secrets", "connects to another computer") else "ask",
                            f"this command {why}", taint_why)
        if tainted:
            return _out("ask", taint_why)
        return _out(pol["shell_default"], None if pol["shell_default"] == "allow" else "commands need your OK by your policy")

    if t == "install":
        why = check_package(str(action.get("package") or ""), str(action.get("manager") or "pip"))
        if why:
            return _out("deny", why)
        return _out("ask", "installing software needs your OK", taint_why)

    if t == "file_delete":
        n = int(action.get("count") or 1)
        path = str(action.get("path") or "").replace("\\", "/").rstrip("/").lower()
        if path in ("", "/", "~", "c:", "c:/users") or re.fullmatch(r"(c:)?/users/[^/]+|/home/[^/]+", path):
            return _out("deny", "that would delete a whole home or system folder")
        if n > 50:
            return _out("deny", f"deleting {n} files at once is how ransomware and runaway agents behave")
        if n <= int(pol["max_auto_delete"] or 0) and not tainted:
            return _out("allow")
        return _out("ask", f"deletes {n} file(s)", taint_why)

    if t in ("browse", "login"):
        hb = _bad_host(str(action.get("url") or ""), pol)
        if hb:
            return _out("deny", hb)
        if t == "login":
            return _out("ask", "signing in to an account needs your OK", taint_why)
        return _out("allow")

    if t in ("email_send", "message_send", "post"):
        if tainted:
            return _out("deny", "a message requested right after reading hidden instructions is how agents get used to spam or leak data")
        return _out("ask", "sending messages as you needs your OK")

    return _out("ask", "unknown kind of action", taint_why)
