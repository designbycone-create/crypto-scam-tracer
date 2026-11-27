"""Live numbers and events for the Desk's Overview and section pages, gathered from files the
watchers already write. Read-only, except note(), which keeps a small privacy-safe activity log
(what kind of check and its result -- never the message text or the number you looked up).
"""
import json
import os
import time
from datetime import datetime, timedelta

ACTIVITY = "desk_activity.jsonl"
FMT = "%Y-%m-%d %H:%M:%S"
_cache = {}


def _now():
    return datetime.now().strftime(FMT)


def note(sec, lvl, title, detail="", href=""):
    """Record a check made on the Desk (shown in the live feed)."""
    try:
        with open(ACTIVITY, "a", encoding="utf-8") as f:
            f.write(json.dumps({"t": _now(), "sec": sec, "lvl": lvl, "title": title[:120], "detail": detail[:200], "href": href}) + "\n")
    except Exception:
        pass


def _json(path, default=None):
    try:
        with open(path, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return default


def _cached_json(path, default=None):
    """Big files (the caller list) are re-read only when they change."""
    try:
        m = os.path.getmtime(path)
    except OSError:
        return default
    c = _cache.get(path)
    if c and c[0] == m:
        return c[1]
    v = _json(path, default)
    _cache[path] = (m, v)
    return v


def _tail_lines(path, n=40, chunk=65536):
    """Last n lines without reading the whole file (some logs are tens of MB)."""
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - chunk))
            data = f.read().decode("utf-8", "replace")
    except OSError:
        return []
    lines = data.splitlines()
    if size > chunk:
        lines = lines[1:]
    return lines[-n:]


def _jsonl(path, n=40):
    out = []
    for l in _tail_lines(path, n):
        try:
            out.append(json.loads(l))
        except ValueError:
            pass
    return out


def _local(t):
    """'2026-11-17 03:00:37 UTC' -> local time, so every event sorts on the same clock."""
    t = str(t or "")
    if t.endswith("UTC"):
        try:
            from datetime import timezone
            return datetime.strptime(t[:19], FMT).replace(tzinfo=timezone.utc).astimezone().strftime(FMT)
        except ValueError:
            pass
    return t[:19].replace("T", " ")


def _stamped(line):
    """'[2026-11-16 21:00:09] text' -> (time, text)"""
    if line.startswith("[") and "]" in line[:22]:
        return line[1:20], line[22:].strip()
    return "", line.strip()


def _lvl_from_text(t):
    low = t.lower()
    if any(w in low for w in ("alert", "cashed out", "exchange deposit", "stop", "critical", "moved")):
        return "caution"
    return "info"


# ---------------------------------------------------------------- the live feed ----

NOISE = ("no change", "reconnecting in", "live on wss", "connection issue")


def _noise(txt):
    low = txt.lower()
    return any(w in low for w in NOISE)


def feed(n=80):
    ev = []
    # crypto
    for t, txt in map(_stamped, _tail_lines("netwatch_events.log", 200)):
        if txt and not _noise(txt):
            ev.append({"t": t, "sec": "crypto", "lvl": _lvl_from_text(txt), "title": "XRP Ledger network", "detail": txt[:220], "href": "/graph"})
    for t, txt in map(_stamped, _tail_lines("mc_events.log", 200)):
        if txt and not _noise(txt):
            ev.append({"t": t, "sec": "crypto", "lvl": _lvl_from_text(txt), "title": "Multi-chain tracer", "detail": txt[:220], "href": "/case"})
    for r in _jsonl("prescreen_log.jsonl", 25):
        v = str(r.get("verdict", ""))
        f0 = (r.get("findings") or [""])[0] if "STOP" in v.upper() else ""
        ev.append({"t": _local(r.get("time", "")), "sec": "crypto",
                   "lvl": "stop" if "STOP" in v.upper() else ("caution" if "CAUTION" in v.upper() else "ok"),
                   "title": f"Address checked: {v or 'done'}", "detail": f"{r.get('chain', '')} {str(r.get('address', ''))[:14]}... {f0}"[:220],
                   "href": "/prescreen"})
    # defense
    for r in _jsonl("extension_events.jsonl", 30):
        k = r.get("kind", "")
        lvl = "stop" if k in ("swap", "attack_host", "paste_blocked", "copied_bad", "page_bad", "tamper") else "info"
        ev.append({"t": r.get("time", ""), "sec": "defense", "lvl": lvl, "title": "Browser: " + k.replace("_", " "),
                   "detail": (r.get("host") or r.get("url") or "")[:160], "href": "/extension"})
    for a in sorted((_json("agent_approvals.json", {}) or {}).values(), key=lambda v: -v.get("created", 0))[:15]:
        st = a.get("status", "")
        ev.append({"t": a.get("when", ""), "sec": "defense", "lvl": "caution" if st == "pending" else ("stop" if st == "denied" else "info"),
                   "title": f"Agent firewall: {st}", "detail": f"{a.get('agent', '')}: {a.get('what', '')}"[:200], "href": "/agentguard"})
    for dom, s in ((_json("sitewatch.json", {}) or {}).get("sites") or {}).items():
        if s.get("level") == "alert":
            ev.append({"t": str((s.get("last") or {}).get("time", ""))[:19], "sec": "defense", "lvl": "stop",
                       "title": f"Site alert: {dom}", "detail": "; ".join(s.get("signals") or [])[:200], "href": "/sitewatch"})
    ss = _json("secretscan_summary.json", {}) or {}
    if ss.get("time"):
        c = ss.get("counts") or {}
        bad = c.get("stop", 0) + c.get("high", 0)
        ev.append({"t": ss["time"], "sec": "defense", "lvl": "stop" if c.get("stop") else ("caution" if bad or c.get("caution") else "ok"),
                   "title": "Secrets scan: " + (f"{bad} urgent or important finding(s)" if bad else ("tidy-up items only" if c.get("caution") else "nothing found")),
                   "detail": f"{ss.get('files', 0):,} files checked (no secrets or paths are stored)", "href": "/secretscan"})
    ex = _json("exposure_state.json", {}) or {}
    for i in (ex.get("items") or [])[:6]:
        if i.get("severity") in ("critical", "high"):
            ev.append({"t": ex.get("checked", ""), "sec": "defense", "lvl": "stop" if i["severity"] == "critical" else "caution",
                       "title": "Open to the internet: " + i["what"][:80], "detail": f"your address {ex.get('ip', '')}", "href": "/exposure"})
    if ex.get("checked") and ex.get("worst") in ("none", "low", "info"):
        ev.append({"t": ex["checked"], "sec": "defense", "lvl": "ok", "title": "Weekly exposure check: nothing serious open",
                   "detail": f"your address {ex.get('ip', '')}", "href": "/exposure"})
    # phone alerts that couldn't be delivered
    for p in (_json("alerts_outbox.json", []) or [])[:10]:
        ev.append({"t": p.get("queued_at", ""), "sec": "settings", "lvl": "stop" if p.get("critical") else "caution",
                   "title": "Phone alert waiting: " + p.get("title", ""), "detail": p.get("message", "")[:200], "href": "/alerts"})
    # checks made on the Desk (message / number checks)
    ev += _jsonl(ACTIVITY, 40)
    ev = [e for e in ev if e.get("t")]
    ev.sort(key=lambda e: e["t"], reverse=True)
    out, seen = [], set()
    for x in ev:                      # the same event logged again and again shows once
        k = (x["sec"], x["title"], x["detail"])
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out[:n]


# ---------------------------------------------------------------- per-section numbers ----

def phone(days=30):
    st = _cached_json("callers_stats.json", {"days": {}}) or {"days": {}}
    lst = _cached_json("callers.json", {}) or {}
    all_days = sorted(st.get("days", {}))
    if all_days:
        last = datetime.strptime(all_days[-1], "%Y-%m-%d").date()
        keep = [d for d in all_days if d > (last - timedelta(days=days)).isoformat()]
    else:
        keep = []
    states, subjects, series, with_states = {}, {}, [], 0
    for d in keep:
        x = st["days"][d]
        series.append([d, x.get("reports", 0)])
        if x.get("states") is not None:
            with_states += 1
            for k, v in x["states"].items():
                states[k] = states.get(k, 0) + v
        for k, v in (x.get("subjects") or {}).items():
            subjects[k] = subjects.get(k, 0) + v
    nums = lst.get("numbers") or {}
    top = sorted(nums.items(), key=lambda kv: -kv[1]["n"])[:10]
    top_rows = []
    for num, e in top:
        subj = max(e["subjects"].items(), key=lambda kv: kv[1])[0] if e.get("subjects") else ""
        top_rows.append({"number": f"({num[:3]}) {num[3:6]}-{num[6:]}", "raw": num, "reports": e["n"], "subject": subj, "last": e.get("last")})
    return {"days": len(keep), "days_with_states": with_states, "from": keep[0] if keep else None, "to": keep[-1] if keep else None,
            "reports": sum(s[1] for s in series), "numbers": len(nums), "states": states,
            "subjects": sorted(subjects.items(), key=lambda kv: -kv[1])[:8], "series": series, "top": top_rows,
            "msg_checks": sum(1 for a in _jsonl(ACTIVITY, 400) if a.get("href") == "/msgcheck")}


def crypto():
    pre = _jsonl("prescreen_log.jsonl", 400)
    try:
        from freezekit import tracker
        tg = tracker.load().get("targets", {})
    except Exception:
        tg = {}
    feed_ = _json(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "threatfeed", "campaigns.json"), {}) or {}
    camps = feed_.get("campaigns") or []
    mc = _json("mc_map.json", {}) or {}
    net = _json("network_map.json", {}) or {}
    return {"checks": len(pre), "stops": sum(1 for r in pre if "STOP" in str(r.get("verdict", "")).upper()),
            "cashout_points": len(tg), "yours": sum(1 for v in tg.values() if v.get("yours")),
            "wallets_mapped": len(net.get("watchlist", [])) + int((mc.get("summary") or {}).get("total_nodes", 0) or 0),
            "campaigns": [{"name": c.get("name"), "first_seen": c.get("first_seen"), "kind": c.get("kind"),
                           "addresses": len(c.get("addresses") or [])} for c in camps]}


def defense():
    ext = _jsonl("extension_events.jsonl", 500)
    ag = (_json("agent_approvals.json", {}) or {}).values()
    sites = (_json("sitewatch.json", {}) or {}).get("sites") or {}
    return {"ext_events": len(ext), "ext_blocks": sum(1 for r in ext if r.get("kind") in ("swap", "attack_host", "paste_blocked", "copied_bad", "page_bad", "tamper")),
            "ext_paired": bool(ext),
            "agent_pending": sum(1 for a in ag if a.get("status") == "pending"),
            "agent_denied": sum(1 for a in ag if a.get("status") == "denied"),
            "sites": len(sites), "site_alerts": sum(1 for s in sites.values() if s.get("level") == "alert"),
            "exposure": {k: (_json("exposure_state.json", {}) or {}).get(k) for k in ("checked", "worst")}}


def services():
    st = _json("desk_status.json", None)
    if st is None:      # a file written by an older Desk can have a second copy glued on: read the first one
        try:
            with open("desk_status.json", encoding="utf-8") as f:
                st = json.JSONDecoder().raw_decode(f.read())[0]
        except Exception:
            st = {}
    svc = st.get("services", {})
    return {"alive": sum(1 for v in svc.values() if v.get("alive")), "total": len(svc),
            "down": [k for k, v in svc.items() if not v.get("alive") and not v.get("skipped")],
            "list": [{"name": k, "alive": bool(v.get("alive")), "skipped": bool(v.get("skipped"))} for k, v in svc.items()]}


def live(days=30):
    return {"generated": _now(), "services": services(), "phone": phone(days), "crypto": crypto(), "defense": defense(), "feed": feed()}
