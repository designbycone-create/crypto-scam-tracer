"""Submission tracking: what was filed where, when, and what came back.

submissions.json:
  {"targets": {target_id: {"detected": iso, "deadline": iso|null, ...}},
   "status":  {target_id|channel_key: {"state": ..., "case_no": ..., "note": ..., "updated": iso, "history": [...]}}}
"""
import json
import os
from datetime import datetime, timedelta

FILE = "submissions.json"
STATES = ["to do", "submitted", "acknowledged", "frozen", "rejected", "not needed"]
FMT = "%Y-%m-%d %H:%M:%S"


def _now():
    return datetime.now().strftime(FMT)


def load():
    try:
        with open(FILE, encoding="utf-8-sig") as f:
            d = json.load(f)
    except Exception:
        d = {}
    d.setdefault("targets", {})
    d.setdefault("status", {})
    return d


def save(d):
    tmp = FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=1)
    os.replace(tmp, FILE)


def register_target(d, tid, deadline_hours=None, info=None):
    """First time a target is seen, stamp detection time (+ deadline). Returns True if new."""
    if tid in d["targets"]:
        return False
    det = datetime.now()
    d["targets"][tid] = {"detected": det.strftime(FMT),
                         "deadline": (det + timedelta(hours=deadline_hours)).strftime(FMT) if deadline_hours else None,
                         **(info or {})}
    return True


def set_status(d, key, state, case_no="", note="", when=""):
    """when: optional 'YYYY-mm-dd HH:MM' if the step happened earlier (e.g. filed this morning)."""
    if state not in STATES:
        raise ValueError(state)
    t = _now()
    if when:
        try:
            t = datetime.strptime(when.strip().replace("T", " ")[:16], "%Y-%m-%d %H:%M").strftime(FMT)
        except ValueError:
            pass
    s = d["status"].setdefault(key, {"history": []})
    s.update({"state": state, "updated": t})
    if case_no:
        s["case_no"] = case_no
    if note:
        s["note"] = note
    s["history"].append({"time": t, "state": state, "case_no": case_no, "note": note})


def get(d, key):
    return d["status"].get(key, {"state": "to do"})


def deadline_from(d, key, hours):
    """Deadline = first time `key` was marked submitted + hours (None if not yet submitted)."""
    if not hours:
        return None
    for h in d["status"].get(key, {}).get("history", []):
        if h["state"] == "submitted":
            try:
                return (datetime.strptime(h["time"], FMT) + timedelta(hours=hours)).strftime(FMT)
            except Exception:
                return None
    return None


def countdown(iso):
    """Human countdown to an iso deadline; ('3h 12m left', seconds) or ('OVERDUE 2h', -s)."""
    if not iso:
        return "", None
    try:
        s = int((datetime.strptime(iso, FMT) - datetime.now()).total_seconds())
    except Exception:
        return "", None
    a = abs(s)
    txt = f"{a // 3600}h {(a % 3600) // 60:02d}m"
    return (f"{txt} left" if s >= 0 else f"OVERDUE by {txt}"), s


def elapsed(iso):
    try:
        s = int((datetime.now() - datetime.strptime(iso, FMT)).total_seconds())
    except Exception:
        return ""
    if s < 3600:
        return f"{s // 60} min ago"
    if s < 172800:
        return f"{s // 3600}h {(s % 3600) // 60:02d}m ago"
    return f"{s // 86400} days ago"
