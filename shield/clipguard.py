"""Copy-paste guard: checks every crypto address you copy, before you paste it into a wallet.

Address-swapping malware (a "clipper", like the OPTIMJACK campaign) replaces the address you copy
with the attacker's. The swapped address passes its checksum, so wallets accept it. The guard
catches it two ways:

  STOP     the copied address is a known attacker address (campaign feed, your incident list,
           public scam / sanctions lists) -> large red warning + phone alert
  SAVED    it's in your address book (your own exchange deposit addresses, people you pay)
           -> small green "this is your saved <name>" note
  UNKNOWN  neither -> small amber note to check it on the site and on your wallet's screen
           (can be switched off)

Privacy: the clipboard is read in memory only. Nothing you copy is saved or logged unless it
is a crypto address that matched a warning. The address book stays on this computer
(address_book.json, never in the repository).

Turn it on from the Desk page /clipguard (config.json "clipguard": true); the Desk then runs
it alongside the watchers.

    python -m shield.clipguard            # run the guard (needs a desktop session)
    python -m shield.clipguard check "<text>"
"""
import html
import json
import os
import sys
import time
from datetime import datetime

BOOK = "address_book.json"
CFG = "config.json"
POLL_MS = 400
MAX_LEN = 5000          # longer clipboard text isn't an address being pasted; ignore it


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


def _k(a):
    from responder.addresses import is_bch
    a = a.strip()
    if a.lower().startswith("bitcoincash:"):
        a = a.split(":", 1)[1]
    return a.lower() if a[:2].lower() == "0x" or is_bch(a) else a


# ---------------------------------------------------------------- address book ----

def book():
    return _load(BOOK, {})


def book_add(address, label):
    from responder.addresses import extract
    found = extract(address or "")
    if len(found) != 1 or _k(found[0][1]) != _k(address):
        return False, "That isn't one valid crypto address (its checksum must be right)."
    if bad_reasons(address):
        return False, "That address is on a warning list, so it can't be saved as trusted."
    b = book()
    b[_k(address)] = {"address": address.strip(), "chain": found[0][0], "label": (label or "").strip() or "saved address",
                      "added": datetime.now().strftime("%Y-%m-%d %H:%M")}
    _save(BOOK, b)
    return True, f"Saved {b[_k(address)]['label']}."


def book_remove(address):
    b = book()
    if b.pop(_k(address), None) is not None:
        _save(BOOK, b)
        return True
    return False


# ---------------------------------------------------------------- assessment ----

def bad_reasons(address):
    """Why this address is known-bad (empty list if it isn't)."""
    out = []
    try:
        import threatfeed
        c = threatfeed.campaign_for_address(address)
        if c:
            out.append(f"attacker address in the {c['name']} campaign ({c.get('kind', '')})")
    except Exception:
        pass
    try:
        from shield import compromised
        h = compromised.check_address(address)
        if h and not out:
            out.append(h)
    except Exception:
        pass
    try:
        from responder import intel
        for src, det in intel.check(address):
            if src != "Your cases":
                out.append(f"{src}: {det}")
    except Exception:
        pass
    return out


def assess(text):
    """[{level: stop|saved|unknown, chain, address, why}] for every valid address in the text."""
    from responder.addresses import extract
    if not text or len(text) > MAX_LEN:
        return []
    b = book()
    out = []
    for chain, a in extract(text):
        why = bad_reasons(a)
        if why:
            out.append({"level": "stop", "chain": chain, "address": a, "why": why})
        elif _k(a) in b:
            out.append({"level": "saved", "chain": chain, "address": a, "why": [b[_k(a)]["label"]]})
        else:
            out.append({"level": "unknown", "chain": chain, "address": a, "why": []})
    return out


def chunked(a, n=4):
    """Address split into groups of 4 so a person can compare it by eye."""
    return " ".join(a[i:i + n] for i in range(0, len(a), n))


def message(f):
    if f["level"] == "stop":
        return ("STOP: do not send to this address",
                "The address you just copied is a known scammer's address:\n" + "\n".join(f["why"]) +
                "\n\nIf you copied it from a website you trust, the website (or your computer) may be "
                "infected and swapped the address. Don't paste it. Get the address another way, "
                "and check it on your wallet's screen.")
    if f["level"] == "saved":
        return (f"Saved address: {f['why'][0]}", "This matches an address in your address book.")
    return ("Check this address before you send",
            "This address isn't in your address book. Compare it with the site, and again on your "
            "wallet's screen, before you send. Malware can swap a copied address.")


# ---------------------------------------------------------------- the guard ----

def run():
    import tkinter as tk
    cfg = _load(CFG, {})
    root = tk.Tk()
    root.withdraw()
    # Windows applies the "start hidden" flag (the Desk runs in the background) to a program's
    # FIRST shown window. Spend it here on the invisible root, or the first STOP warning stays hidden.
    root.deiconify(); root.update(); root.withdraw()
    state = {"last": None, "cfg_at": 0, "cfg": cfg}
    colors = {"stop": ("#b00020", "#ffffff"), "saved": ("#1e7d32", "#ffffff"), "unknown": ("#f2b01e", "#111111")}

    def show(f):
        title, body = message(f)
        bg, fg = colors[f["level"]]
        w = tk.Toplevel(root)
        w.title("ScamHunter: " + title)
        w.configure(bg=bg)
        w.attributes("-topmost", True)
        big = f["level"] == "stop"
        tk.Label(w, text=title, bg=bg, fg=fg, font=("Segoe UI", 26 if big else 18, "bold"),
                 wraplength=760, justify="left").pack(padx=24, pady=(20, 8), anchor="w")
        tk.Label(w, text=chunked(f["address"]), bg=bg, fg=fg, font=("Consolas", 22 if big else 16),
                 wraplength=760, justify="left").pack(padx=24, pady=4, anchor="w")
        tk.Label(w, text=body, bg=bg, fg=fg, font=("Segoe UI", 16 if big else 13),
                 wraplength=760, justify="left").pack(padx=24, pady=(8, 12), anchor="w")
        tk.Button(w, text="I understand" if big else "OK", font=("Segoe UI", 16 if big else 12, "bold"),
                  command=w.destroy).pack(pady=(0, 20))
        w.update_idletasks()
        x = (w.winfo_screenwidth() - w.winfo_width()) // 2
        y = (w.winfo_screenheight() - w.winfo_height()) // 3 if big else 40
        w.geometry(f"+{x}+{y}")
        if big:
            w.focus_force()
            try:
                import alerts
                alerts.send("STOP: scam address copied", f"{f['chain']} {f['address']}\n" + "\n".join(f["why"]),
                            critical=True, key="clipguard-" + f["address"])
            except Exception:
                pass
            print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] STOP: copied {f['chain']} {f['address']} ({'; '.join(f['why'])})", flush=True)
        else:
            w.after(5000 if f["level"] == "saved" else 9000, w.destroy)

    def tick():
        try:
            if time.time() - state["cfg_at"] > 10:
                state["cfg"], state["cfg_at"] = _load(CFG, {}), time.time()
            try:
                text = root.clipboard_get()
            except tk.TclError:
                text = None          # empty or not text (an image, files)
            if text != state["last"]:
                state["last"] = text
                for f in assess(text):
                    if f["level"] == "unknown" and not state["cfg"].get("clipguard_unknown", True):
                        continue
                    show(f)
        except Exception as ex:
            print(f"guard error: {ex}", flush=True)
        root.after(POLL_MS, tick)

    try:
        state["last"] = root.clipboard_get()      # don't react to whatever was already copied
    except tk.TclError:
        pass
    print("Copy-paste guard running.", flush=True)
    root.after(POLL_MS, tick)
    root.mainloop()


def enabled():
    return bool(_load(CFG, {}).get("clipguard"))


# ---------------------------------------------------------------- Desk page /clipguard ----

e = lambda s: html.escape(str(s if s is not None else ""), quote=True)
CSS = """body{font-family:Segoe UI,Arial,sans-serif;font-size:18px;max-width:900px;margin:24px auto;padding:0 16px;color:#111;background:#fff}
h1{font-size:30px}h2{font-size:22px;margin-top:28px}.mono{font-family:Consolas,monospace;word-break:break-all}
.box{border:2px solid #ddd;border-radius:10px;padding:14px 18px;margin:14px 0}
.stop{border-color:#b00020;background:#fdecee}.saved{border-color:#1e7d32;background:#eaf6ec}.unknown{border-color:#f2b01e;background:#fff8e6}
input[type=text]{font-size:18px;padding:8px;width:100%;box-sizing:border-box}button{font-size:18px;padding:8px 16px;cursor:pointer}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}
.hint{color:#444;font-size:16px}"""


def page(msg="", test=None, test_text=""):
    cfg = _load(CFG, {})
    on, unk = bool(cfg.get("clipguard")), cfg.get("clipguard_unknown", True)
    rows = "".join(f"<tr><td>{e(v['label'])}</td><td>{e(v['chain'])}</td><td class=mono>{e(v['address'])}</td>"
                   f"<td><form method=post action=/clipguard><input type=hidden name=do value=remove>"
                   f"<input type=hidden name=address value='{e(v['address'])}'><button>Remove</button></form></td></tr>"
                   for v in sorted(book().values(), key=lambda v: v["label"].lower()))
    tres = ""
    if test is not None:
        tres = "".join(f"<div class='box {f['level']}'><b>{e(message(f)[0])}</b><div class=mono style='font-size:20px'>{e(chunked(f['address']))}</div>"
                       f"<p>{e(message(f)[1])}</p></div>" for f in test) or "<p>No valid crypto address found in that text.</p>"
    try:
        import threatfeed
        camps = "".join(f"<li><b>{e(c['name'])}</b>, first seen {e(c.get('first_seen'))}: {len(c.get('addresses', []))} attacker addresses</li>"
                        for c in threatfeed.campaigns())
    except Exception:
        camps = ""
    note = "" if os.name == "nt" else "<p class=hint>Tested on Windows. On other systems it needs a desktop session with Tk.</p>"
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Copy-paste guard</title><style>{CSS}</style></head><body>
<h1>Copy-paste guard</h1>
<p>Malware on a website can swap the crypto address you copy for a scammer's. The swapped address looks real and passes every
wallet check. The guard checks each address the moment you copy it.</p>
{f"<div class='box saved'>{e(msg)}</div>" if msg else ""}
<div class="box {'saved' if on else 'unknown'}"><b>The guard is {'ON' if on else 'OFF'}.</b>
<form method=post action=/clipguard style="display:inline"><input type=hidden name=do value={'off' if on else 'on'}>
<button>{'Turn off' if on else 'Turn on'}</button></form>
<p class=hint>When it's on, the Desk runs it in the background. Nothing you copy is saved; only addresses are checked.</p>
<form method=post action=/clipguard><input type=hidden name=do value=unknown>
<label><input type=checkbox name=v value=1 {'checked' if unk else ''} onchange="this.form.submit()"> Also remind me to double-check
addresses that aren't in my address book</label></form></div>{note}
<h2>Your address book</h2>
<p class=hint>Save the addresses you send to regularly: your own exchange deposit addresses, people you pay. When you copy one, the guard
confirms it by name. Save an address only after checking it carefully (for an exchange, on the exchange's own app).</p>
<table><tr><th>Name</th><th>Chain</th><th>Address</th><th></th></tr>{rows or "<tr><td colspan=4>No saved addresses yet.</td></tr>"}</table>
<form method=post action=/clipguard class=box><input type=hidden name=do value=add>
<label>Name (for example "My Coinbase BTC deposit")</label><input type=text name=label>
<label>Address</label><input type=text name=address class=mono><p><button>Save address</button></p></form>
<h2>Check an address now</h2>
<form method=post action=/clipguard><input type=hidden name=do value=test>
<input type=text name=text value="{e(test_text)}" placeholder="Paste an address or a message containing one"><p><button>Check</button></p></form>{tres}
<h2>Known campaigns (updated with each signed release)</h2><ul>{camps or "<li>None loaded.</li>"}</ul>
</body></html>"""


def post(form):
    do = (form.get("do") or "").strip()
    cfg = _load(CFG, {})
    if do in ("on", "off"):
        cfg["clipguard"] = do == "on"
        _save(CFG, cfg)
        return page("Guard turned on. It starts within 15 seconds; copy an address to try it." if do == "on" else "Guard turned off.")
    if do == "unknown":
        cfg["clipguard_unknown"] = bool(form.get("v"))
        _save(CFG, cfg)
        return page("Saved.")
    if do == "add":
        ok, m = book_add(form.get("address", ""), form.get("label", ""))
        return page(m)
    if do == "remove":
        book_remove(form.get("address", ""))
        return page("Removed.")
    if do == "test":
        t = form.get("text", "")
        return page(test=assess(t), test_text=t)
    return page()


if __name__ == "__main__":
    if sys.argv[1:2] == ["check"]:
        for f in assess(" ".join(sys.argv[2:])):
            print(f["level"].upper(), f["chain"], f["address"], "; ".join(f["why"]))
    else:
        run()
