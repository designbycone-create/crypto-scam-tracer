"""Hardware wallet check, step 2: what does the wallet tell Windows about itself over USB?

A partial check. Take a list of USB devices with the wallet unplugged, then again after it's plugged in: the new
entries are everything the wallet presented, with nothing else mixed in. Read-only (a fixed PowerShell command,
nothing typed by anyone is passed into it); nothing is installed or sent to the device. A match does NOT prove a
wallet is genuine: a fake can copy these IDs, and a hidden chip with its own SIM card never shows up here.

Vendor IDs are from the makers' published device rules (Ledger 2c97; Trezor 534c:0001 and 1209:53c1;
Coinkite/Coldcard d13e:cc10). See NOTICE.md.
"""
import json
import os
import re
import subprocess

VENDORS = {"2c97": "Ledger", "534c": "Trezor", "1209:53c1": "Trezor", "d13e": "Coinkite (Coldcard)"}
TYPING = {"coinkite (coldcard)"}           # makers that document a keyboard ("type passwords") feature
RISKY = {"Keyboard": "stop", "DiskDrive": "careful", "Volume": "careful", "WPD": "careful", "Net": "careful",
         "Modem": "careful", "Ports": "careful", "Bluetooth": "careful", "Camera": "careful", "AudioEndpoint": "careful"}
CMD = ["powershell", "-NoProfile", "-NonInteractive", "-Command",
       "Get-PnpDevice -PresentOnly | Select-Object InstanceId,FriendlyName,Class,Manufacturer | ConvertTo-Json -Compress"]
LIST = None          # test hook: f() -> [{"InstanceId","FriendlyName","Class","Manufacturer"}]


class NotAvailable(Exception):
    pass


def snapshot():
    if LIST:
        return LIST()
    if os.name != "nt":
        raise NotAvailable("This check reads Windows' device list, so it only works on the Windows computer running the Desk.")
    try:
        r = subprocess.run(CMD, capture_output=True, text=True, timeout=25, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired) as ex:
        raise NotAvailable(f"Windows didn't give the device list ({type(ex).__name__}).")
    try:
        data = json.loads(r.stdout or "[]")
    except ValueError:
        raise NotAvailable("Windows gave a device list the Desk couldn't read.")
    return data if isinstance(data, list) else [data]


def ids(dev):
    m = re.search(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", str(dev.get("InstanceId", "")), re.I)
    return (m.group(1).lower(), m.group(2).lower()) if m else (None, None)


def maker(dev):
    vid, pid = ids(dev)
    if not vid:
        return None
    return VENDORS.get(f"{vid}:{pid}") or (VENDORS.get(vid) if vid != "1209" else None)


def new_devices(before, after):
    seen = {d.get("InstanceId") for d in before}
    return [d for d in after if d.get("InstanceId") not in seen]


def judge(new, brand):
    """(level, sentence, rows) for the devices that appeared. brand: 'ledger' | 'trezor' | 'other' | 'unknown'."""
    rows, level, why = [], "ok", []
    makers = {m for m in (maker(d) for d in new) if m}
    for d in new:
        m = maker(d)
        cls = d.get("Class") or ""
        note = ""
        if cls == "Keyboard" and not (m or "").lower() in TYPING:
            note, lv = "A keyboard appeared. A hidden keyboard can type commands into this computer.", "stop"
        elif cls in RISKY and RISKY[cls] != "stop":
            note, lv = f"A {cls.lower()} device appeared, which a wallet doesn't usually need.", "careful"
        else:
            lv = "ok"
        known = "Yes" if m else ("Not sure" if not ids(d)[0] else "No")
        rows.append({"name": d.get("FriendlyName") or "(no name)", "maker": m or d.get("Manufacturer") or "Not shown",
                     "known": known, "note": note, "level": lv})
        if lv == "stop":
            level = "stop"
        elif lv == "careful" and level == "ok":
            level = "careful"
    if not new:
        return "info", "Nothing new appeared. Check the cable is a data cable and the wallet is turned on, then try again.", rows
    want = {"ledger": "Ledger", "trezor": "Trezor"}.get(brand)
    if want and want not in makers:
        level = "stop"
        why.append(f"It didn't present itself as a {want}." + (f" It said {', '.join(sorted(makers))}." if makers else ""))
    elif not makers and level == "ok":
        level = "careful"
        why.append("None of the new devices showed a known wallet maker's ID.")
    if any(r["level"] == "stop" for r in rows):
        why.append("Something appeared that a wallet shouldn't need.")
    sentence = {"stop": "Don't use this wallet. " + " ".join(why),
                "careful": "Something here needs a closer look. " + " ".join(why),
                "ok": "The device name matches the maker you picked."}[level]
    return level, sentence, rows
