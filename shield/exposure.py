"""Is anything at my home or business reachable from the internet that shouldn't be?

In October 2026 attackers switched the refrigeration at hundreds of French supermarkets into
defrost overnight. They didn't need anything clever: the stores' refrigeration controllers were
reachable from the internet, with a login of "admin" and the current date as the password. In
November CISA and the FBI warned that cold-chain controllers everywhere are targets. The same
mistake exposes cameras, door systems, HVAC, remote desktops and old routers.

This check looks up YOUR OWN public internet address in Shodan's free InternetDB (a public record
of what internet-wide scans have already seen there: open ports, product names, known flaws),
then, only for your own address, looks at the login page of any open web port to name the device.
It never logs in, never tries passwords, never probes anyone else.

Run it from the network you want to check (the store's, the office's, your home's).

    python -m shield.exposure            # this connection's address
"""
import html
import ipaddress
import json
import re
import ssl
import urllib.request

UA = {"User-Agent": "ScamHunter-ExposureCheck/1.0"}
GET = None        # test hook: f(url) -> str

# port -> (what it is, severity, plain advice)
PORTS = {
    502: ("Modbus (industrial controllers: refrigeration, HVAC, pumps, PLCs)", "critical", "Industrial equipment answers anyone on the internet. Have your installer put it behind a VPN or take it offline today."),
    102: ("Siemens S7 (industrial controllers)", "critical", "Industrial controller exposed. Take it off the internet."),
    20000: ("DNP3 (utility / industrial control)", "critical", "Industrial control protocol exposed. Take it off the internet."),
    47808: ("BACnet (building automation: HVAC, refrigeration, lighting)", "critical", "Building controls are reachable from anywhere. Take them off the internet."),
    44818: ("EtherNet/IP (industrial controllers)", "critical", "Industrial controller exposed. Take it off the internet."),
    2404: ("IEC 60870-5-104 (power / utility control)", "critical", "Utility control protocol exposed."),
    1911: ("Niagara Fox (building automation)", "critical", "Building management system exposed."),
    4911: ("Niagara Fox (building automation, TLS)", "critical", "Building management system exposed."),
    9600: ("OMRON FINS (industrial controllers)", "critical", "Industrial controller exposed."),
    1962: ("PCWorx (industrial controllers)", "critical", "Industrial controller exposed."),
    2455: ("CODESYS (industrial controllers)", "critical", "Industrial controller exposed."),
    789: ("Red Lion (industrial controllers)", "critical", "Industrial controller exposed."),
    10001: ("Automated tank gauge (fuel tanks)", "high", "Tank monitoring may be exposed; check with your fuel system vendor."),
    3389: ("Remote Desktop (Windows)", "high", "Ransomware gangs scan for this constantly. Turn it off or put it behind a VPN."),
    5900: ("VNC remote control", "high", "Remote control of a computer is open to the internet. Turn it off or use a VPN."),
    23: ("Telnet (old, unencrypted remote login)", "high", "Telnet sends passwords in plain text. Turn it off."),
    445: ("Windows file sharing (SMB)", "high", "File sharing should never face the internet. Block it at the router."),
    21: ("FTP file transfer", "medium", "Old and unencrypted. Turn it off unless you need it."),
    22: ("SSH remote login", "low", "Fine if it uses keys, not passwords, and is kept updated."),
    554: ("Camera video stream (RTSP)", "high", "A camera or recorder streams to the internet. Check its password and firmware, or turn off remote access."),
    37777: ("Dahua camera / recorder", "high", "Security camera recorder exposed. Update it and turn off port forwarding."),
    8000: ("Hikvision camera / recorder (or a web app)", "medium", "If this is a camera recorder, update it and turn off port forwarding."),
    1883: ("MQTT (smart devices, sensors)", "medium", "Smart-device messaging is open; make sure it requires a password."),
    5000: ("Web app / NAS / UPnP", "medium", "Check what this is."),
    7547: ("Router remote management (TR-069)", "medium", "Your internet provider's remote management; ask them if it should be open."),
    8291: ("MikroTik router management", "high", "Router admin open to the internet. Restrict it."),
    161: ("SNMP (network device information)", "medium", "Can leak device details. Block it at the router."),
}
WEB_PORTS = (80, 443, 8080, 8443, 8081, 8888, 9000)
# login-page fingerprints -> device (titles and page text seen on these products)
DEVICES = [
    (r"\bAK-?SM\s?8\d\d|\bAK-?SC\s?355|danfoss", "Danfoss refrigeration controller (the model family hit in the 2026 supermarket attacks)", "critical"),
    (r"\bXWEB\b|dixell|copeland\s*xweb", "Dixell / Copeland XWEB refrigeration supervisor (named in the 2026 attacks)", "critical"),
    (r"\bE2\b.{0,40}(emerson|copeland)|emerson.{0,40}\bE2\b|site supervisor", "Emerson / Copeland E2 or Site Supervisor refrigeration controller", "critical"),
    (r"pCOWeb|carel|boss\s*mini|plantvisor", "Carel refrigeration / HVAC controller", "critical"),
    (r"niagara|tridium|\bjace\b", "Tridium Niagara building controller", "critical"),
    (r"metasys|johnson controls", "Johnson Controls building system", "critical"),
    (r"\bsiemens\b.{0,40}(desigo|s7|simatic)", "Siemens building / industrial controller", "critical"),
    (r"veeder|tls-?\d{3}", "Veeder-Root fuel tank gauge", "high"),
    (r"hikvision|dahua|\bDVR\b|\bNVR\b|webcam|ip camera", "Camera or video recorder", "high"),
    (r"synology|qnap|\bNAS\b", "Network storage (NAS)", "high"),
    (r"routeros|mikrotik|netgear|tp-?link|asus router|linksys|fortigate|sonicwall|pfsense", "Router or firewall admin page", "high"),
]
FIX = [
    "Remove equipment controllers from the public internet. If a vendor needs remote access, use a VPN or the vendor's secure cloud service, not port forwarding.",
    "Change every default password, and turn off logins that use the date or another fixed code.",
    "Install the maker's updates. Equipment no longer supported (for example Danfoss AK-SC355, AK-SM800) should be replaced.",
    "Keep equipment on a separate network from business computers and guest Wi-Fi.",
    "Set safe temperature limits and an alarm that reaches a phone, so an overnight change can't go unnoticed.",
]


def _get(url, timeout=12):
    if GET:
        return GET(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE        # device pages often have self-signed certificates
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout, context=ctx) as r:
        return r.read(200_000).decode("utf-8", "replace")


def my_ip():
    for u in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            ip = _get(u).strip()
            ipaddress.ip_address(ip)
            return ip
        except Exception:
            continue
    return None


def internetdb(ip):
    try:
        return json.loads(_get(f"https://internetdb.shodan.io/{ip}"))
    except Exception as ex:
        if "404" in str(ex):
            return {"ip": ip, "ports": [], "cpes": [], "hostnames": [], "tags": [], "vulns": []}
        return None


def identify(ip, port):
    """Title / product of the web page on one of YOUR OWN open web ports (no login attempted)."""
    for scheme in (("https",) if port in (443, 8443) else ("http", "https")):
        try:
            page = _get(f"{scheme}://{ip}:{port}/", timeout=8)
        except Exception:
            continue
        title = (re.search(r"<title[^>]*>(.*?)</title>", page, re.I | re.S) or [None, ""])[1]
        title = html.unescape(re.sub(r"\s+", " ", title)).strip()[:120]
        for rx, name, sev in DEVICES:
            if re.search(rx, title + " " + page[:20000], re.I):
                return {"title": title, "device": name, "severity": sev}
        return {"title": title, "device": None, "severity": "info"}
    return None


def check(ip=None, mine=True, look=True):
    """mine=True: ip is this connection's own address (looked up automatically when not given)."""
    ip = ip or my_ip()
    if not ip:
        return {"ok": False, "error": "Couldn't find this connection's public internet address."}
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "That isn't an internet address."}
    if a.is_private or a.is_loopback:
        return {"ok": False, "error": "That's a private address inside a network; the internet can't see it directly."}
    db = internetdb(ip)
    if db is None:
        return {"ok": False, "error": "Couldn't reach Shodan's InternetDB right now. Try again later."}
    items = []
    for p in sorted(db.get("ports") or []):
        if p in PORTS:
            what, sev, adv = PORTS[p]
            items.append({"port": p, "what": what, "severity": sev, "advice": adv})
        elif p in WEB_PORTS:
            items.append({"port": p, "what": "Web page", "severity": "info", "advice": "Check what this page is: a device login page should not face the internet."})
        else:
            items.append({"port": p, "what": "Other service", "severity": "low", "advice": "Find out what answers here; close it if it isn't needed."})
    if look and mine:
        for it in items:
            if it["port"] in WEB_PORTS:
                d = identify(ip, it["port"])
                if d:
                    it["title"] = d["title"]
                    if d["device"]:
                        it.update({"what": f"Web login: {d['device']}", "severity": d["severity"],
                                   "advice": "This device's login page is open to the whole internet. Take it off the internet today."})
    for c in db.get("cpes") or []:
        for rx, name, sev in DEVICES:
            if re.search(rx, c, re.I):
                items.append({"port": None, "what": f"Scanners identified: {name}", "severity": sev, "advice": "Take it off the internet."})
                break
    if "ics" in (db.get("tags") or []) and not any(i["severity"] == "critical" for i in items):
        items.append({"port": None, "what": "Scanners tagged this address as industrial equipment (ICS)", "severity": "critical",
                      "advice": "Find which device it is and take it off the internet."})
    vulns = sorted(db.get("vulns") or [])
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    items.sort(key=lambda i: order[i["severity"]])
    worst = items[0]["severity"] if items else "none"
    return {"ok": True, "ip": ip, "mine": mine, "items": items, "vulns": vulns, "worst": worst,
            "hostnames": db.get("hostnames") or [], "fix": FIX if worst in ("critical", "high") else FIX[1:3]}


# ---------------------------------------------------------------- Desk page /exposure ----

e = lambda s: html.escape(str(s if s is not None else ""), quote=True)
CSS = """body{font-family:Segoe UI,Arial,sans-serif;font-size:19px;max-width:900px;margin:24px auto;padding:0 16px;color:#111;background:#fff;line-height:1.45}
h1{font-size:30px}.box{border:2px solid #ddd;border-radius:10px;padding:12px 16px;margin:10px 0}
.critical{border-color:#b00020;background:#fdecee}.high{border-color:#d9480f;background:#fff0e6}.medium{border-color:#f2b01e;background:#fff8e6}
.low,.info{border-color:#bbb}.none{border-color:#1e7d32;background:#eaf6ec}button{font-size:19px;padding:9px 20px;cursor:pointer}
input[type=text]{font-size:18px;padding:7px}.hint{color:#444;font-size:16px}"""


def page(result=None, msg=""):
    body = ""
    if result:
        if not result.get("ok"):
            body = f"<div class='box medium'>{e(result['error'])}</div>"
        else:
            its = "".join(f"<div class='box {i['severity']}'><b>{e(i['severity'].upper())}{' &middot; port ' + str(i['port']) if i['port'] else ''}</b>: "
                          f"{e(i['what'])}{' &mdash; page title: ' + e(i['title']) if i.get('title') else ''}<br>{e(i['advice'])}</div>" for i in result["items"])
            head = ("<div class='box none'><b>Nothing exposed.</b> Internet scans have seen no open services at this address.</div>"
                    if not result["items"] else "")
            vul = (f"<p><b>Known security flaws reported for software at this address:</b> {e(', '.join(result['vulns'][:15]))}</p>"
                   if result["vulns"] else "")
            fix = "".join(f"<li>{e(x)}</li>" for x in result["fix"])
            body = (f"<h2>Address {e(result['ip'])}</h2>{head}{its}{vul}"
                    + (f"<h2>What to do</h2><ol>{fix}</ol>" if result["items"] else ""))
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Exposure check</title><style>{CSS}</style></head><body>
<h1>Is anything here open to the internet?</h1>
<p>Refrigeration, heating and cooling controllers, cameras and remote-desktop computers get attacked when they can be reached from the
internet. In October 2026 that's how attackers heated the fridges at hundreds of supermarkets overnight. This checks what internet-wide
scans have already seen at <b>your</b> address. It never logs in to anything.</p>
<p class=hint>Run it on the computer connected to the network you want to check, such as the store's or the office's.</p>
{f"<div class='box medium'>{e(msg)}</div>" if msg else ""}
<form method=post action=/exposure><input type=hidden name=do value=mine><button>Check this network</button></form>
<form method=post action=/exposure style="margin-top:14px"><input type=hidden name=do value=other>
<label>Or another address you own or manage: <input type=text name=ip placeholder="203.0.113.10"></label>
<label><input type=checkbox name=own value=1> I own or manage this address</label> <button>Check</button></form>{body}
<p class=hint>Data: Shodan InternetDB (free, for non-commercial use), updated weekly, so a just-closed port may still show.</p></body></html>"""


def post(form):
    if form.get("do") == "other":
        if not form.get("own"):
            return page(msg="Please confirm you own or manage that address. Checking other people's networks isn't allowed.")
        return page(check(form.get("ip", "").strip(), mine=False))
    return page(check())


if __name__ == "__main__":
    print(json.dumps(check(), indent=1))
