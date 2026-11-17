"""Windows Defender (Microsoft Defender Antivirus) from the Desk: is it on and up to date, what has it
caught lately, and scan a file or run a quick scan.

Read-only status, plus scans you start yourself. The Desk never changes Defender's settings (it
doesn't turn anything on or off and never adds exclusions). Works without administrator rights.
If Defender finds something, Defender handles it (quarantine) as it normally would.
"""
import json
import os
import subprocess
import threading
import time

RUN = None          # test hook: f(args:list, env:dict|None, timeout:int) -> (returncode, stdout)


def available():
    return os.name == "nt" and os.path.exists(mpcmdrun())


def mpcmdrun():
    return os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe")


def _run(args, env=None, timeout=60):
    if RUN:
        return RUN(args, env, timeout)
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env={**os.environ, **(env or {})},
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return p.returncode, p.stdout


def _ps(script, env=None, timeout=60):
    code, out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], env, timeout)
    out = (out or "").strip()
    if code != 0 or not out:
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def _date(v):
    """PowerShell 5 dates come as '/Date(1794884185933)/'."""
    if isinstance(v, str) and v.startswith("/Date("):
        try:
            return time.strftime("%Y-%m-%d %H:%M", time.localtime(int(v[6:].split(")")[0].split("+")[0].split("-")[0]) / 1000))
        except ValueError:
            return ""
    return str(v or "")[:16].replace("T", " ")


def status():
    """{'ok', 'on', 'realtime', 'tamper', 'sig_age_days', 'sig_updated', 'quick_age', 'full_age', 'problems': [...]}"""
    if not available() and not RUN:
        return {"ok": False, "why": "Windows Defender isn't available on this computer."}
    d = _ps("Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected,"
            "AntivirusSignatureAge,AntivirusSignatureLastUpdated,QuickScanAge,FullScanAge,AMRunningMode | ConvertTo-Json")
    if not d:
        return {"ok": False, "why": "Couldn't read Windows Defender's status (another antivirus may be in charge)."}
    never = lambda v: v is None or int(v) >= 4294967295 // 2
    s = {"ok": True, "on": bool(d.get("AMServiceEnabled") and d.get("AntivirusEnabled")), "realtime": bool(d.get("RealTimeProtectionEnabled")),
         "tamper": bool(d.get("IsTamperProtected")), "sig_age_days": d.get("AntivirusSignatureAge"),
         "sig_updated": _date(d.get("AntivirusSignatureLastUpdated")), "mode": d.get("AMRunningMode"),
         "quick_age": None if never(d.get("QuickScanAge")) else d.get("QuickScanAge"),
         "full_age": None if never(d.get("FullScanAge")) else d.get("FullScanAge")}
    p = []
    if not s["on"]:
        p.append(("stop", "Windows Defender antivirus is OFF (or another antivirus has replaced it)."))
    elif not s["realtime"]:
        p.append(("stop", "Real-time protection is OFF: files aren't checked as they arrive. Turn it on in Windows Security."))
    if s["on"] and not s["tamper"]:
        p.append(("caution", "Tamper protection is off: malware could switch Defender off. Turn it on in Windows Security."))
    if isinstance(s["sig_age_days"], int) and s["sig_age_days"] > 3:
        p.append(("caution", f"Virus definitions are {s['sig_age_days']} days old. Run Windows Update."))
    if s["quick_age"] is None or (isinstance(s["quick_age"], int) and s["quick_age"] > 14):
        p.append(("caution", "No recent quick scan. Run one below (a few minutes)."))
    if s["full_age"] is None:
        p.append(("info", "A full scan has never been run on this computer. It takes an hour or more; run it from Windows Security when convenient."))
    s["problems"] = p
    return s


def detections(n=10):
    """Recent things Defender caught: [{'when', 'name', 'severity', 'where', 'handled'}]"""
    rows = _ps("$t=@{}; Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { $t[[string]$_.ThreatID]=@($_.ThreatName,$_.SeverityID) };"
               f"@(Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending | Select-Object -First {int(n)} | "
               "ForEach-Object { [pscustomobject]@{when=$_.InitialDetectionTime; name=$t[[string]$_.ThreatID][0]; sev=$t[[string]$_.ThreatID][1];"
               " where=(@($_.Resources) -join '; '); handled=$_.ActionSuccess} }) | ConvertTo-Json -Depth 3")
    if rows is None:
        return []
    if isinstance(rows, dict):
        rows = [rows]
    sev = {1: "low", 2: "medium", 4: "high", 5: "severe"}
    return [{"when": _date(r.get("when")), "name": r.get("name") or "unknown threat", "severity": sev.get(r.get("sev"), ""),
             "where": (r.get("where") or "")[:300], "handled": bool(r.get("handled"))} for r in rows]


def scan_file(path, timeout=300):
    """Defender custom scan of one file or folder. {'ran', 'threat', 'detail'} ; Defender quarantines anything it finds."""
    if not os.path.exists(path):
        return {"ran": False, "threat": None, "detail": "file not found"}
    if not available() and not RUN:
        return {"ran": False, "threat": None, "detail": "Windows Defender isn't available on this computer"}
    try:
        code, out = _run([mpcmdrun(), "-Scan", "-ScanType", "3", "-File", path], timeout=timeout)
    except Exception as ex:
        return {"ran": False, "threat": None, "detail": f"scan didn't run: {ex}"[:200]}
    if code == 0:
        return {"ran": True, "threat": False, "detail": "Windows Defender found no threats in it."}
    if code == 2:
        lines = [l.strip() for l in (out or "").splitlines() if "Threat" in l or "threat" in l]
        return {"ran": True, "threat": True, "detail": "Windows Defender found a threat" + (f": {lines[0][:160]}" if lines else "") +
                ". Defender has quarantined it or will ask you what to do."}
    return {"ran": False, "threat": None, "detail": f"Windows Defender couldn't scan it (code {code})."}


_quick = {"running": False, "started": None, "result": None}


def quick_scan_start():
    if _quick["running"] or (not available() and not RUN):
        return False
    _quick.update(running=True, started=time.strftime("%H:%M"), result=None)

    def go():
        try:
            code, _ = _run([mpcmdrun(), "-Scan", "-ScanType", "1"], timeout=3600)
            _quick["result"] = {0: "Quick scan finished: no threats found.",
                                2: "Quick scan found threats. Defender has handled them; see 'Recently caught' below."}.get(
                code, f"Quick scan stopped (code {code}).")
        except Exception as ex:
            _quick["result"] = f"Quick scan didn't run: {ex}"[:200]
        _quick["running"] = False
    threading.Thread(target=go, daemon=True).start()
    return True


def quick_scan_state():
    return dict(_quick)


def signature(path):
    """Who signed this program (Windows Authenticode). {'status', 'signer'} ; status 'Valid' means signed and unchanged."""
    d = _ps("Get-AuthenticodeSignature -LiteralPath $env:SH_FILE | Select-Object @{n='status';e={[string]$_.Status}},"
            "@{n='signer';e={$_.SignerCertificate.Subject}} | ConvertTo-Json", env={"SH_FILE": path}, timeout=30)
    return d or {"status": "Unknown", "signer": None}
