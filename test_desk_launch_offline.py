"""Offline test of the Desk's launch safety (no network, no real processes):
a second Desk doesn't start, leftover watchers are stopped, other programs are left alone.
    python test_desk_launch_offline.py
"""
import os, subprocess, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import desk

ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []


class H(BaseHTTPRequestHandler):
    body = b"<title>ScamHunter Threat Desk</title>"
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(self.body)
    def log_message(self, *a):
        pass


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
port = srv.server_address[1]
r.append(ok(desk._already_running(port), "a running Desk is detected, so a second copy won't start"))
H.body = b"<title>Some other app</title>"
r.append(ok(not desk._already_running(port), "another program on the port is not mistaken for the Desk"))
srv.shutdown()
r.append(ok(not desk._already_running(port), "nothing listening: the Desk starts normally"))

# leftover watchers
exe = desk.SERVICES[0][1][0]
listing = "\n".join([
    f"101\t\"{exe}\" -u -m multichain watch --interval 300",
    f"102\t{exe} -u -m scam_investigator.netwatch",
    f"103\t{exe} -u -m some_other_tool watch",
    f"104\tpython.exe C:\\Users\\x\\my_script.py",
])
killed = []
real_name, real_run = os.name, subprocess.run


def fake_run(args, **kw):
    if args[0] == "powershell":
        return subprocess.CompletedProcess(args, 0, stdout=listing, stderr="")
    if args[0] == "taskkill":
        killed.append(args[2])
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
    raise AssertionError(args)


desk.os.name = "nt"
desk.subprocess.run = fake_run
try:
    n = desk._stop_orphans(log=lambda *_: None)
finally:
    desk.os.name = real_name
    desk.subprocess.run = real_run
r.append(ok(n == 2 and sorted(killed) == ["101", "102"], f"only the Desk's own leftover watchers are stopped ({killed})"))
r.append(ok(desk._stop_orphans() == 0 or os.name == "nt", "does nothing off Windows"))

# missing packages: installed, then the Desk starts over in a fresh Python (a running one may not see them)
import builtins
real_import, real_run, real_call, real_exit = builtins.__import__, desk.subprocess.run, desk.subprocess.call, sys.exit
calls, exits = [], []
def no_segno(name, *a, **k):
    if name == "segno":
        raise ImportError("no segno")
    return real_import(name, *a, **k)
builtins.__import__ = no_segno
desk.subprocess.run = lambda args, **kw: calls.append(("run", args)) or subprocess.CompletedProcess(args, 0)
desk.subprocess.call = lambda args, **kw: calls.append(("call", args)) or 0
desk.sys.exit = lambda code=0: exits.append(code)
os.environ.pop("SCAMHUNTER_DEPS_RESTARTED", None)
try:
    desk.ensure_deps()
    first = list(calls)
    calls.clear()
    desk.ensure_deps()                      # the restarted Desk must not restart again
finally:
    builtins.__import__, desk.subprocess.run, desk.subprocess.call, desk.sys.exit = real_import, real_run, real_call, real_exit
r.append(ok([c[0] for c in first] == ["run", "call"] and "--require-hashes" in first[0][1] and first[1][1][0] == sys.executable,
            "packages installed with hash checks, then the Desk restarts in a fresh Python"))
r.append(ok([c[0] for c in calls] == ["run"], "it restarts only once"))
os.environ.pop("SCAMHUNTER_DEPS_RESTARTED", None)

print(f"{sum(r)}/{len(r)} passed")
sys.exit(0 if all(r) else 1)
