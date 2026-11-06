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
    body = b"<title>ScamHunter Desk</title>"
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

print(f"{sum(r)}/{len(r)} passed")
sys.exit(0 if all(r) else 1)
