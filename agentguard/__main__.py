"""python -m agentguard scan <file or -> [--html]   |   python -m agentguard action '<json>'"""
import json
import sys

from . import decide, scan

if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["scan"] and len(a) > 1:
        data = sys.stdin.read() if a[1] == "-" else open(a[1], encoding="utf-8", errors="replace").read()
        r = scan(data, "html" if "--html" in a else None)
        print(f"risk: {r['risk']}")
        for f in r["findings"]:
            print(f"  [{f['level']}] {f['where']}: {f['what']}")
    elif a[:1] == ["action"] and len(a) > 1:
        print(json.dumps(decide(json.loads(a[1])), indent=1))
    else:
        print(__doc__)
