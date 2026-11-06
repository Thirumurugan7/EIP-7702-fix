#!/usr/bin/env python3
"""Print production-profile runtime sizes, smallest margin first. Usage: python3 test/tools/sizes.py [N]"""
import re, subprocess, sys, os
env = dict(os.environ, FOUNDRY_PROFILE="production")
out = subprocess.run(["forge", "build", "--sizes", "--skip", "test", "--skip", "script"], capture_output=True, text=True, env=env).stdout
rows = []
for l in out.splitlines():
    m = re.match(r"\|\s*(\S+)\s*\|\s*([\d,]+)\s*\|\s*([\d,]+)\s*\|\s*(-?[\d,]+)\s*\|\s*(-?[\d,]+)\s*\|", l)
    if m:
        rows.append((m.group(1),) + tuple(int(x.replace(",", "")) for x in m.groups()[1:]))
rows.sort(key=lambda r: r[3])
print("%-36s %8s %8s %9s %9s" % ("contract", "runtime", "initcode", "rt margin", "ic margin"))
for r in rows[: int(sys.argv[1]) if len(sys.argv) > 1 else 12]:
    print("%-36s %8d %8d %9d %9d" % r)
