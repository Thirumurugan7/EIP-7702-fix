#!/usr/bin/env python3
"""Regenerate the codehash constants in src/ProtocolCodehashes.sol for the active Foundry profile.

Pins are compiled into contracts that are themselves pinned, so one pass is not enough: rebuild and
re-measure until nothing changes. Usage (from the repo root):

    FOUNDRY_SOLC=/path/to/oksolc python3 test/tools/update-pins.py            # default profile
    FOUNDRY_SOLC=/path/to/oksolc FOUNDRY_PROFILE=production python3 test/tools/update-pins.py
"""
import os, re, subprocess, sys

SRC = "src/ProtocolCodehashes.sol"
suffix = "_PRODUCTION" if os.environ.get("FOUNDRY_PROFILE") == "production" else "_DEFAULT"

def measure():
    out = subprocess.run(
        ["forge", "test", "--match-contract", "PinReport", "-vv"], capture_output=True, text=True
    )
    pins = dict(re.findall(r"PIN (\w+) (0x[0-9a-f]{64})", out.stdout))
    if len(pins) != 11:
        sys.stderr.write(out.stdout[-3000:] + out.stderr[-3000:])
        sys.exit("expected 11 pins, got %d" % len(pins))
    return pins

for round_ in range(1, 9):
    pins = measure()
    text = open(SRC).read()
    changed = []
    for name, value in pins.items():
        pattern = re.compile(r"(%s%s\s*=\s*)(0x[0-9a-fA-F]{64})" % (name, suffix))
        m = pattern.search(text)
        if not m:
            sys.exit("constant not found: %s%s" % (name, suffix))
        if m.group(2).lower() != value:
            text = pattern.sub(lambda mm: mm.group(1) + value, text, count=1)
            changed.append(name)
    print("round %d: %s" % (round_, ", ".join(changed) if changed else "stable"))
    if not changed:
        break
    open(SRC, "w").write(text)
else:
    sys.exit("pins did not converge")
