#!/usr/bin/env python3
"""Keep doc/registry-containment.json and src/registry/RegistryContainmentSelectors.sol in step.

  python3 test/tools/containment.py check   # verify selectors, ordering, and that the packed table matches the JSON
  python3 test/tools/containment.py write   # regenerate the packed table from the JSON

The JSON is the reviewed inventory. The packed table holds one 5-byte record per selector that stays
callable while the Registry is paused: 4 selector bytes + 1 policy byte, sorted by selector.
"""
import json, re, subprocess, sys

DOC = "doc/registry-containment.json"
SOL = "src/registry/RegistryContainmentSelectors.sol"
POLICY_BYTE = {"read": 1, "nested": 1, "pause": 1, "resume": 1, "cancel": 2, "renounce": 2}  # "blocked" is absent

def table_from(entries):
    recs = sorted((e["selector"][2:], POLICY_BYTE[e["policy"]]) for e in entries if e["policy"] != "blocked")
    return "".join("%s%02x" % r for r in recs)

def main(mode):
    entries = json.load(open(DOC))
    sigs = [e["signature"] for e in entries]
    assert len(set(sigs)) == len(sigs), "duplicate signature in JSON"
    for e in entries:
        got = subprocess.run(["cast", "sig", e["signature"]], capture_output=True, text=True).stdout.strip()
        assert got == e["selector"], "selector mismatch for %s: %s != %s" % (e["signature"], got, e["selector"])
        assert e["policy"] == "blocked" or e["policy"] in POLICY_BYTE, e
    want = table_from(entries)
    src = open(SOL).read()
    m = re.search(r'hex"([0-9a-f]*)"', src)
    if mode == "write":
        open(SOL, "w").write(src[: m.start(1)] + want + src[m.end(1) :])
        print("table written: %d records" % (len(want) // 10))
    else:
        assert m.group(1) == want, "packed table does not match the JSON; run: containment.py write"
        print("ok: %d selectors, %d callable while paused" % (len(entries), len(want) // 10))

main(sys.argv[1] if len(sys.argv) > 1 else "check")
