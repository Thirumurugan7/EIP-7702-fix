#!/bin/sh
# Regenerate the codehash constants for BOTH Foundry profiles until neither changes.
# The constants are compiled into pinned contracts, so each profile's update can move the other's.
# Usage (repo root): FOUNDRY_SOLC=/path/to/oksolc sh test/tools/update-all-pins.sh
set -e
for pass in 1 2 3 4 5; do
  before=$(shasum src/ProtocolCodehashes.sol)
  echo "pass $pass: default";    python3 test/tools/update-pins.py
  echo "pass $pass: production"; FOUNDRY_PROFILE=production python3 test/tools/update-pins.py
  after=$(shasum src/ProtocolCodehashes.sol)
  if [ "$before" = "$after" ]; then echo "both profiles stable"; exit 0; fi
done
echo "pins did not converge across profiles"; exit 1
