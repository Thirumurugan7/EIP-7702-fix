#!/bin/sh
# Compile the UNPATCHED release (the branch's base commit) into out-orig/, for test/Migration7702.t.sol.
# The working tree is restored afterwards. Usage (repo root): FOUNDRY_SOLC=/path/to/oksolc sh test/tools/build-original.sh
set -e
if [ -n "$(git stash list)" ]; then echo "refusing to run with an existing git stash"; exit 1; fi
git stash push -q -- src packages doc
trap 'git stash pop -q' EXIT
forge build --skip test --out out-orig --cache-path cache-orig
