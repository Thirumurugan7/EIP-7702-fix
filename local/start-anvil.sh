#!/bin/sh
# Local chain for Chainwall: an anvil fork of Arbitrum One with EIP-7702 (Prague) and 1 second blocks.
#
# Why a fork and not a blank chain: the contracts only deploy where the ERC-4337 EntryPoint v0.8 is
# pinned by chain id and codehash (src/WebAuthnEntryPoint.sol). Chain 31337 is not on that list, and the
# stack also needs the real Safe 1.3.0 contracts. Forking keeps chain id 42161 and all real contracts.
#
# Usage: sh local/start-anvil.sh            (port 8546, state in local/run/)
set -e
cd "$(dirname "$0")"
mkdir -p run
PORT=${PORT:-8546}
UPSTREAM=${UPSTREAM_RPC:-https://arb1.arbitrum.io/rpc}
if lsof -iTCP:$PORT -sTCP:LISTEN >/dev/null 2>&1; then echo "port $PORT is already in use"; exit 1; fi
BLOCK=${FORK_BLOCK:-$(cast block-number --rpc-url "$UPSTREAM")}
echo "$BLOCK" > run/fork-block
nohup anvil --fork-url "$UPSTREAM" --fork-block-number "$BLOCK" --hardfork prague --port "$PORT" \
  --block-time 1 --accounts 0 --retries 8 --timeout 60000 > run/anvil.log 2>&1 &
echo $! > run/anvil.pid
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if cast chain-id --rpc-url "http://127.0.0.1:$PORT" >/dev/null 2>&1; then
    echo "anvil pid $(cat run/anvil.pid), port $PORT, chain $(cast chain-id --rpc-url http://127.0.0.1:$PORT), forked at block $BLOCK"
    exit 0
  fi
  sleep 1
done
echo "anvil did not come up; see local/run/anvil.log"; exit 1
