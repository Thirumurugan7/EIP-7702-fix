#!/usr/bin/env python3
"""Background traffic for the local Chainwall chain, so blocks look like a public network.

It keeps a pool of wallets and sends a randomly paced, randomly mixed stream of real transactions to
the anvil fork: native transfers, WETH wraps and transfers, token approvals, Uniswap v3 swaps on the
real forked pools, USDC transfers, small contract deployments and calls to them, transactions that
revert on chain, calldata-only "note" transactions, and EIP-7702 delegations and clears.

Standard library only. Wallets without a key are driven through anvil's account impersonation; a
smaller set of keyed wallets signs real EIP-7702 authorizations through `cast`.

  python3 local/noise.py                 # run until stopped (Ctrl-C or kill)
  python3 local/noise.py --seconds 120   # run for two minutes
  python3 local/noise.py --rate 10       # average transactions per second (default 6)

Stats are written to local/run/noise.stats every few seconds.
"""
import argparse, json, os, random, secrets, signal, subprocess, sys, time, urllib.request

WETH = "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1"
USDC = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"
ROUTER = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"  # Uniswap v3 SwapRouter02 on Arbitrum One
MAX_UINT = "f" * 64

HERE = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.join(HERE, "run")


def word(value):
    if isinstance(value, str):
        return value.lower().replace("0x", "").rjust(64, "0")
    return "%064x" % value


class Rpc:
    def __init__(self, url):
        self.url, self.n = url, 0

    def call(self, method, params=()):
        self.n += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(self.url, body, {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            out = json.load(resp)
        if "error" in out:
            raise RuntimeError(out["error"].get("message", str(out["error"])))
        return out["result"]


class Noise:
    def __init__(self, rpc, url, wallets, keyed, rate):
        self.rpc, self.url, self.rate = rpc, url, rate
        self.wallets = ["0x" + secrets.token_hex(20) for _ in range(wallets)]
        self.keyed = []          # (address, private key) for EIP-7702 traffic
        self.weth = {}           # address -> wei we know it holds
        self.usdc = set()        # addresses that swapped into USDC
        self.approved = set()
        self.contracts = []      # noise contracts deployed so far
        self.delegated = set()
        self.sent, self.errors, self.by_kind = 0, 0, {}
        self.last_error = ""
        self.setup(keyed)

    def setup(self, keyed):
        for w in self.wallets:
            self.rpc.call("anvil_impersonateAccount", [w])
            self.rpc.call("anvil_setBalance", [w, hex(random.randint(5 * 10**16, 8 * 10**18))])
        for _ in range(keyed):
            out = json.loads(subprocess.run(["cast", "wallet", "new", "--json"], capture_output=True, text=True).stdout)
            self.keyed.append((out[0]["address"], out[0]["private_key"]))
            self.rpc.call("anvil_setBalance", [out[0]["address"], hex(random.randint(10**17, 2 * 10**18))])

    # ---- sending

    def send(self, kind, sender, to=None, value=0, data="0x", gas=21000):
        tx = {"from": sender, "value": hex(value), "data": data, "gas": hex(gas)}
        if to:
            tx["to"] = to
        tip = random.choice([0, 0, 10**6, 10**7, 5 * 10**7, 10**8])
        if tip:
            tx["maxPriorityFeePerGas"] = hex(tip)
            tx["maxFeePerGas"] = hex(tip + 10**9)
        try:
            h = self.rpc.call("eth_sendTransaction", [tx])
            self.sent += 1
            self.by_kind[kind] = self.by_kind.get(kind, 0) + 1
            return h
        except Exception as e:  # noqa: BLE001 - noise must keep going
            self.errors += 1
            self.last_error = "%s: %s" % (kind, str(e)[:160])
            return None

    def pick(self):
        return random.choice(self.wallets)

    # ---- transaction kinds

    def native_transfer(self):
        a, b = self.pick(), self.pick()
        self.send("native transfer", a, b, random.randint(10**12, 3 * 10**16))

    def wrap(self):
        a = self.pick()
        amount = random.randint(10**14, 2 * 10**16)
        if self.send("weth deposit", a, WETH, amount, "0xd0e30db0", 70000):
            self.weth[a] = self.weth.get(a, 0) + amount

    def weth_transfer(self):
        holders = [a for a, v in self.weth.items() if v > 10**13]
        if not holders:
            return self.wrap()
        a, b = random.choice(holders), self.pick()
        amount = random.randint(1, self.weth[a] // 2)
        if self.send("weth transfer", a, WETH, 0, "0xa9059cbb" + word(b) + word(amount), 90000):
            self.weth[a] -= amount
            self.weth[b] = self.weth.get(b, 0) + amount

    def approve(self):
        holders = [a for a in self.weth if a not in self.approved]
        if not holders:
            return self.wrap()
        a = random.choice(holders)
        if self.send("approve", a, WETH, 0, "0x095ea7b3" + word(ROUTER) + MAX_UINT, 80000):
            self.approved.add(a)

    def swap(self):
        ready = [a for a in self.approved if self.weth.get(a, 0) > 10**14]
        if not ready:
            return self.approve()
        a = random.choice(ready)
        amount = random.randint(10**13, self.weth[a] // 2)
        # exactInputSingle((tokenIn, tokenOut, fee, recipient, amountIn, amountOutMinimum, sqrtPriceLimitX96))
        data = "0x04e45aaf" + word(WETH) + word(USDC) + word(500) + word(a) + word(amount) + word(0) + word(0)
        if self.send("uniswap swap", a, ROUTER, 0, data, 450000):
            self.weth[a] -= amount
            self.usdc.add(a)

    def usdc_transfer(self):
        if not self.usdc:
            return self.swap()
        a, b = random.choice(sorted(self.usdc)), self.pick()
        self.send("usdc transfer", a, USDC, 0, "0xa9059cbb" + word(b) + word(random.randint(1, 20000)), 120000)

    def deploy(self):
        # runtime: PUSH1 n; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN  (answers every call with n)
        runtime = "60%02x60005260206000f3" % random.randint(1, 255)
        initcode = "0x600a600c600039600a6000f3" + runtime
        a = self.pick()
        h = self.send("contract deploy", a, None, 0, initcode, 120000)
        if h:
            self.pending_deploys.append(h)

    def call_contract(self):
        if not self.contracts:
            return self.deploy()
        self.send("contract call", self.pick(), random.choice(self.contracts), 0, "0x" + secrets.token_hex(4), 60000)

    def reverting(self):
        # transfer more WETH than the sender holds: mined, status 0
        a, b = self.pick(), self.pick()
        self.send("reverted tx", a, WETH, 0, "0xa9059cbb" + word(b) + word(10**30), 90000)

    def note(self):
        a = self.pick()
        size = random.randint(8, 180)
        self.send("calldata note", a, a, 0, "0x" + secrets.token_hex(size), 21000 + 16 * size + 2000)

    def delegation(self):
        if not self.keyed or not self.contracts:
            return self.deploy()
        addr, key = random.choice(self.keyed)
        target = "0x0000000000000000000000000000000000000000" if addr in self.delegated and random.random() < 0.4 \
            else random.choice(self.contracts)
        out = subprocess.run(
            ["cast", "send", addr, "--auth", target, "--private-key", key, "--rpc-url", self.url, "--async"],
            capture_output=True, text=True,
        )
        if out.returncode == 0:
            self.sent += 1
            kind = "7702 clear" if int(target, 16) == 0 else "7702 delegation"
            self.by_kind[kind] = self.by_kind.get(kind, 0) + 1
            (self.delegated.discard if int(target, 16) == 0 else self.delegated.add)(addr)
        else:
            self.errors += 1
            self.last_error = "7702: " + out.stderr.strip()[:160]

    KINDS = [
        (native_transfer, 34), (wrap, 11), (weth_transfer, 12), (approve, 5), (swap, 9), (usdc_transfer, 8),
        (deploy, 4), (call_contract, 6), (reverting, 5), (note, 4), (delegation, 2),
    ]

    # ---- main loop

    def collect_deploys(self):
        still = []
        for h in self.pending_deploys:
            try:
                r = self.rpc.call("eth_getTransactionReceipt", [h])
            except Exception:  # noqa: BLE001
                r = None
            if r is None:
                still.append(h)
            elif r.get("contractAddress") and r.get("status") == "0x1":
                self.contracts.append(r["contractAddress"])
        self.pending_deploys = still[-50:]
        self.contracts = self.contracts[-200:]

    def write_stats(self, started):
        try:
            block = int(self.rpc.call("eth_blockNumber"), 16)
        except Exception:  # noqa: BLE001
            block = -1
        elapsed = max(time.time() - started, 1e-9)
        stats = {
            "seconds": round(elapsed, 1), "sent": self.sent, "errors": self.errors,
            "tx_per_second": round(self.sent / elapsed, 2), "block": block,
            "wallets": len(self.wallets), "keyed_wallets": len(self.keyed),
            "noise_contracts": len(self.contracts), "by_kind": dict(sorted(self.by_kind.items())),
            "last_error": self.last_error,
        }
        with open(os.path.join(RUN, "noise.stats"), "w") as f:
            json.dump(stats, f, indent=2)

    def run(self, seconds):
        self.pending_deploys = []
        funcs = [k for k, _ in self.KINDS]
        weights = [w for _, w in self.KINDS]
        started = last_stats = time.time()
        while seconds is None or time.time() - started < seconds:
            # bursty pacing: mostly small ticks, occasionally a quiet gap or a burst
            mood = random.random()
            burst = 0 if mood < 0.08 else (random.randint(8, 20) if mood > 0.94 else random.randint(1, 3))
            for _ in range(burst):
                random.choices(funcs, weights)[0](self)
            now = time.time()
            if now - last_stats > 4:
                self.collect_deploys()
                self.write_stats(started)
                last_stats = now
            # keep the long-run average near the requested rate
            time.sleep(max(0.02, random.expovariate(self.rate / 2.2)))
        self.write_stats(started)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default=os.environ.get("LOCAL_RPC", "http://127.0.0.1:8546"))
    ap.add_argument("--rate", type=float, default=6.0, help="average transactions per second")
    ap.add_argument("--wallets", type=int, default=150)
    ap.add_argument("--keyed", type=int, default=12, help="wallets with keys, used for EIP-7702 traffic")
    ap.add_argument("--seconds", type=float, default=None)
    args = ap.parse_args()
    os.makedirs(RUN, exist_ok=True)
    rpc = Rpc(args.rpc)
    chain = int(rpc.call("eth_chainId"), 16)
    if "anvil" not in rpc.call("web3_clientVersion").lower():
        sys.exit("refusing to run: %s is not an anvil node" % args.rpc)
    print("chain %d, preparing %d wallets..." % (chain, args.wallets), flush=True)
    noise = Noise(rpc, args.rpc, args.wallets, args.keyed, args.rate)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    print("sending", flush=True)
    try:
        noise.run(args.seconds)
    finally:
        print(json.dumps(noise.by_kind), flush=True)


main()
