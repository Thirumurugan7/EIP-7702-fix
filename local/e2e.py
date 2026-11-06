#!/usr/bin/env python3
"""Genuine end-to-end against the DEPLOYED factory on the local chain: every step is a real
transaction mined on the node (not a forge fork). Creates a tenant, configures it, funds the vault
with real USDC (by locating and setting the balanceOf slot via anvil), runs the 2-of-2 lifecycle,
then runs the forged-signature 7702 attack and asserts it is refused on chain.

  LOCAL_RPC=http://127.0.0.1:8546 FACTORY=0x... python3 local/e2e.py
"""
import json, os, subprocess, sys, urllib.request

RPC = os.environ.get("LOCAL_RPC", "http://127.0.0.1:8546")
FACTORY = os.environ["FACTORY"]
USDC = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"
TERMS = "0xc0d0b6034b7971648ff8332f4002119b0b39358ce84d4865a90101fc2220ab80"
TRANSFER_SCRIPT = "0x0102320100601801053201026018010023010061180101230100631801012301002302bad6ccbe8f6bed92553dd18910f79c66afaaa5d196515ba83f48c7fe256ee89a0300000000a9059cbb010221180101ff"
YES_INITCODE = "0x60296000600c600039f3" + ""  # placeholder, replaced below

_id = 0
def rpc(method, params=()):
    global _id; _id += 1
    req = urllib.request.Request(RPC, json.dumps({"jsonrpc":"2.0","id":_id,"method":method,"params":list(params)}).encode(), {"Content-Type":"application/json"})
    out = json.load(urllib.request.urlopen(req, timeout=60))
    if "error" in out: raise RuntimeError("%s: %s" % (method, out["error"]))
    return out["result"]

def cast(*args, check=True):
    r = subprocess.run(["cast", *map(str, args)], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError("cast %s\n%s" % (" ".join(map(str,args)), r.stderr.strip()))
    return r.stdout.strip(), r.returncode

def keccak(s):
    out,_ = cast("keccak", s); return out

def new_wallet(eth="100"):
    w = json.loads(cast("wallet","new","--json")[0])[0]
    rpc("anvil_setBalance", [w["address"], hex(int(float(eth)*10**18))])
    return w["address"], w["private_key"]

def send(key, to, sig, *args, value=0):
    cmd = ["send", to, sig, *map(str,args), "--private-key", key, "--rpc-url", RPC, "--json"]
    if value: cmd += ["--value", str(value)]
    out, rc = cast(*cmd, check=False)
    if rc != 0: return None
    try: return json.loads(out)
    except Exception: return {"status":"0x1"}

def call(to, sig, *args):
    out,_ = cast("call", to, sig, *map(str,args), "--rpc-url", RPC)
    return out

print("chain", int(rpc("eth_chainId"),16), "block", int(rpc("eth_blockNumber"),16))
assert rpc("web3_clientVersion").lower().find("anvil") >= 0, "not anvil"

owner, ownerK = new_wallet()
alice, aliceK = new_wallet()
bob, bobK = new_wallet()
carol, carolK = new_wallet()
attacker, attackerK = new_wallet()
recipient = "0x" + keccak("e2e recipient")[26:]
print("tenant owner", owner)

# ---- create the tenant through the deployed factory (3 real transactions)
salt = keccak("chainwall e2e on-chain")
send(ownerK, FACTORY, "deployInstanceStage1Deterministic(address,uint8,bytes32)", owner, 0, salt)
key = call(FACTORY, "deriveInstanceDeploymentKey(bytes32,address,uint8)(bytes32)", salt, owner, 0)
registry = call(FACTORY, "getRegistryByDeploymentKey(bytes32)(address)", key)
assert int(registry,16) != 0, "registry not recorded"
send(ownerK, FACTORY, "deployInstanceStage1Finalize(address)", registry)
send(ownerK, FACTORY, "deployInstanceStage2(address)", registry)
inst = call(FACTORY, "getInstance(address)((uint256,address,address,address,address,address,uint8,address))", registry)
parts = [p.strip() for p in inst.strip("()").split(",")]
interact, accountFactory = parts[3], parts[5]
print("registry", registry, "interact", interact, "nextInstanceId now", call(FACTORY,"nextInstanceId()(uint256)"))

# ---- configure
TREASURY_GROUP = keccak("treasury"); OPS_GROUP = keccak("ops")
TREASURY_POLICY = keccak("treasury 2-of-2"); OPS_POLICY = keccak("ops 1-of-1")
INTERACTION = keccak("usdc-transfer"); EXECUTOR = keccak("cap.registry.interaction.execute")
send(ownerK, registry, "acceptTerms(bytes32)", TERMS)
for u,uk in [(alice,aliceK),(bob,bobK),(carol,carolK)]: send(ownerK, registry, "addUser(address)", u)
send(ownerK, registry, "createGroup(bytes32)", TREASURY_GROUP)
send(ownerK, registry, "addGroupMember(bytes32,address)", TREASURY_GROUP, alice)
send(ownerK, registry, "addGroupMember(bytes32,address)", TREASURY_GROUP, bob)
send(ownerK, registry, "createGroup(bytes32)", OPS_GROUP)
send(ownerK, registry, "addGroupMember(bytes32,address)", OPS_GROUP, carol)
send(ownerK, registry, "grantCapabilityGroup(bytes32,bytes32)", EXECUTOR, TREASURY_GROUP)
send(ownerK, registry, "grantCapabilityGroup(bytes32,bytes32)", EXECUTOR, OPS_GROUP)
send(ownerK, registry, "createPolicy(bytes32,bytes32[],uint256[])", TREASURY_POLICY, "[%s]"%TREASURY_GROUP, "[2]")
send(ownerK, registry, "createPolicy(bytes32,bytes32[],uint256[])", OPS_POLICY, "[%s]"%OPS_GROUP, "[1]")
send(ownerK, registry, "upsertOrg(string,address,bool,address[])", "circle", owner, "false", "[]")
usdc_version = "0x3100000000000000000000000000000000000000000000000000000000000000"
send(ownerK, registry, "addContractVersion(string,string,(address,bytes32,address),bytes32)", "circle", "usdc",
     "(%s,%s,0x0000000000000000000000000000000000000000)"%(USDC,usdc_version), "0x"+"00"*32)
bhash = call(registry, "getInteractionBundleHash(bytes32)(bytes32)", INTERACTION)
send(ownerK, registry, "upsertInteractionBundle(bytes32,(bytes32,bytes,uint256,(bytes32,bytes)[]))",
     bhash, "(%s,%s,0,[])"%(INTERACTION, TRANSFER_SCRIPT))
vault = call(accountFactory, "computeAccountAddress(bytes32)(address)", keccak("vault 1"))
send(aliceK, accountFactory, "newAccount(bytes32)", keccak("vault 1"))
assert call(registry,"isAccountAllowed(address)(bool)",vault) == "true", "vault not admitted"
print("vault", vault, "allowed")

# ---- fund the vault with real USDC by finding its balanceOf storage slot
want = 1000 * 10**6
found = None
for slot in range(0, 40):
    keyslot,_ = cast("index", "address", "uint256", vault, slot) if False else (None,None)
    ks = keccak("0x"+vault[2:].rjust(64,"0")+hex(slot)[2:].rjust(64,"0"))
    prev = rpc("eth_getStorageAt", [USDC, ks, "latest"])
    rpc("anvil_setStorageAt", [USDC, ks, "0x"+hex(want)[2:].rjust(64,"0")])
    if int(call(USDC,"balanceOf(address)(uint256)",vault).split()[0].replace(",","")) == want:
        found = slot; break
    rpc("anvil_setStorageAt", [USDC, ks, prev])
assert found is not None, "could not locate USDC balance slot"
print("vault USDC funded at slot", found, "=", call(USDC,"balanceOf(address)(uint256)",vault))

# ---- lifecycle: a real 2-of-2 payout
args = "[%d,%d]" % (int(recipient,16), 250*10**6)
deadline = int(rpc("eth_getBlockByNumber",["latest",False])["timestamp"],16) + 86400
ph = call(interact, "getPayloadHash(bytes32,uint256[],bytes32,uint256,uint256,address)(bytes32)", INTERACTION, args, TREASURY_POLICY, deadline, 0, vault)
send(aliceK, interact, "propose(bytes32,bytes32,uint256,uint256,address)", ph, TREASURY_POLICY, deadline, 0, vault)
opid = call(interact, "nextOperationId()(uint256)") if False else "1"
send(bobK, interact, "approveOperation(uint256)", 1)
send(aliceK, interact, "executeFromAccount(uint256,bytes32,uint256[],uint256)", 1, INTERACTION, args, 10000)
rbal = int(call(USDC,"balanceOf(address)(uint256)",recipient).split()[0].replace(",",""))
vbal = int(call(USDC,"balanceOf(address)(uint256)",vault).split()[0].replace(",",""))
print("after payout: recipient", rbal, "vault", vbal)
assert rbal == 250*10**6 and vbal == 750*10**6, "lifecycle payout wrong"

# ---- attack: delegate carol (real 7702 tx) to a yes-contract, attacker forges a signature
yes_runtime = "7f1626ba7e0000000000000000000000000000000000000000000000000000000060005260206000f3"
yes_init = "0x60296000600c6000396000f3"  # wrong length guard; build precisely:
rt = "7f1626ba7e" + "00"*28 + "60005260206000f3"
rtlen = len(rt)//2
yes_init = "0x60" + hex(rtlen)[2:].rjust(2,"0") + "600c60003960" + hex(rtlen)[2:].rjust(2,"0") + "6000f3" + rt
dep = subprocess.run(["cast","send","--private-key",ownerK,"--rpc-url",RPC,"--create",yes_init,"--json"],capture_output=True,text=True)
yes_addr = json.loads(dep.stdout)["contractAddress"]
assert call(yes_addr,"isValidSignature(bytes32,bytes)(bytes4)", "0x"+"11"*32, "0x1234")[:10] == "0x1626ba7e", "yes contract bad"
subprocess.run(["cast","send",carol,"--auth",yes_addr,"--private-key",carolK,"--rpc-url",RPC],capture_output=True,text=True)
code = rpc("eth_getCode",[carol,"latest"])
assert code.lower() == ("0xef0100"+yes_addr[2:]).lower(), "carol not delegated: "+code
print("carol delegated to yes-contract:", code)
r = send(attackerK, interact, "directExecuteFromAccount(address,bytes32,bytes32,uint256[],uint256,uint256,uint256,address,bytes)",
         vault, OPS_POLICY, INTERACTION, "[%d,%d]"%(int(attacker,16),1000*10**6), 10000, 0, deadline, carol, "0xdeadbeef")
drained = int(call(USDC,"balanceOf(address)(uint256)",attacker).split()[0].replace(",",""))
assert r is None, "ATTACK SUCCEEDED: directExecute did not revert on chain"
assert drained == 0, "ATTACK SUCCEEDED: attacker got USDC"
assert int(call(USDC,"balanceOf(address)(uint256)",vault).split()[0].replace(",","")) == 750*10**6, "vault changed"
print("forged-signature attack refused on chain; vault intact")
print("\nEND TO END OK: tenant", registry, "nextInstanceId", call(FACTORY,"nextInstanceId()(uint256)"))
