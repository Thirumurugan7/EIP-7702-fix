# Chainwall as a defense against the EIP-7702 actor-hijack class

Prepared for OKcontract (Henri) and the external auditors. Based on the public repo at commit d24313d,
read in full, patched on branch `feat/eip7702-actor-guard`, and verified on an Arbitrum One fork. This
report describes a live, unaudited finding; keep it internal until the fix ships.

## 1. The attack, and why it is not the ordinary multisig story

On 29 Oct 2026 Binance lost about $6.3B. On Ethereum the mechanism was EIP-7702: the attacker got the
signing service to sign an authorization for the Binance hot wallet, an EOA. The wallet then carried
the attacker's sweeper code, and the funds left without the attacker touching the withdrawal infra again.

EIP-7702 lets an EOA install a delegation designator as its code: exactly 23 bytes, `0xef0100` followed
by a delegate address. From then on every call "from" that EOA runs the delegate's code, and every
signature check against that EOA is answered by the delegate (ERC-1271), not by its key. The account
keeps its private key and its address. One signature turns a key holder into a programmable contract
that the key holder, or whoever coerced that one signature, controls.

Chainwall's own thesis is "your multisig can correctly approve the wrong transaction." EIP-7702 is a
sharper version of the same problem: the account that is supposed to represent a human stops
representing that human, with a valid signature and no code deployment the normal checks would notice.

## 2. What Chainwall already defends, before any change

Chainwall splits an onchain operation into pieces and puts the rules on chain:

- Funds live in a vault: a Safe or an OKAccount. Both are contracts with no private key. They cannot be
  7702-delegated, because 7702 only applies to EOAs. The exact Binance move, hijacking the
  fund-holding wallet, is structurally impossible against a Chainwall vault.
- A vault does nothing on its own. Every movement must be a registered interaction, to registered
  targets, that satisfies a policy and meets an approval threshold, rechecked by the chain at the
  moment of execution.
- A stolen key is still only one actor. Thresholds, group membership and policy programs all hold. We
  proved this: a single hijacked approver cannot pass a 2-of-2 policy.
- Passkey (WebAuthn) accounts have no EOA owner, recovery or admin, so there is no key to delegate, and
  a delegated EOA cannot impersonate one (the factory checks the exact clone codehash).

So Chainwall already removes the primary Binance vector. The funds cannot be swept by delegating the
thing that holds them.

## 3. The gap the patch closes: the actors, not the vault

The vault is safe. The people are not. Users, approvers and admins are ordinary addresses, usually
EOAs. Nothing in the 101 contracts, read line by line, looked for a 7702 delegation (no mention of
`7702` or `ef0100` anywhere in `src`). That left four ways a single delegation turns into control:

1. Forged signatures, forever. Actor signatures are verified with OpenZeppelin `SignatureChecker`
   (`InteractModuleBase.sol:367, 453, 509`), which takes the ERC-1271 path for any signer with code. A
   delegated actor's delegate says "valid" to everything, so one authorization yields unlimited valid
   signatures for that actor with no further access to the key.
2. Acting as the actor directly. On every `msg.sender` path (propose, approve, execute, direct
   execute), the delegate's code can call as the actor.
3. Dormant authority waking up. `hasCapability` treated "has code" as "is a contract"
   (`Capabilities.sol`), so a capability could activate the moment an address gained designator code.
4. A swappable target. The engine accepted any address with code as a call target
   (`MiniScriptEngine.sol:745`), so a registered "contract" could be an EOA whose logic changes with
   one signature.

Verified by execution on the fork, against the bytecode the official Arbitrum factory actually deploys:
after one delegation by a single-actor-policy signer, a party who is not even a Chainwall user drained
the vault with the signature `0xdeadbeef`. This is a real exploit against what is live today. (Mitigating
fact: the official factory has created no tenants yet.)

Severity is bounded by the same thresholds that make Chainwall work: on a 2-of-N policy the attacker
needs N delegated signers. On a single-actor policy, or against a delegated admin, it is full control
of whatever that policy or role allows.

## 4. The defense the patch adds: one rule, enforced where authority is decided

The rule: an address whose code is a 7702 designator holds no authority and does not count as a
contract, unless its delegate is on a per-tenant allowlist that is empty by default and governed by its
own timelock category.

It is enforced at the points where authority is actually decided, not scattered across call sites:

- Caller identity. The registry resolves the caller of every authority check through one helper
  (`actorOrSender`). The rule lives there, so it covers direct calls and timelock replays, every facet,
  roles, ownership and governance, in one place.
- Registry answers. Interact never reads registry storage; it asks "is this a user, a group member, a
  capability holder." Those answers now return false for a delegated actor. That also closes the time
  gap: Interact re-asks at execution, so an approver who delegates after approving stops counting, and
  stored timelock approvals from a since-delegated approver are dropped.
- Signatures. All six signature sites (three actor, three commit-reveal) reject a delegated signer
  before `SignatureChecker` can consult the delegate.
- Roles. `hasRole` reports a delegated admin as not holding the role, to every caller inside and
  outside the registry, while leaving the stored grant intact so the role can still be revoked.
- "Is a contract." The engine target check, contract registration, vault allowlists, implementations,
  engine, Safe singleton and migrator, sync sources and price feeds now reject designator code.
- Grants and deployment. A delegated address cannot be added as a user, group member, capability
  actor, contract, or tenant owner at deployment.

The allowlist is the escape hatch for legitimate smart-wallet users: an admin approves a specific
delegate (pinned to its codehash, behind a delay), and that delegate's accounts work again.

## 5. What it costs, and what it deliberately does not do

- A normal account pays one EXTCODESIZE and no external call per check. Only a 23-byte account is looked
  at further.
- It does not stop an attacker who can sign ordinary transactions with an actor's key. That was always
  one vote; thresholds and policies are the defense there. The patch stops 7702 from making that vote
  permanent, key-free and signature-forging.
- Paying out to a delegated EOA is allowed by default (a recipient gains no authority). A tenant that
  wants to refuse such recipients can, with a one-line policy program using the new `delegateOf` view.

## 6. Proof

Everything below runs on an Arbitrum One fork with the real Safe and EntryPoint contracts.

- The full test suite: 65 tests, green in both the default and the production build.
- Before/after on the same files: with the patch stashed, the four attack tests drain or succeed; with
  it applied, all are refused with exact reverts.
- Against the live deployment: a tenant from the official Arbitrum factory is drained before the patch;
  a tenant from the patched factory refuses the same attacks.
- Fully on chain: on a local node a tenant was created, configured, funded with real USDC, run through
  a real 2-of-2 payout (vault 1000 -> 750 USDC), then the forged-signature attack was broadcast and
  reverted on chain, with a public-looking transaction load running throughout.

## 7. Open items for OKcontract

- The registry deployed on Arbitrum One does not match the public source at this commit (it refuses this
  repo's registry as its successor, and its sizes differ). An in-place upgrade of an existing official
  tenant therefore needs the source of what is actually deployed, which only OKcontract has. The patch
  and its migration path are proven against this repository's own code.
- `RegistryTokensFacet` sits 33 bytes under the 24,576 byte limit after the patch. It is the tightest
  contract in the protocol and should be given headroom before anything else is added.
- This changes audited code and must enter the external audit scope before the December report.
- A deployment is production-usable only as an Official Factory published by OKcontract under the BUSL.

## 8. Findings unrelated to 7702, noted during the full read (for the auditors)

Actor trailer signatures have no nonce or deadline; a policy with all-zero thresholds executes with
zero approvals; `createOperation` is public and skips the vault allowlist check `propose` does;
`withdrawOperation` needs no current user; all 19 timelock categories ship at zero delay; `diamondCut`
needs only ADMIN_ROLE while a registry upgrade needs governor plus UPGRADER_ROLE; `renounceRole` works
while paused; the containment doc marks `getInteractionScript`/`getInteractionFlags` readable while
paused but both revert under the pause modifier. None are caused by the patch.
