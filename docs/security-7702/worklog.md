# Chainwall EIP-7702 work log

Kept outside the repo on purpose: it describes a working exploit against code that is live on Arbitrum One. Do not publish or commit it until the fix is out.

Repo: `~/Desktop/chainwall` (github.com/okcontract/chainwall, commit d24313d "Initial public release").
Branch: `feat/eip7702-actor-guard`. Nothing committed, nothing pushed.

---

## 1. Background

- 29 Oct 2026: Binance lost about $6.3B. On Ethereum the attacker got Binance's signing service to sign EIP-7702 authorizations for the Binance 14 hot wallet (an EOA), 50 in one transaction, one of which matched the nonce. The wallet then ran the attacker's sweeper code, independent of Binance's withdrawal infrastructure. Binance cleared it by delegating to the zero address at 00:10 UTC on 30 Oct.
- Task: make Chainwall prevent this class of attack, by changing the core contracts.

## 2. What was done, in order

### 5 Nov, evening: first read
- Cloned the public repo into the cloud workspace. `grep` for 7702 / `ef0100` in `src`: no matches. Chainwall has no 7702 handling.
- Found the first gap by reading: `InteractModuleBase.sol` lines 367, 453, 509 verify actors with OpenZeppelin `SignatureChecker.isValidSignatureNow` (OZ pinned at 5.3.0). That function uses ECDSA only when `signer.code.length == 0`, otherwise it calls ERC-1271 on the signer. A delegated EOA has 23 bytes of code, so its delegate decides.

### 5 Nov, night: full line-by-line read
- All 101 Solidity files (about 32,700 lines) read in 8 parallel batches, each producing notes with line references and a table of every authority site.
- Notes delivered as `chainwall-full-read-notes.md` (4,680 lines).
- About 190 authority sites recorded (some overlap in shared helpers).

### 5 Nov, 23:45 to 6 Nov, 00:01: clone, build, run
- Cloned to `~/Desktop/chainwall` with all submodules.
- Built with the existing oksolc at `~/dev/oksolc/zig-out/bin/oksolc` (reports `0.8.36+oksolc.0.2.3`; the checkout is 3 commits past the v0.2.3 tag) and foundry 1.5.1. 171 files, success.
- Compared build output with `ProtocolCodehashes.sol`: all 11 pinned contracts match the default-profile constants. (MiniScriptEngine could only be checked after deployment because of constructor immutables: deployed codehash `0xd173247f...08c6` equals `MINISCRIPT_ENGINE_CODEHASH_DEFAULT`.)
- Read the official Arbitrum factory `0x20d2eD7f3d008a70b2aED91CC7F9801Ff14b449b`: its stage 1, stage 2, auth and predictor module codehashes equal the PRODUCTION constants in this commit. The deployed factory is this source.
- The public repo has no tests and no deploy scripts, so a harness was written:
  - `test/ChainwallDeployer.sol`: deploys every facet, implementation, the engine, config, modules, TermsRegistry and OKFactory from `out/` artifacts, then one tenant through stages 1a, 1b and 2.
  - Runs on a fork of Arbitrum One (public RPC). Reason: `WebAuthnEntryPoint.requireCanonical` only accepts chains with a pinned EntryPoint v0.8 codehash; chain 31337 is not one of them.
  - External dependencies are the same addresses the official factory config uses: Safe 1.3.0 singleton `0xd9Db270c...9552`, Safe proxy factory `0xa6B71E26...6AB2`, EntryPoint v0.8 `0x4337084D...F108`.
- `test/E2E.t.sol`, 2 tests, both pass:
  - `test_01_tenantDeployed`: owner holds ADMIN_ROLE, UPGRADER_ROLE and ownership; factory holds nothing; registry unpaused; terms accepted.
  - `test_02_proposeApproveExecute`: 2-of-2 policy on an OKAccount vault moves 250 USDC. Refusals verified with exact reasons: non-user propose ("caller is not a user"), 1 of 2 approvals ("operation not approved by required groups"), changed amount (`OperationHashMismatch`), replay ("operation does not exist").
- Interaction scripts are real compiler output from `~/dev/chainwall-cli-arbitrum/zig-out/bin/miniscript` (CLI 0.3.1): `test/scripts/usdc-transfer.core.ls`, `test/scripts/hook-ping.core.ls`.
- The vault's USDC balance is set with the forge `deal` cheat. Everything else is real fork state.

### 6 Nov, 00:09 to 00:14: step 1 of the patch plan, attack tests
- `test/TenantFixture.sol`: shared setup (alice, bob in a 2-of-2 treasury policy; carol in a single-actor ops policy; funded vault).
- `test/Attack7702.t.sol`: 7 tests. Delegations are real EIP-7702 authorizations signed with the actor's private key (`vm.signAndAttachDelegation`), after which the account's code is exactly `0xef0100 || delegate` (23 bytes).
- Result on unpatched code: 9 tests total, 6 pass, 3 fail. The 3 failures are the attacks succeeding.

| Test | Result on unpatched code |
|---|---|
| `test_attack_forgedSignatureAfterDelegation` | FAIL (attack works). After one delegation by carol, a non-user sends `directExecuteFromAccount` with signature `0xdeadbeef`. Accepted. Vault 1,000 USDC to 0. |
| `test_attack_delegateCodeActsAsMsgSender` | FAIL (attack works). Attacker drives carol's address through the delegate: `propose` then `executeFromAccount`. 1,000 USDC to the attacker. |
| `test_attack_delegatedEOAAcceptedAsTarget` | FAIL (attack works). A delegated EOA registered as a contract is called by the vault. |
| `test_control_forgedSignatureRejectedForPlainEOA` | PASS. Same garbage signature reverts `InvalidActorSignature` when carol is a plain EOA. |
| `test_control_oneDelegatedApproverCannotMeetThreshold` | PASS. One delegated approver cannot pass a 2-of-2 policy. |
| `test_control_targetWithoutCodeRefused` | PASS. The engine refuses a target with no code. |
| `test_control_directActorGrantsLockedAfterDeployment` | PASS. `grantCapabilityActor` reverts `ActorGrantsLocked` on a factory tenant. |

## 3. Findings

### 3.1 EIP-7702, proven by execution
1. Forged actor signatures. One delegation by an actor makes every "signature" for that actor valid, forever, with no further access to the key. Sites: `InteractModuleBase.sol:367` (trailer), `:453` (direct execute, Safe mode), `:509` (direct execute, account mode).
2. Delegate code acts as the actor on every `msg.sender` path: propose, approve, withdraw, unsigned account-mode execute, unsigned direct execute.
3. A delegated EOA passes the engine's "target has code" check (`MiniScriptEngine.sol:745`) and is called as a contract.

### 3.2 EIP-7702, from reading (not yet executed)
4. The 3 registry commit-reveal signature checks use the same `SignatureChecker`: `RegistryContractsFacet.sol:591`, `RegistryTokenCommitsFacet.sol:320`, `RegistryInteractionsFacet.sol:627`. A delegated committer's delegate decides; a third party who knows the preimage and salt could publish a private script.
5. Execute recounts approvals against live group membership only. An approver who delegates after approving still counts.
6. No registry authority check looks at code: roles, owner, org and group membership, timelock queue / approve / cancel. All go through `ExecutionContextLib.actorOrSender()` (`TimelockLib.sol:110`).
7. `CapabilitiesLib.hasCapability` and `hasDirectActorCapability` (`Capabilities.sol:157`, `:178`) treat `code.length != 0` as "is a contract".
8. Other "has code" checks a delegated EOA passes: `MiniScriptABIEncoder.sol:148`, `:812`; `MiniScriptAnalyzer.sol:119`, `:445`; vault allowlists; upgrade and release checks (implementation, engine, Safe singleton, migrator); sync sources; price feeds; `TermsRegistry.sol:52`.
9. Contract registration validates nothing about code: a contract version only needs a nonzero address.
10. The tenant owner is only checked for nonzero at deployment (`OKFactoryStage1Module.sol:94`).

### 3.3 What Chainwall already prevents
- The vault itself (Safe or OKAccount) is a contract with no key and cannot be 7702-delegated. The Binance attack on the fund-holding wallet is impossible.
- One hijacked actor is one vote. Thresholds hold (control test passes).
- Passkey accounts: no EOA holds authority inside them; a delegated EOA cannot pose as one (exact clone codehash check).
- Codehash pins cannot be matched by a designator.

### 3.4 Not 7702, found during the read (for Henri and the auditors)
- Actor trailer signature (Safe queued path) has no nonce or deadline and does not bind interaction id, args or `maxSteps`.
- A policy with empty or all-zero thresholds executes with zero approvals.
- `createOperation` is public and skips the vault allowlist check that `propose` does.
- `withdrawOperation` does not require a current user.
- All 19 timelock categories default to zero delay, including config and diamond.
- `diamondCut` needs only ADMIN_ROLE; a registry upgrade needs governor plus UPGRADER_ROLE.
- `enforceOrQueueWithMinimum` has no caller; the protocol minimum delay is unused.
- `setCategoryConfig` has no cap on the minimum delay.
- The original queuer of a timelock action keeps the cancel right forever.
- `grantCapabilityActor`'s contract-required check is dead code.
- After `lockCapabilityActors`, direct actors cannot be revoked.
- `renounceRole` works while paused; a last admin renouncing during a pause leaves no way to unpause (from reading).
- `OKFactoryConfig` is not codehash-pinned yet briefly holds ADMIN_ROLE on every tenant registry.
- A deployment that fails midway has no recovery path.
- `doc/registry-containment.json` marks `getInteractionScript` / `getInteractionFlags` as readable while paused, but both carry `whenNotPausedD` and revert.
- Engine direct-call guard (`MiniScriptEngine.sol:539`) compares against a caller-supplied engine address. Possible bypass flagged by the read; line confirmed, full path NOT traced.
- Native transfer recipient in MiniScript is any stack address, and a failed transfer pushes 0 instead of reverting.
- Several stale comments (constructor arity in the config doc, "20 storage records" vs 19 categories).

## 4. Corrections to earlier statements
- `ProtocolCodehashes.sol` holds 22 constants (11 contracts, two profiles), not 36.
- Registry storage slots are plain `keccak256("okc.storage.*")`, not the ERC-7201 formula.
- A registry pause does halt vault execution (the interaction reads revert), even though one batch of the read said otherwise.
- "A dormant direct capability on an EOA can be activated by delegating": not reachable on a factory-deployed tenant, because the factory locks direct actor grants during deployment. The check is still wrong in principle.
- Contract registration has no code check today, so rejecting designators there is a new check.

## 5. Not verified
- Safe library internals and EntryPoint v0.8 internals beyond what the tests exercise.
- Safe vault path (guard and module), passkey flows, private commit and reveal, timelock flows: not exercised by tests yet.
- The internal OKcontract test suite: not available here.
- Production-profile build and the full pin regeneration cascade.

## 6. Patch plan and status

Rule: an address whose code is a 7702 designator has no authority and does not count as a contract, unless its delegate is on a registry allowlist (empty by default, behind its own timelock category).

| Step | Status |
|---|---|
| 1. Attack tests | DONE (3 attacks proven, 4 controls) |
| 2. Detection library | DONE |
| 3. Registry allowlist and shared check | DONE (delay test added; pause table entries and production size check go with step 7) |
| 4. Registry enforcement | DONE, gaps closed and tested |
| 5. Interact enforcement | DONE |
| 6. "Is a contract" checks | DONE |
| 7. Pins and redeployment | DONE (both profiles; in-place upgrade path built and tested; deploy script dry-run) |
| 8. Proof and report | pending |

Open decisions (recommendations in brackets): delegated signer handling [reject outright]; include the MiniScript engine checks [yes]; add a Safe-mode test [yes], passkey flows [later].

## 7. How to run
```sh
cd ~/Desktop/chainwall
FOUNDRY_SOLC=$HOME/dev/oksolc/zig-out/bin/oksolc forge test -vv
```

## 8. Log of later work

### 6 Nov, 00:14 to 00:40: steps 2 and 3

Step 2, detection library
- New `src/Delegation7702.sol`: `delegateOf(address)`, `isDelegated(address)`, `hasContractCode(address)`.
  A designator is recognised as code of exactly 23 bytes starting with `0xef0100`. EIP-3541 forbids deploying contract code starting with `0xef`, so this cannot be a real contract.
- Tests (`test/Delegation7702.t.sol`, all pass): plain EOA, delegated EOA, re-delegation follows the latest delegate, real contracts (including USDC, Interact and the registry on the fork), and a 23-byte contract that is not a designator.

Step 3, registry allowlist
- New `src/registry/DelegationGuard.sol`:
  - `DelegateAllowlistStorage` at slot `keccak256("okc.storage.delegate_allowlist")`: a set of approved delegates plus the runtime codehash pinned at approval.
  - `DelegationGuard`: `isDelegateAllowed`, `isActorUsable`, `requireActorUsable`, error `ActorDelegated(actor, delegate)`.
- `RegistryUsersFacet` gained 7 functions: `allowDelegate`, `disallowDelegate`, `isDelegateAllowed`, `getAllowedDelegateCount`, `getAllowedDelegateAt`, `delegateOf`, `isActorUsable`. Writes are ADMIN_ROLE only and go through the new timelock category.
- `TimelockLib`: new `CATEGORY_DELEGATE = keccak256("timelock.category.delegate")`, accessor, and added to `isProtocolCategory`.
- `Selectors.users()`: 23 to 30 selectors. No existing selector or signature changed.
- Tests (all pass): views track delegation; allowlist starts empty; only admin can approve; zero address, EOAs and delegated EOAs are rejected as delegates; approve and remove; approval is per delegate; a code change at an approved address revokes the approval.

Deviations from the plan, and why
- The allowlist lives in the existing users facet, not a new facet. A new facet would change the `OKFactoryConfig` constructor and the factory wiring for no security gain.
- The new selectors were NOT added to the pause containment table. Effect: they are blocked while the registry is paused (fail closed). Adding them would change the pause module's codehash; that is deferred to the pin step, and `doc/registry-containment.json` still needs the 7 new entries.
- Allowlist changes do not bump the execution semantics revision. To be reviewed in step 5.

Tooling added
- `test/tools/PinReport.t.sol` and `test/tools/update-pins.py`: measure the 11 pinned codehashes for the active profile and rewrite `ProtocolCodehashes.sol` until stable. Run after steps 2 and 3: "round 1: stable", meaning none of the 11 pinned contracts changed bytecode yet.

Test status after steps 2 and 3: 20 tests, 17 pass, 3 fail. The 3 failures are still the three attack tests, as expected: nothing enforces the rule yet. Enforcement is steps 4 to 6.

Still open from step 3
- A test with a real delay configured on the delegate category (approval queues, then executes).
- Contract size check of the users facet under the production profile.

### 6 Nov, 00:28 to 01:05: steps 4 and 5 (enforcement)

Design decision
- The Registry already resolves the caller of every authority check through one helper, `ExecutionContextLib.actorOrSender()` (`TimelockLib.sol`). It is used by the diamond's `_msgSender()`, the pause module's `_msgSender()`, `FacetGuard._msgSenderD()` (all facets), `GroupGovernanceLib` and the timelock internals. The rule is enforced there, so it covers direct calls and timelock replays (where the actor is the stored queuer) without touching each facet.
- Interact never looks at registry storage; it asks the Registry `isUser`, `isGroupMemberByHash` and `hasCapability`. Those three answers now apply the rule, which also fixes the approval recount at execute, because Interact re-reads membership live.
- `hasRole` was left reporting stored grants. Making it delegation-aware would break OpenZeppelin's grant and revoke logic (a delegated admin's role could no longer be revoked). Role holders are stopped at the caller helper instead.

Step 4, registry (files changed)
- `src/registry/TimelockLib.sol`: `actorOrSender()` reverts `ActorDelegated` for an unusable actor. Stored timelock approvals count only for approvers who are still members AND usable (`compactGroupApprovers`, `liveGroupCount`, the approval eligibility check and the approval status view).
- `src/registry/facets/RegistryUsersFacet.sol`: `isUser` and `isGroupMemberByHash` return false for an unusable actor. `addUser` and `addGroupMember` (both the pre-check and the post-timelock re-check) reject an unusable account.
- `src/registry/Capabilities.sol`: `hasCapability` returns false for an unusable actor on the group path; direct actors and `hasDirectActorCapability` now require real contract code (`Delegation7702.hasContractCode`).
- `RegistryContractsFacet`, `RegistryTokenCommitsFacet`, `RegistryInteractionsFacet`: the commit-reveal signature check rejects a delegated committer before `SignatureChecker` runs.
- `src/OKFactoryStage1Module.sol` + `OKFactoryErrors.sol`: a delegated tenant owner is rejected at deployment with `OwnerDelegated(owner, delegate)`.
- `src/WebAuthnAuthAccountFactory.sol`: the two admin checks that read `hasRole(ADMIN_ROLE, msg.sender)` also require `isActorUsable(msg.sender)`.

Step 5, Interact (files changed)
- `packages/interfaces/src/IAccessRegistry.sol`: added `isActorUsable`.
- `src/InteractErrors.sol`: new error `ActorDelegated(actor, delegate)`.
- `src/AppEx.sol`: `_requireActorUsable(actor)`, called first in `_onlyUser()` (propose, approve, every execute and direct execute path, for the resolved or claimed actor) and in `withdrawOperation`. Cost for a normal account: one EXTCODESIZE, no external call.
- `src/InteractModuleBase.sol`: the same check directly before each of the 3 `SignatureChecker` calls.

Codehash pins
- `update-pins.py`, default profile: round 1 changed 4 constants (`CANONICAL_STAGE1_MODULE`, `INTERACT_OPS_MODULE`, `REGISTRY_PAUSE_MODULE`, `REGISTRY_TIMELOCK_EXECUTION_MODULE`), round 2 stable. Production-profile constants are NOT regenerated yet.

Finding from running on real Arbitrum state
- The first run after the patch failed in test setup with `ActorDelegated(0x328809Bc894f92807417D2dAD6b7C998c1aFdac6, 0x468d6fb7f616659b72E9db05Ac7a1C8238D20905)`. That address is forge's well-known "alice" test key. On Arbitrum One it really carries an EIP-7702 delegation: `cast code` returns `0xef0100468d6fb7f616659b72e9db05ac7a1c8238d20905`. So the guard correctly refused a delegation that exists on mainnet today, and it shows publicly known keys are being delegated in the wild.
- Consequence for the earlier runs: in the pre-patch end to end test, "alice" was already a delegated EOA on the fork. It did not change those results (her calls were made directly from her address), but the fixture now uses its own labels (`chainwall-test ...`) and asserts every test account has no code before use.

Tests added: `test/Guard7702.t.sol` (9 tests, all pass)
| Test | Proves |
|---|---|
| `test_interact_forgedSignatureRevertsActorDelegated` | forged signature now reverts with exactly `ActorDelegated(carol, delegate)` |
| `test_interact_delegatedSenderCannotPropose` | delegate code cannot propose as the actor |
| `test_interact_approvalDroppedWhenApproverDelegatesBeforeExecute` | bob approves, then delegates: execute refuses. bob clears the delegation: the same operation executes |
| `test_interact_delegatedSubmitterCannotWithdraw` | withdraw path |
| `test_interact_approvedDelegateMayAct` | once the admin approves the delegate, the delegated actor can propose and execute |
| `test_registry_predicatesFollowDelegation` | `isUser`, `isGroupMemberByHash`, `hasCapability` go false on delegation and true again when cleared |
| `test_registry_delegatedAdminCannotAct` | a delegated admin cannot govern, through the delegate or directly; works again once cleared |
| `test_registry_cannotGrantToDelegatedAccount` | `addUser` and `addGroupMember` reject delegated accounts |
| `test_factory_rejectsDelegatedTenantOwner` | `OwnerDelegated` at stage 1 |

Test status after steps 4 and 5: 29 tests, 28 pass, 1 fail.
- `test_attack_forgedSignatureAfterDelegation`: now PASS (attack refused, vault still 1,000 USDC).
- `test_attack_delegateCodeActsAsMsgSender`: now PASS (propose refused).
- `test_attack_delegatedEOAAcceptedAsTarget`: still FAIL. That is step 6.

Patched but not yet covered by a test (to add in step 8)
- Timelock: a queued action whose queuer delegates before execution; stored timelock approvals from an approver who delegates.
- The 3 commit-reveal signature sites.
- The WebAuthn factory admin checks (the test tenant is deployed without the passkey module).

Known limits of what is built so far
- `hasRole` still returns true for a delegated role holder (it reports the stored grant). Any external contract that trusts `hasRole` alone must also ask `isActorUsable`. In this repo only the WebAuthn factory did, and it is patched.
- Allowlist changes do not bump the execution semantics revision.
- A delegated-unapproved EOA can no longer call any Registry function that resolves its caller, including permissionless ones (for example executing someone else's ready timelock action). Intended, but a behavior change.

### 6 Nov, 00:39 to 01:25: closing the gaps left after steps 4 and 5

Gap 1: `hasRole` reported the stored grant for a delegated admin. FIXED.
- `src/RegistryDiamond.sol`: `hasRole(role, account)` now returns the stored grant AND `isActorUsable(account)`. Every consumer, inside and outside the registry, sees a delegated admin as not an admin.
- To keep revocation working, grant and revoke bookkeeping now read the stored grant directly through the existing `RegistryRoleStorage` library: new `_hasStoredRole`, and overrides of `_grantRole` / `_revokeRole` with the same effects and events as OpenZeppelin's. The "previous owner must not retain a role" handover check and the security-bindings hash also use the stored grant.
- The extra `isActorUsable` condition added to `WebAuthnAuthAccountFactory.sol` in step 4 became redundant and was reverted. That file is back to the original.
- Tests: `test_roles_hasRoleFollowsDelegation`; `test_roles_delegatedAdminCanBeRevoked` (a second admin is granted through role governance, delegates, is revoked by a REVOKE_ADMIN holder, clears the delegation, and is still not an admin).

Gap 2: sites patched but untested. NOW TESTED (`test/Gaps7702.t.sol`, 14 tests, all pass).
| Test | Proves |
|---|---|
| `test_timelock_queuerDelegatesBeforeExecution` | 1 hour delay on the user category; admin queues `addUser`, then delegates. Execution by a third party reverts `ActorDelegated(admin, delegate)`. After clearing, it executes. |
| `test_timelock_approverDelegatesBeforeExecution` | category reviewed by the 2-of-2 policy; alice and bob approve; bob delegates. Execution reverts `TimelockApprovalsStale(actionId, policy)`. After clearing, it executes. |
| `test_timelock_delegatedMemberCannotApprove` | a delegated member cannot approve a timelock action |
| `test_timelock_delegateApprovalIsDelayed` | 2 day delay on the new delegate category: `allowDelegate` queues, early execution reverts `TimelockActionNotReady`, and it applies after the delay |
| `test_reveal_contract_realSignatureWorks` | control: a real ECDSA signature from the committer lets a relayer reveal |
| `test_reveal_contract_garbageSignatureRejected` | control: garbage signature, plain committer: `RevealSignatureInvalid` |
| `test_reveal_contract_delegatedCommitterRefused` | committer (an org owner, not an admin) delegates: `ActorDelegated(committer, delegate)` |
| `test_reveal_token_garbageSignatureRejected` / `..._delegatedCommitterRefused` | same pair for private token commits |
| `test_reveal_interaction_garbageSignatureRejected` / `..._delegatedCommitterRefused` | private interaction commits. The delegated committer is refused with `CommitterNoLongerAuthorized`, one check earlier than the signature site, because her write authority comes from a capability and capabilities now follow the rule. |
| `test_passkeyFactory_delegatedAdminRefused` | a second tenant is deployed WITH the passkey module (flag 2). A plain admin passes the factory's admin check; once delegated, `NotAuthManager(admin)`. |

Honest note on the interaction reveal: the guard line directly before `SignatureChecker` in `RegistryInteractionsFacet` is not reached by any test, because every way to hold interaction write authority (admin role, REGISTRY_MANAGER, INTERACTION_AUTHOR) is already delegation-aware. It stays as a second line of defence.

Gap 3: "a delegated, unapproved EOA cannot call any Registry function that resolves its caller". Not changed, by design.
- This is the mechanism, not a side effect: the rule is enforced where the caller is resolved. Narrowing it to "authority only" would mean patching about 100 individual checks and would reopen the risk of missing one.
- What it costs: a delegated EOA cannot trigger permissionless functions such as executing someone else's ready timelock action. Anyone else still can (the timelock tests execute as a third party).
- The way out for a legitimate smart-wallet user is the allowlist: an admin approves the delegate.

Codehash pins after this round: `update-pins.py` reports stable (RegistryDiamond is not a pinned contract).

Test status: 43 tests, 42 pass, 1 fail. The one failure is still `test_attack_delegatedEOAAcceptedAsTarget`, which is step 6.

Remaining known limits
- Allowlist changes do not bump the execution semantics revision.
- Org owner / member authority (`OrgsStorage.hasCatalogAuthority`) is still a raw storage answer when asked about a third party. It is only consulted for the caller (blocked by the caller helper) and for a commit's committer (blocked at the signature sites, tested above).
- Production-profile pins not regenerated; the 7 new selectors are not in the pause containment table or `doc/registry-containment.json`.

### 6 Nov, 00:48 to 01:50: step 6, "is a contract" checks

What changed
- MiniScript engine (`src/MiniScriptEngine.sol`, `resolveTarget`): new Yul helper `hasOwnCode`. A target with exactly 23 bytes of code starting with `0xef0100` is refused with the same error as a target with no code (ERR_02). The helper saves and restores the scratch word it uses, so the interpreter's memory is untouched.
- Contract directory: `RegistryContractsFacet._recordContractVersionCore` and the sync import path (`RegistrySyncFacet.importContract`) reject an address or implementation that is a delegated EOA, with the new error `ContractAddressDelegated(address)`. Registration still accepts an address with no code yet, as before.
- Everywhere else: 86 uses of `X.code.length == 0` / `!= 0` across 36 files were replaced by `Delegation7702.hasContractCode(X)`. This covers implementations, the engine and its two children, the Safe singleton, proxy factory, migrator and configurator, vault allowlists, sync sources, price feeds and the sequencer feed, the passkey contracts, diamond facets, the timelock policy runner, the terms registry and the factory config.
- Deliberately NOT changed (4 sites, because they are not "is this a contract" questions): the passkey factory's "address already occupied" and "account not yet deployed" checks, the Safe proxy runtime probe, and the two places that read the length of stored governance data.

Codehash pins (default profile): 3 rounds to converge.
- Round 1: stage 1 module, stage 2 module, Interact ops module, timelock execution module, engine, analyzer, encoder.
- Round 2: stage 1 module, Interact ops module, timelock execution module (they embed the engine pins).
- Round 3: stable.
This matches the cascade predicted from reading: an engine change moves the modules that pin it.

Tests
- `test_attack_delegatedEOAAcceptedAsTarget` was rewritten to the realistic case: the address is registered while it is a plain EOA, delegates afterwards, and the vault is asked to call it. Now refused by the engine.
- New `test_attack_delegatedEOARegisteredAsContract`: registering an already delegated EOA reverts `ContractAddressDelegated`.

Before / after proof on the final test file
- The source changes were stashed and the attack suite was run against the ORIGINAL contracts: 4 attack tests fail (attacks succeed), 4 controls pass.
  - forged signature: vault drained (1,000 USDC to the attacker)
  - delegate code as msg.sender: vault drained
  - delegated EOA accepted as a target
  - delegated EOA registered as a contract
- With the patch restored: all 8 pass.

Test status after step 6: 44 tests, 44 pass, 0 fail.

Limits of step 6
- The 86 mechanical replacements are covered by the full suite as a regression (the stack still deploys and runs), but only the engine target check and contract registration have a dedicated 7702 test. Vault allowlists, price feeds, upgrade and release targets and sync sources have no dedicated test yet.
- A native transfer from a script can still send value to a delegated EOA. That is a recipient, not a call target, and is unchanged.
- Bytecode grew in many contracts. Sizes under the production profile are not checked yet (step 7).

### 6 Nov, 00:57 to 02:20: fixing the limits left after step 6

Limit A: contract sizes under the production build. A REAL PROBLEM WAS FOUND AND FIXED.
- First production build (`FOUNDRY_PROFILE=production forge build --sizes`): `RegistryTokensFacet` was 24,936 bytes, 360 over the 24,576 byte EIP-170 limit. It could not have been deployed.
- Context: the tokens facet deployed by the official Arbitrum factory is 24,479 bytes, so the original code only had 97 bytes of headroom. Any shared-library growth lands in it.
- What was changed to get under the limit:
  1. The full rule now lives in one place. `src/registry/DelegationGuard.sol` has two libraries: `DelegationRules` (complete logic: read the designator, check the allowlist and pinned codehash, revert `ActorDelegated`) is compiled only into `RegistryUsersFacet`; `DelegationGuard` is a thin entry used everywhere else. The thin guard does one EXTCODESIZE; only for an account with exactly 23 bytes of code does it STATICCALL the Registry's own `isActorUsable` / `requireActorUsable` (new external view on the users facet, selector list 30 to 31). If that call cannot be answered, the account is treated as not usable (fail closed).
  2. `CapabilitiesLib` no longer carries the rule for group-held capabilities. Callers are covered by `actorOrSender()`; third-party questions are covered in the external view `RegistryCapabilitiesFacet.hasCapability`, which is what Interact and the factories call. Direct actors use `code.length > 23` instead of `hasContractCode` (same effect for system actors, zero extra bytes).
  3. Price feed checks use `code.length <= 23` (a feed must have more code than a designator) in `PriceModule`, `RegistryTokensFacet`, `RegistryTokenCommitsFacet` and the sync feed check. Zero extra bytes.
  4. `CATEGORY_DELEGATE` was removed from `isProtocolCategory`. It has no code-defined default any more: `allowDelegate` / `disallowDelegate` revert `TimelockCategoryNotConfigured` until governance calls `setCategoryConfig` for that category. This saves bytes in every facet and makes accepting delegates an explicit opt-in with an explicit delay.
  5. `Delegation7702.hasContractCode` rewritten in assembly (one EXTCODESIZE).
- Result, production profile, smallest margins:
  | contract | runtime bytes | margin |
  |---|---|---|
  | RegistryTokensFacet | 24,543 | 33 |
  | RegistryInteractionsFacet | 23,730 | 846 |
  | RegistryDiamond | 23,393 | 1,183 |
  | RegistryContractsFacet | 23,367 | 1,209 |
  | MiniScriptEngine | 23,247 | 1,329 |
  | RegistryTimelockUpgradeFacet | 23,093 | 1,483 |
  Every contract is under the limit. The tokens facet margin went from 97 to 33 bytes: it deploys, but it is the tightest contract in the protocol and should be raised with Henri.
- Tooling: `test/tools/sizes.py` prints production sizes, smallest margin first.
- Default-profile pins re-converged in 3 rounds after these changes.

Consequences of the restructuring (behavior, not bugs)
- Approving a delegate now needs the delegate timelock category to be configured first (new test `test_registry_allowDelegateNeedsCategoryConfig`).
- The interaction reveal test now reaches the guard directly before `SignatureChecker` and reverts `ActorDelegated(committer, delegate)`. The line that no test reached before is now covered.
- While the Registry is paused, the two views the thin guard calls are blocked (they are not in the pause table yet), so an actor with a 23-byte code is refused during a pause even if its delegate is approved. Plain EOAs and contracts are unaffected. To be settled in step 7 with the pause table.

Limit B: converted "is a contract" sites without a dedicated test. NOW TESTED (`test/Contractness7702.t.sol`, 6 tests, all pass). In each test the delegated EOA points at genuine code of the expected kind, so only the contract-code check stops it.
| Test | Proves |
|---|---|
| `test_feed_realContractAccepted` | control: a real contract with the right `decimals()` is accepted as a token price feed |
| `test_feed_delegatedEOARefused` | an EOA delegated to that same feed code answers `decimals()` correctly and is still refused: `TokenFeedInvalid` |
| `test_syncSource_delegatedEOARefused` | `SourceRegistryNotContract` |
| `test_authFactory_delegatedEOARefused` | `AuthAccountFactoryNotDeployed(eoa)` |
| `test_upgrade_delegatedEOARefusedAsImplementation` | an EOA delegated to the GENUINE Registry implementation is refused as an upgrade implementation: `UpgradeImplementationInvalid(eoa)` |
| `test_release_delegatedEOARefusedAsTarget` | `ReleaseTargetInvalid(eoa)` |
Still without a dedicated test, and why: vault allowlists (only the tenant's own factories can add a vault, and they only add contracts they deployed), the Safe singleton / proxy factory / migrator / configurator checks and the passkey account wiring (all followed by codehash pins or component checks that a designator cannot satisfy), and the direct capability actor rule (not reachable on a factory tenant, see section 4).

Limit C: paying out to a delegated EOA. Checked; handled as an opt-in policy, not a protocol rule.
- Reasoning: a recipient gets no authority over the vault, and a contract recipient can already run code on receipt, so a delegated recipient adds no new power. Refusing them in the engine would also break payouts to people who use 7702 smart wallets. So the engine is unchanged.
- What a tenant can do: the patch added a Registry view `delegateOf(address)`. A policy program can read it, the same way the bundled policy templates read the Registry. New script `test/scripts/recipient-not-delegated.core.ls`, compiled with the CLI's `miniscript`:
  `let recipient = $subjectArg(0) in $require($read(REGISTRY, delegateOf(address), {recipient}) == 0)`
- Tests (`test/Recipient7702.t.sol`, 2 tests, pass): by default a delegated EOA can be paid; with the program attached to the policy, a plain recipient is paid, a delegated recipient is refused, and the same recipient is paid again after clearing the delegation.
- This is a candidate for an eighth bundled policy template in the CLI repo. Not added there; that repo was not touched.

Test status: 53 tests, 53 pass, 0 fail.

### 6 Nov, 01:24 to 02:45: step 7, pause table, production pins, both-profile verification

Pause containment
- `doc/registry-containment.json`: 8 entries added for the new users-facet functions (374 to 382 selectors). The 6 views (`isDelegateAllowed`, `getAllowedDelegateCount`, `getAllowedDelegateAt`, `delegateOf`, `isActorUsable`, `requireActorUsable`) are `read`; `allowDelegate` and `disallowDelegate` are `blocked`.
- `src/registry/RegistryContainmentSelectors.sol`: packed table regenerated from the JSON, 251 to 257 records.
- New tool `test/tools/containment.py`: `check` recomputes every selector from its signature and verifies the packed table equals the JSON; `write` regenerates the table. Check result: "ok: 382 selectors, 257 callable while paused".
- Effect: the thin guard keeps working during a pause, so an actor with an approved delegate is no longer refused while paused.
- Tests (`test/Pause7702.t.sol`, 3, pass): views readable and allowlist writes blocked while paused; an admin with an approved delegate can pause and unpause; an admin with an unapproved delegate cannot unpause until the delegation is cleared.

Codehash pins, both profiles
- New `test/tools/update-all-pins.sh`: runs `update-pins.py` for the default and the production profile in turn until neither changes (each profile's constants are compiled into the other's pinned contracts).
- Converged in 3 passes: "both profiles stable".
- 20 of the 22 constants in `src/ProtocolCodehashes.sol` changed. Unchanged: the predictor (default and production), which this patch does not touch.

Verification in both builds
- Default profile: 56 tests, 56 pass.
- Production profile (`FOUNDRY_PROFILE=production forge test`): 56 tests, 56 pass. The whole stack deploys from production-sized contracts and every pinned check accepts the regenerated production constants.
- Production sizes after the pause table change: unchanged ranking, `RegistryTokensFacet` 24,543 bytes (33 byte margin), everything else at least 846 bytes under the limit.

Not done in step 7
- Deployment to a real network. Everything runs on a local fork of Arbitrum One.
- An upgrade path for tenants that already exist on the official factory. They would need a governed facet cut (users, capabilities, contracts, interactions, tokens, token commits, sync, timelock facets and more), an Interact upgrade, an engine replacement and a new Registry implementation, each through their own timelock. None of that sequence is written or tested.
- The new factory family would need publishing as an Official Factory under the BUSL terms. That is OKcontract's decision.

State of the repo
- Branch `feat/eip7702-actor-guard`, nothing committed or pushed.
- 52 tracked files changed (514 insertions, 123 deletions), plus new files: `src/Delegation7702.sol`, `src/registry/DelegationGuard.sol`, and everything under `test/`.

### 6 Nov, 01:30 to 03:10: the three items left open after step 7

Note on how this section came about. When this round started, the repo already held files I had no record of writing: `test/Migration7702.t.sol`, `script/DeployFactoryFamily.s.sol`, `test/tools/build-original.sh`, an `out-orig/` build directory, and edits to `.gitignore`, `foundry.toml` and `test/ChainwallDeployer.sol`, all timestamped 01:43 to 01:53. They come from an earlier run of this same task that was cut off before it reported. I read every one of them, independently reproduced their two main findings before I noticed them, removed my own duplicate test, and re-ran everything. What follows is verified in this run.

Item 1: upgrade path for an existing tenant. BUILT AND TESTED (within this repository's code).
- `test/tools/build-original.sh` compiles the unpatched base commit into `out-orig/` (it stashes `src`, `packages` and `doc`, builds, and restores them). `foundry.toml` gained one test-only line granting forge read access to `out-orig`; `.gitignore` ignores `out-orig/`, `cache-orig/` and `test.log`. Neither changes any bytecode.
- `test/Migration7702.t.sol`, contract `Migration7702Test`: a tenant is deployed and configured from the UNPATCHED build (original code, original pins), then upgraded in place to the patched build through its own governance only. Nothing is written to storage directly. The sequence, all sent by the tenant admin:
  A. One governed diamond cut per facet (21 cuts): routed selectors replaced, the 8 new selectors added. The users facet goes first because every other patched component calls its two views.
  B. `upgradeRegistry` to the patched Registry implementation.
  C. `upgradeMiniScript`, `upgradeInteract`, `upgradeAccountFactory`, `upgradeOkAccount` (the existing vault), `upgradeSafeFactory`, `upgradeOkGuard`, `upgradeOkModule`.
  D. `replaceEngine` on the policy host, the account factory and the existing vault, then a new timelock policy runner bound to the new engine.
- One constraint found: a SafeFactory's security bindings include the codehash of its component factory, so the patched SafeFactory implementation used for an upgrade must be built against the component factory the tenant already has.
- Tests (3, pass in both profiles):
  - `test_migration_00_unpatchedTenantIsVulnerable`: before the upgrade the forged-signature attack drains the vault.
  - `test_migration_01_upgradeInPlaceThenAttackRefused`: after the upgrade every component points at patched code, tenant state survived (owner, users, group membership, capability, vault allowlist, vault balance), and the same attack is refused.
  - `test_migration_02_normalOperationAfterUpgrade`: a 2-of-2 payout on the pre-existing vault works.
- Limits: the test upgrades one vault and a tenant without passkey accounts. A real tenant repeats step C/D for every OKAccount, migrates its Safes, and upgrades passkey components if it has them. With real timelock delays each step queues and waits; every upgrade also marks all other queued actions stale.

Item 2: the deployment that is live on Arbitrum One. TESTED, WITH TWO FINDINGS.
- `OfficialDeployment7702Test` creates a tenant through the official factory `0x20d2eD7f3d008a70b2aED91CC7F9801Ff14b449b`, so it runs the bytecode that is actually deployed.
- Finding A, `test_official_tenantIsVulnerable` (pass): on that deployed bytecode, after one EIP-7702 delegation by a single-actor signer, a non-user drains the vault with the signature `0xdeadbeef`. The exploit is confirmed against the live deployment's code, not only against a local build.
- Finding B, `test_official_registryUpgradeToThisRepoIsRefused` (pass): the official tenant's Registry refuses this repository's Registry implementation as its successor with `UpgradeBindingsChanged`. I confirmed separately that the unpatched base commit is refused the same way, and that a local-to-local Registry upgrade of the same code succeeds. So the Registry deployed on Arbitrum One is not built from the public source at this commit. Production sizes agree: deployed Registry implementation 23,979 bytes vs 23,574 from the public source; deployed timelock upgrade facet 21,857 vs 23,018; interactions facet 23,753 vs 23,670; while the engine (23,197) and the factory stage modules match exactly.
- Consequence: an in-place upgrade of a tenant created by the official factory cannot be built from the public repository. It needs the source of what is deployed, which only OKcontract has.
- Mitigating fact: at the fork block the official factory reports `nextInstanceId() == 0`, meaning it has created no tenant yet.

Item 3: real deployment. PREPARED, NOT SENT.
- `script/DeployFactoryFamily.s.sol` deploys one complete factory family (facets, implementations, engine, config, stage modules, terms registry, OKFactory), one contract per transaction, with the Arbitrum One dependency addresses as overridable defaults.
- Dry run against an Arbitrum One fork with the production build: simulation complete, about 180 million gas in total, estimated 0.0072 ETH at 0.04 gwei. No transaction was broadcast.
- Not done on purpose: sending it. That needs a funded deployer key and a decision that is not mine to make. Under the BUSL a deployment is only production-usable as an Official Factory published by OKcontract.

Verification of the whole tree in this run
- Default profile: 61 tests, 61 pass. Production profile: 61 tests, 61 pass.
- Pins stable in both profiles, containment check ok, production sizes unchanged (tokens facet 33 bytes under the limit).

### 6 Nov, 08:38 to 09:15: local deployment + traffic generator + full local test

Goal: a local chain that behaves like a public one, a real deployment onto it, and the whole suite run against that.

Local chain (`local/start-anvil.sh`)
- anvil forking Arbitrum One, Prague hardfork (EIP-7702), 1 second blocks, port 8546. A fork is required: the stack only deploys where EntryPoint v0.8 is pinned and needs the real Safe 1.3.0 contracts, so a blank chain (chain id 31337) cannot host it. The fork keeps chain id 42161 and every real contract.

Traffic generator (`local/noise.py`, standard library only)
- Keeps a pool of 150 impersonated wallets plus 12 keyed wallets (for EIP-7702), funds them, and sends a bursty, randomly paced, randomly mixed stream of real transactions: native transfers, WETH wrap/transfer, approvals, real Uniswap v3 swaps on the forked pools, USDC transfers, small contract deploys and calls to them, transactions that revert on chain, calldata-only notes, and EIP-7702 delegations and clears. Writes `local/run/noise.stats` every few seconds.
- Observed: ~5.9 tx/s sustained, 0 errors, 12 transaction kinds, ~230 tx across a sample of 40 blocks with 100 distinct senders, ~200 ok / ~30 reverted, 29 swaps (22 ok, 7 reverted), type-0x4 (7702) transactions present. The chain reads like a live public network.

Live deployment onto the local chain
- `script/DeployFactoryFamily.s.sol` run with `--broadcast` and the production profile against the local fork, signed by a fresh funded key. "ONCHAIN EXECUTION COMPLETE & SUCCESSFUL."
- Deployed: OKFactory 0x9DA61baA639778e193Ff08a06E07c62dEDBa5813, config, terms registry, engine, every implementation and facet. Factory codesize 6409, `nextInstanceId() == 0`. Gas for the whole family ~178.8M.

Full test in local (`test/LiveLocal7702.t.sol` + the whole suite)
- New `LiveLocal7702Test` forks the local chain, binds to the DEPLOYED factory (does not deploy a new one), creates a tenant through it, and runs the lifecycle and the 7702 attacks. 4 tests pass: 2-of-2 payout works; forged signature refused; delegate code cannot propose; an approved delegate works through the governed allowlist.
- Whole suite against the local chain, both profiles, with the traffic generator still running: 12 suites, 65 tests, 65 pass (default) and 65 pass (production).
- The background chain was unaffected: noise kept flowing at ~5.9 tx/s with 0 errors throughout (2,960 tx sent, kinds including 41 7702 delegations and 13 clears).

Note: the `LiveLocal` tenant lives only inside the forge fork of the local chain, not broadcast to it, so the live factory still reports `nextInstanceId() == 0`. The factory family itself is really deployed and persistent on the local chain.

Files added: `local/start-anvil.sh`, `local/noise.py`, `test/LiveLocal7702.t.sol`. `local/run/` is gitignored.
Total tests now: 65 (12 suites), green in both profiles, local fork and public fork alike.

### 6 Nov, 08:52 to 09:30: genuine end-to-end on the live local chain

`local/e2e.py` drives the DEPLOYED factory (0x9DA6...) with real transactions mined on the node, no forge fork. Every step persists on chain.
- Created a tenant through the factory's three stages (fresh funded owner key). Factory `nextInstanceId` went 0 -> 1 -> 2 across two runs, confirming real persistence.
- Configured it live: accepted terms, added alice/bob/carol, two groups, INTERACTION_EXECUTOR, a 2-of-2 treasury policy and a 1-of-1 ops policy, the circle org, the USDC contract record, and the usdc-transfer interaction (its MiniScript bytecode from the CLI). Created an OKAccount vault through the account factory; the registry admits it.
- Funded the vault with real USDC by locating its balanceOf storage slot (slot 9) with anvil_setStorageAt and confirming balanceOf == 1000e6.
- Lifecycle, real transactions: alice proposes, bob approves (2-of-2 met), alice executes. On chain: recipient 0 -> 250e6, vault 1000e6 -> 750e6.
- Attack, real transactions: deployed a yes-ERC1271 contract, delegated carol to it with a real EIP-7702 authorization (carol's code became 0xef0100 || yes), then the attacker sent directExecuteFromAccount with signature 0xdeadbeef. The transaction reverted on chain (ActorDelegated); attacker USDC 0; vault still 750e6.
- Post-run verification against the node: factory reports 2 tenants, the tenant registry owner is the deploy owner, registry not paused, vault holds 750e6 USDC, vault codesize 100. All persisted.
- The traffic generator kept running throughout: ~6 tx/s, 5531 sent, 1 transient error (a nonce race with the e2e sends, auto-recovered).

So the patched protocol is proven end-to-end three ways now: the full forge suite (65 tests, both profiles), a forge run bound to the live-deployed factory (LiveLocal7702Test, 4 tests), and this fully broadcast lifecycle-plus-attack on the live node.
