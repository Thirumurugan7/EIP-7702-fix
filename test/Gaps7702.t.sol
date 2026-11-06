// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.36;

import {ContractAddress, ERCToken, InteractionBundleInput, LinkedArtifactInput} from "@chainwall/interfaces/RegistryTypes.sol";

import {SecretCommitLib} from "../src/registry/SecretCommitLib.sol";

import {IRegistryAdmin, TenantFixture, TimelockCategoryConfig} from "./TenantFixture.sol";

contract YesDelegate {
    function ping() external {}

    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }

    function exec(address target, bytes calldata data) external returns (bytes memory ret) {
        bool ok;
        (ok, ret) = target.call(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }
}

/// @dev Exposes the protocol's own commitment formulas so tests never re-derive them by hand.
contract CommitMath {
    function contractCommit(bytes32 key, ContractAddress calldata a, bytes32 label, bytes32 salt)
        external
        pure
        returns (bytes32)
    {
        return SecretCommitLib.computeContractCommit(key, a, label, salt);
    }

    function tokenCommit(bytes32 key, ERCToken calldata d, uint256 flags, bytes32 salt)
        external
        pure
        returns (bytes32)
    {
        return SecretCommitLib.computeTokenCommit(key, d, flags, salt);
    }

    function interactionCommit(InteractionBundleInput calldata b, bytes32[] calldata related, bytes32 salt)
        external
        pure
        returns (bytes32)
    {
        return SecretCommitLib.computeInteractionCommit(b, related, salt);
    }
}

interface IAuthFactory {
    struct DirectExecuteScope {
        address account;
        bytes32 policyId;
        bytes32 interactionId;
        bool active;
    }

    function newAuthAccount(
        bytes32 accountSalt,
        bytes32 initialCredHash,
        bytes32 initialQx,
        bytes32 initialQy,
        address expectedImplementation,
        bytes32 expectedImplementationCodehash,
        DirectExecuteScope[] calldata initialScopes
    ) external returns (address);
}

/// @notice Closes the gaps left after steps 4 and 5: roles, timelock replay and stored timelock
///         approvals, the three commit-reveal signature sites, and the passkey factory admin checks.
contract Gaps7702Test is TenantFixture {
    bytes32 internal constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 internal constant GRANT_ADMIN = keccak256("cap.registry.admin.grant");
    bytes32 internal constant REVOKE_ADMIN = keccak256("cap.registry.admin.revoke");
    bytes32 internal constant INTERACTION_AUTHOR = keccak256("cap.registry.interaction.write");
    bytes32 internal constant CATEGORY_USER = keccak256("timelock.category.user");
    bytes32 internal constant CATEGORY_DELEGATE = keccak256("timelock.category.delegate");

    YesDelegate internal delegate;
    CommitMath internal math;
    address internal dora;
    uint256 internal doraPk;

    function setUp() public {
        _setUpTenant();
        _configureTenant();
        delegate = new YesDelegate();
        math = new CommitMath();
        (dora, doraPk) = makeAddrAndKey("chainwall-test dora");
        _requirePlainEOA(dora);
    }

    function _actorDelegated(address actor) internal view returns (bytes memory) {
        return abi.encodeWithSignature("ActorDelegated(address,address)", actor, address(delegate));
    }

    function _lastPendingAction() internal view returns (bytes32) {
        bytes32[] memory ids = reg.getPendingActionIds(0, 50);
        require(ids.length != 0, "nothing queued");
        return ids[ids.length - 1];
    }

    // ------------------------------------------------------------------ roles

    function test_roles_hasRoleFollowsDelegation() public {
        assertTrue(reg.hasRole(ADMIN_ROLE, tenantOwner));
        _delegate(tenantOwnerPk, tenantOwner, address(delegate));
        assertFalse(reg.hasRole(ADMIN_ROLE, tenantOwner), "a delegated admin must not read as an admin");
        _clearDelegation(tenantOwnerPk, tenantOwner);
        assertTrue(reg.hasRole(ADMIN_ROLE, tenantOwner), "the stored grant is intact");
    }

    /// @notice The role of a currently delegated admin can still be revoked, and stays revoked.
    function test_roles_delegatedAdminCanBeRevoked() public {
        (address erin, uint256 erinPk) = makeAddrAndKey("chainwall-test erin");
        vm.startPrank(tenantOwner);
        reg.grantCapabilityGroup(GRANT_ADMIN, OPS_GROUP);
        reg.grantCapabilityGroup(REVOKE_ADMIN, OPS_GROUP);
        vm.stopPrank();

        vm.prank(carol);
        reg.grantRole(ADMIN_ROLE, erin);
        assertTrue(reg.hasRole(ADMIN_ROLE, erin), "granted");

        _delegate(erinPk, erin, address(delegate));
        assertFalse(reg.hasRole(ADMIN_ROLE, erin));

        vm.prank(carol);
        reg.revokeRole(ADMIN_ROLE, erin);

        _clearDelegation(erinPk, erin);
        assertFalse(reg.hasRole(ADMIN_ROLE, erin), "revocation must reach the stored grant");
    }

    // ------------------------------------------------------------------ timelock

    function _setUserCategory(uint64 delay, bytes32 policyId) internal {
        vm.prank(tenantOwner);
        reg.setCategoryConfig(CATEGORY_USER, TimelockCategoryConfig(0, 30 days, delay, 1 days, policyId));
    }

    /// @notice A queued action replays with its queuer as actor. If the queuer delegated in the meantime,
    ///         the replay is refused, whoever triggers it.
    function test_timelock_queuerDelegatesBeforeExecution() public {
        address newUser = makeAddr("chainwall-test queued user");
        _setUserCategory(1 hours, bytes32(0));

        vm.prank(tenantOwner);
        reg.addUser(newUser);
        assertFalse(reg.isUser(newUser), "must be queued, not applied");
        bytes32 actionId = _lastPendingAction();

        _delegate(tenantOwnerPk, tenantOwner, address(delegate));
        vm.warp(block.timestamp + 1 hours + 1);

        vm.prank(outsider);
        vm.expectRevert(_actorDelegated(tenantOwner));
        reg.executeAction(actionId);
        assertFalse(reg.isUser(newUser));

        _clearDelegation(tenantOwnerPk, tenantOwner);
        vm.prank(outsider);
        reg.executeAction(actionId);
        assertTrue(reg.isUser(newUser), "executes once the queuer is a plain EOA again");
    }

    /// @notice A stored timelock approval stops counting when its approver delegates.
    function test_timelock_approverDelegatesBeforeExecution() public {
        address newUser = makeAddr("chainwall-test reviewed user");
        _setUserCategory(0, TREASURY_POLICY);

        vm.prank(tenantOwner);
        reg.addUser(newUser);
        assertFalse(reg.isUser(newUser), "must wait for review");
        bytes32 actionId = _lastPendingAction();

        vm.prank(alice);
        reg.approveAction(actionId);
        vm.prank(bob);
        assertTrue(reg.approveAction(actionId), "2 of 2 approvals should make it ready");

        _delegate(bobPk, bob, address(delegate));
        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSignature("TimelockApprovalsStale(bytes32,bytes32)", actionId, TREASURY_POLICY));
        reg.executeAction(actionId);
        assertFalse(reg.isUser(newUser), "one approval no longer counts");

        _clearDelegation(bobPk, bob);
        vm.prank(outsider);
        reg.executeAction(actionId);
        assertTrue(reg.isUser(newUser));
    }

    /// @notice A delegated member cannot approve a timelock action at all.
    function test_timelock_delegatedMemberCannotApprove() public {
        _setUserCategory(0, TREASURY_POLICY);
        vm.prank(tenantOwner);
        reg.addUser(makeAddr("chainwall-test reviewed user 2"));
        bytes32 actionId = _lastPendingAction();

        _delegate(alicePk, alice, address(delegate));
        vm.prank(attacker);
        vm.expectRevert(_actorDelegated(alice));
        YesDelegate(alice).exec(registry, abi.encodeCall(reg.approveAction, (actionId)));
    }

    /// @notice Approving a delegate obeys a real delay on the delegate timelock category.
    function test_timelock_delegateApprovalIsDelayed() public {
        vm.prank(tenantOwner);
        reg.setCategoryConfig(CATEGORY_DELEGATE, TimelockCategoryConfig(0, 30 days, 2 days, 1 days, bytes32(0)));

        vm.prank(tenantOwner);
        reg.allowDelegate(address(delegate));
        assertFalse(reg.isDelegateAllowed(address(delegate)), "must be queued");
        bytes32 actionId = _lastPendingAction();

        vm.prank(outsider);
        vm.expectRevert(abi.encodeWithSignature("TimelockActionNotReady(bytes32,uint8)", actionId, uint8(1)));
        reg.executeAction(actionId);

        vm.warp(block.timestamp + 2 days + 1);
        vm.prank(outsider);
        reg.executeAction(actionId);
        assertTrue(reg.isDelegateAllowed(address(delegate)));
    }

    // ------------------------------------------------------------------ commit / reveal signatures

    function _signReveal(string memory typeString, bytes32 keyOrId, bytes32 commitHash, bytes32 salt, address relayer)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash =
            keccak256(abi.encode(keccak256(bytes(typeString)), keyOrId, commitHash, salt, block.chainid, relayer));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(doraPk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev dora owns the org "acme" and may write its catalog; she is not an admin.
    function _giveDoraAnOrg() internal {
        vm.startPrank(tenantOwner);
        reg.setOrgCatalogDelegationEnabled(true);
        reg.upsertOrg("acme", dora, false, new address[](0));
        vm.stopPrank();
    }

    address internal constant SECRET_TARGET = 0x82aF49447D8a07e3bd95BD0d56f35241523fBab1; // WETH, Arbitrum One
    bytes32 internal constant SALT = keccak256("chainwall-test salt");

    function _commitContract() internal returns (ContractAddress memory a, bytes32 key, bytes32 commitHash) {
        _giveDoraAnOrg();
        a = ContractAddress(SECRET_TARGET, bytes32("1"), address(0));
        key = keccak256("acme/secret");
        commitHash = math.contractCommit(key, a, bytes32(0), SALT);
        vm.prank(dora);
        reg.commitContractPrivate("acme", "secret", commitHash, uint64(block.timestamp + 1 days), address(0), bytes32(0));
    }

    string internal constant REVEAL_CONTRACT =
        "RevealContract(bytes32 key,bytes32 commitHash,bytes32 salt,uint256 chainId,address forwarder)";

    /// @notice Control: with a real signature from the committer's key, a relayer can reveal.
    function test_reveal_contract_realSignatureWorks() public {
        (ContractAddress memory a, bytes32 key, bytes32 commitHash) = _commitContract();
        bytes memory sig = _signReveal(REVEAL_CONTRACT, key, commitHash, SALT, outsider);
        vm.prank(outsider);
        reg.revealContractCommit("acme", "secret", a, bytes32(0), SALT, sig);
        assertEq(reg.getAddress("acme", "secret"), SECRET_TARGET);
    }

    /// @notice Control: a garbage signature for a plain-EOA committer is rejected.
    function test_reveal_contract_garbageSignatureRejected() public {
        (ContractAddress memory a,,) = _commitContract();
        vm.prank(attacker);
        vm.expectRevert(bytes4(keccak256("RevealSignatureInvalid()")));
        reg.revealContractCommit("acme", "secret", a, bytes32(0), SALT, hex"deadbeef");
    }

    /// @notice Once the committer delegates, her delegate's ERC-1271 answer must not publish the commit.
    function test_reveal_contract_delegatedCommitterRefused() public {
        (ContractAddress memory a,,) = _commitContract();
        _delegate(doraPk, dora, address(delegate));
        vm.prank(attacker);
        vm.expectRevert(_actorDelegated(dora));
        reg.revealContractCommit("acme", "secret", a, bytes32(0), SALT, hex"deadbeef");
    }

    function _commitToken() internal returns (ERCToken memory t) {
        _giveDoraAnOrg();
        t = ERCToken("acme", "tkn", "TKN", 18, address(0), 0);
        bytes32 commitHash = math.tokenCommit(keccak256("acme/tkn"), t, 0, SALT);
        vm.prank(dora);
        reg.commitTokenPrivate("acme", "tkn", commitHash, uint64(block.timestamp + 1 days), address(0), bytes32(0));
    }

    function test_reveal_token_garbageSignatureRejected() public {
        ERCToken memory t = _commitToken();
        vm.prank(attacker);
        vm.expectRevert(bytes4(keccak256("RevealSignatureInvalid()")));
        reg.revealTokenCommit(t, 0, SALT, hex"deadbeef");
    }

    function test_reveal_token_delegatedCommitterRefused() public {
        ERCToken memory t = _commitToken();
        _delegate(doraPk, dora, address(delegate));
        vm.prank(attacker);
        vm.expectRevert(_actorDelegated(dora));
        reg.revealTokenCommit(t, 0, SALT, hex"deadbeef");
    }

    function _commitInteraction() internal returns (InteractionBundleInput memory bundle) {
        // carol may author interactions through her group; she is not an admin.
        vm.prank(tenantOwner);
        reg.grantCapabilityGroup(INTERACTION_AUTHOR, OPS_GROUP);
        bundle.id = keccak256("private-transfer");
        bundle.script = TRANSFER_SCRIPT;
        bundle.flags = 0;
        bundle.linked = new LinkedArtifactInput[](0);
        bytes32 commitHash = math.interactionCommit(bundle, new bytes32[](0), SALT);
        vm.prank(carol);
        reg.commitInteractionPrivate(bundle.id, commitHash, uint64(block.timestamp + 1 days), address(0), bytes32(0));
    }

    function test_reveal_interaction_garbageSignatureRejected() public {
        InteractionBundleInput memory bundle = _commitInteraction();
        vm.prank(attacker);
        vm.expectRevert(bytes4(keccak256("RevealSignatureInvalid()")));
        reg.revealInteractionCommit(bundle, new bytes32[](0), SALT, hex"deadbeef");
    }

    /// @notice A delegated interaction author's private script cannot be published by a third party
    ///         behind her delegate: the reveal signature check refuses her.
    function test_reveal_interaction_delegatedCommitterRefused() public {
        InteractionBundleInput memory bundle = _commitInteraction();
        _delegate(carolPk, carol, address(delegate));
        vm.prank(attacker);
        vm.expectRevert(_actorDelegated(carol));
        reg.revealInteractionCommit(bundle, new bytes32[](0), SALT, hex"deadbeef");
    }

    // ------------------------------------------------------------------ passkey factory admin checks

    /// @notice A second tenant deployed WITH the passkey module: its factory refuses a delegated admin.
    function test_passkeyFactory_delegatedAdminRefused() public {
        (address owner2, uint256 owner2Pk) = makeAddrAndKey("chainwall-test passkey tenant owner");
        _requirePlainEOA(owner2);
        _deployTenant(owner2, 2, keccak256("passkey tenant"));
        IAuthFactory authFactory = IAuthFactory(instance.authAccountFactory);
        assertGt(address(authFactory).code.length, 0, "passkey factory not deployed");
        IAuthFactory.DirectExecuteScope[] memory none = new IAuthFactory.DirectExecuteScope[](0);

        // control: a plain-EOA admin passes the admin check (and then fails on the dummy arguments)
        vm.prank(owner2);
        try authFactory.newAuthAccount(bytes32(uint256(1)), bytes32(0), bytes32(0), bytes32(0), address(0), bytes32(0), none) {
            revert("dummy arguments were accepted");
        } catch (bytes memory reason) {
            assertTrue(bytes4(reason) != bytes4(keccak256("NotAuthManager(address)")), "plain admin was refused");
        }

        _delegate(owner2Pk, owner2, address(delegate));
        vm.prank(owner2);
        vm.expectRevert(abi.encodeWithSignature("NotAuthManager(address)", owner2));
        authFactory.newAuthAccount(bytes32(uint256(1)), bytes32(0), bytes32(0), bytes32(0), address(0), bytes32(0), none);
    }
}
