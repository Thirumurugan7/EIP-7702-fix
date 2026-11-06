// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.36;

import {IERC20, TenantFixture} from "./TenantFixture.sol";

/// @notice Delegate code used in these tests: lets anyone drive the delegated account, and calls every
///         signature valid.
contract DrivableDelegate {
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

/// @notice Steps 4 and 5 of the EIP-7702 patch: each enforcement site, with its exact revert.
contract Guard7702Test is TenantFixture {
    DrivableDelegate internal delegate;

    function setUp() public {
        _setUpTenant();
        _configureTenant();
        delegate = new DrivableDelegate();
    }

    function _actorDelegated(address actor) internal view returns (bytes memory) {
        return abi.encodeWithSignature("ActorDelegated(address,address)", actor, address(delegate));
    }

    // ------------------------------------------------------------------ Interact (step 5)

    function test_interact_forgedSignatureRevertsActorDelegated() public {
        _delegate(carolPk, carol, address(delegate));
        uint256[] memory args = _transferArgs(attacker, 1_000e6);
        vm.prank(attacker);
        vm.expectRevert(_actorDelegated(carol));
        interact.directExecuteFromAccount(
            vault, OPS_POLICY, TRANSFER_INTERACTION, args, 10_000, 0, block.timestamp + 1 hours, carol, hex"deadbeef"
        );
    }

    function test_interact_delegatedSenderCannotPropose() public {
        _delegate(carolPk, carol, address(delegate));
        uint256[] memory args = _transferArgs(attacker, 1_000e6);
        uint256 deadline = block.timestamp + 1 days;
        bytes32 payloadHash = interact.getPayloadHash(TRANSFER_INTERACTION, args, OPS_POLICY, deadline, 0, vault);

        vm.prank(attacker);
        vm.expectRevert(_actorDelegated(carol));
        DrivableDelegate(carol).exec(
            address(interact), abi.encodeCall(interact.propose, (payloadHash, OPS_POLICY, deadline, 0, vault))
        );
    }

    /// @notice An approval stops counting when its approver delegates before execution, and counts again
    ///         once the delegation is cleared.
    function test_interact_approvalDroppedWhenApproverDelegatesBeforeExecute() public {
        uint256[] memory args = _transferArgs(recipient, 250e6);
        uint256 deadline = block.timestamp + 1 days;
        bytes32 payloadHash = interact.getPayloadHash(TRANSFER_INTERACTION, args, TREASURY_POLICY, deadline, 0, vault);

        vm.prank(alice);
        uint256 opId = interact.propose(payloadHash, TREASURY_POLICY, deadline, 0, vault);
        vm.prank(bob);
        assertTrue(interact.approveOperation(opId), "2 of 2 reached");

        _delegate(bobPk, bob, address(delegate));

        vm.prank(alice);
        vm.expectRevert(bytes("AccessControlPolicy: operation not approved by required groups"));
        interact.executeFromAccount(opId, TRANSFER_INTERACTION, args, 10_000);
        assertEq(IERC20(USDC).balanceOf(recipient), 0);

        _clearDelegation(bobPk, bob);

        vm.prank(alice);
        interact.executeFromAccount(opId, TRANSFER_INTERACTION, args, 10_000);
        assertEq(IERC20(USDC).balanceOf(recipient), 250e6, "executes once the approver is a plain EOA again");
    }

    /// @notice A delegated submitter cannot withdraw its own operation through its delegate.
    function test_interact_delegatedSubmitterCannotWithdraw() public {
        uint256[] memory args = _transferArgs(recipient, 250e6);
        uint256 deadline = block.timestamp + 1 days;
        bytes32 payloadHash = interact.getPayloadHash(TRANSFER_INTERACTION, args, TREASURY_POLICY, deadline, 0, vault);
        vm.prank(alice);
        uint256 opId = interact.propose(payloadHash, TREASURY_POLICY, deadline, 0, vault);

        _delegate(alicePk, alice, address(delegate));
        vm.prank(attacker);
        vm.expectRevert(_actorDelegated(alice));
        DrivableDelegate(alice).exec(address(interact), abi.encodeWithSignature("withdrawOperation(uint256)", opId));
    }

    /// @notice With the delegate approved by the tenant, the delegated actor works again.
    function test_interact_approvedDelegateMayAct() public {
        _delegate(carolPk, carol, address(delegate));
        _configureDelegateCategory(0);
        vm.prank(tenantOwner);
        reg.allowDelegate(address(delegate));

        uint256[] memory args = _transferArgs(recipient, 100e6);
        uint256 deadline = block.timestamp + 1 days;
        bytes32 payloadHash = interact.getPayloadHash(TRANSFER_INTERACTION, args, OPS_POLICY, deadline, 0, vault);

        bytes memory ret = DrivableDelegate(carol).exec(
            address(interact), abi.encodeCall(interact.propose, (payloadHash, OPS_POLICY, deadline, 0, vault))
        );
        uint256 opId = abi.decode(ret, (uint256));
        DrivableDelegate(carol).exec(
            address(interact), abi.encodeCall(interact.executeFromAccount, (opId, TRANSFER_INTERACTION, args, 10_000))
        );
        assertEq(IERC20(USDC).balanceOf(recipient), 100e6);
    }

    // ------------------------------------------------------------------ Registry (step 4)

    function test_registry_predicatesFollowDelegation() public {
        assertTrue(reg.isUser(carol));
        assertTrue(reg.isGroupMemberByHash(OPS_GROUP, carol));
        assertTrue(reg.hasCapability(INTERACTION_EXECUTOR, carol));

        _delegate(carolPk, carol, address(delegate));
        assertFalse(reg.isUser(carol), "isUser");
        assertFalse(reg.isGroupMemberByHash(OPS_GROUP, carol), "isGroupMemberByHash");
        assertFalse(reg.hasCapability(INTERACTION_EXECUTOR, carol), "hasCapability");

        _clearDelegation(carolPk, carol);
        assertTrue(reg.isUser(carol));
        assertTrue(reg.isGroupMemberByHash(OPS_GROUP, carol));
        assertTrue(reg.hasCapability(INTERACTION_EXECUTOR, carol));
    }

    /// @notice A delegated admin cannot govern, even when the call really comes from its address.
    function test_registry_delegatedAdminCannotAct() public {
        address newUser = makeAddr("chainwall-test new user");
        _delegate(tenantOwnerPk, tenantOwner, address(delegate));

        // through the delegate's code
        vm.prank(attacker);
        vm.expectRevert(_actorDelegated(tenantOwner));
        DrivableDelegate(tenantOwner).exec(registry, abi.encodeCall(reg.addUser, (newUser)));

        // and directly from the delegated address
        vm.prank(tenantOwner);
        vm.expectRevert(_actorDelegated(tenantOwner));
        reg.addUser(newUser);

        vm.prank(tenantOwner);
        vm.expectRevert(_actorDelegated(tenantOwner));
        reg.allowDelegate(address(delegate));

        _clearDelegation(tenantOwnerPk, tenantOwner);
        vm.prank(tenantOwner);
        reg.addUser(newUser);
        assertTrue(reg.isUser(newUser), "admin works again as a plain EOA");
    }

    function test_registry_cannotGrantToDelegatedAccount() public {
        (address erin, uint256 erinPk) = makeAddrAndKey("chainwall-test erin");
        _delegate(erinPk, erin, address(delegate));

        vm.prank(tenantOwner);
        vm.expectRevert(_actorDelegated(erin));
        reg.addUser(erin);

        // bob is a user; once delegated he cannot be added to another group
        _delegate(bobPk, bob, address(delegate));
        vm.prank(tenantOwner);
        vm.expectRevert(_actorDelegated(bob));
        reg.addGroupMember(OPS_GROUP, bob);
    }

    // ------------------------------------------------------------------ Factory

    function test_factory_rejectsDelegatedTenantOwner() public {
        (address owner2, uint256 owner2Pk) = makeAddrAndKey("chainwall-test second owner");
        _delegate(owner2Pk, owner2, address(delegate));
        vm.expectRevert(abi.encodeWithSignature("OwnerDelegated(address,address)", owner2, address(delegate)));
        factory.deployInstanceStage1Deterministic(owner2, 0, keccak256("second tenant"));
    }
}
