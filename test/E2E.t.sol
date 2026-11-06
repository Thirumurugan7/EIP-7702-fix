// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.36;

import {console2} from "forge-std/console2.sol";

import {IERC20, IRegistryView, TenantFixture} from "./TenantFixture.sol";

/// @notice End to end run of the unmodified protocol from the local build on an Arbitrum One fork.
contract E2ETest is TenantFixture {
    function setUp() public {
        _setUpTenant();
    }

    function test_01_tenantDeployed() public {
        IRegistryView r = IRegistryView(registry);
        console2.log("factory      ", address(factory));
        console2.log("registry     ", registry);
        console2.log("interact     ", instance.interact);
        console2.log("miniScript   ", instance.miniScript);
        console2.log("safeFactory  ", instance.safeFactory);
        console2.log("acctFactory  ", instance.accountFactory);
        console2.log("engine       ", engine);
        console2.logBytes32(engine.codehash);

        assertEq(r.owner(), tenantOwner, "owner");
        assertTrue(r.hasRole(r.ADMIN_ROLE(), tenantOwner), "admin role");
        assertTrue(r.hasRole(r.UPGRADER_ROLE(), tenantOwner), "upgrader role");
        assertFalse(r.hasRole(r.ADMIN_ROLE(), address(factory)), "factory kept admin");
        assertFalse(r.paused(), "paused");
        assertEq(instance.initialOwner, tenantOwner, "instance owner");
        assertGt(instance.interact.code.length, 0, "interact");
        assertGt(instance.miniScript.code.length, 0, "miniScript");
        assertGt(instance.safeFactory.code.length, 0, "safeFactory");
        assertGt(instance.accountFactory.code.length, 0, "accountFactory");

        assertFalse(r.instanceHasAcceptedInitialTerms(), "terms pre-accepted");
        vm.prank(tenantOwner);
        r.acceptTerms(INITIAL_TERMS_HASH);
        assertTrue(r.instanceHasAcceptedInitialTerms(), "terms");
    }

    /// @notice Full lifecycle on an OKAccount vault with a 2-of-2 policy: a real USDC transfer.
    function test_02_proposeApproveExecute() public {
        _configureTenant();

        uint256[] memory args = _transferArgs(recipient, 250e6);
        uint256 deadline = block.timestamp + 1 days;
        bytes32 payloadHash = interact.getPayloadHash(TRANSFER_INTERACTION, args, TREASURY_POLICY, deadline, 0, vault);

        // a non-user cannot propose
        vm.prank(outsider);
        vm.expectRevert(bytes("AccessControlPolicy: caller is not a user"));
        interact.propose(payloadHash, TREASURY_POLICY, deadline, 0, vault);

        // alice proposes; as a policy signatory her approval is recorded with the proposal
        vm.prank(alice);
        uint256 opId = interact.propose(payloadHash, TREASURY_POLICY, deadline, 0, vault);
        console2.log("operation id ", opId);

        // 1 of 2 approvals: execution is refused
        vm.prank(alice);
        vm.expectRevert(bytes("AccessControlPolicy: operation not approved by required groups"));
        interact.executeFromAccount(opId, TRANSFER_INTERACTION, args, 10_000);

        // bob approves: thresholds met
        vm.prank(bob);
        assertTrue(interact.approveOperation(opId), "thresholds not met after 2nd approval");

        // approved operation, different amount: refused (payload hash mismatch)
        uint256[] memory tampered = _transferArgs(recipient, 900e6);
        vm.prank(alice);
        vm.expectRevert(bytes4(keccak256("OperationHashMismatch()")));
        interact.executeFromAccount(opId, TRANSFER_INTERACTION, tampered, 10_000);

        // the exact approved action executes
        vm.prank(alice);
        uint256 stackTop = interact.executeFromAccount(opId, TRANSFER_INTERACTION, args, 10_000);
        console2.log("stackTop     ", stackTop);
        assertEq(IERC20(USDC).balanceOf(recipient), 250e6, "recipient");
        assertEq(IERC20(USDC).balanceOf(vault), 750e6, "vault");

        // the operation is consumed: no replay
        vm.prank(alice);
        vm.expectRevert(bytes("AccessControlPolicy: operation does not exist"));
        interact.executeFromAccount(opId, TRANSFER_INTERACTION, args, 10_000);
    }
}
