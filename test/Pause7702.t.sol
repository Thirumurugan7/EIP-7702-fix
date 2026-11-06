// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.36;

import {TenantFixture} from "./TenantFixture.sol";

contract WalletDelegate {
    function ping() external {}
}

/// @notice The EIP-7702 actor rule while the Registry is paused. The delegate views are in the pause
///         containment table as reads, so the rule keeps working for approved delegates; delegate
///         allowlist writes stay blocked.
contract Pause7702Test is TenantFixture {
    WalletDelegate internal delegate;

    function setUp() public {
        _setUpTenant();
        _configureTenant();
        delegate = new WalletDelegate();
    }

    function test_pause_delegateViewsReadableWritesBlocked() public {
        _configureDelegateCategory(0);
        vm.prank(tenantOwner);
        reg.pause();
        assertTrue(reg.paused());

        assertTrue(reg.isActorUsable(carol));
        reg.requireActorUsable(carol);
        assertEq(reg.delegateOf(carol), address(0));
        assertFalse(reg.isDelegateAllowed(address(delegate)));
        assertEq(reg.getAllowedDelegateCount(), 0);

        vm.prank(tenantOwner);
        vm.expectRevert(bytes4(keccak256("EnforcedPause()")));
        reg.allowDelegate(address(delegate));
    }

    /// @notice An admin whose delegate is approved keeps working through a pause, including the unpause.
    function test_pause_adminWithApprovedDelegateCanPauseAndUnpause() public {
        _configureDelegateCategory(0);
        vm.prank(tenantOwner);
        reg.allowDelegate(address(delegate));
        _delegate(tenantOwnerPk, tenantOwner, address(delegate));

        vm.prank(tenantOwner);
        reg.pause();
        assertTrue(reg.paused());
        assertTrue(reg.isActorUsable(tenantOwner), "approved delegate must stay usable while paused");

        vm.prank(tenantOwner);
        reg.unpause();
        assertFalse(reg.paused());
    }

    /// @notice An admin who delegates to an unapproved delegate cannot unpause until the delegation is cleared.
    function test_pause_adminWithUnapprovedDelegateCannotUnpause() public {
        vm.prank(tenantOwner);
        reg.pause();
        _delegate(tenantOwnerPk, tenantOwner, address(delegate));

        vm.prank(tenantOwner);
        vm.expectRevert(abi.encodeWithSignature("ActorDelegated(address,address)", tenantOwner, address(delegate)));
        reg.unpause();
        assertTrue(reg.paused());

        _clearDelegation(tenantOwnerPk, tenantOwner);
        vm.prank(tenantOwner);
        reg.unpause();
        assertFalse(reg.paused());
    }
}
