// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.36;

import {Delegation7702} from "../src/Delegation7702.sol";

import {TenantFixture} from "./TenantFixture.sol";

contract DelegationProbe {
    function delegateOf(address a) external view returns (address) {
        return Delegation7702.delegateOf(a);
    }

    function isDelegated(address a) external view returns (bool) {
        return Delegation7702.isDelegated(a);
    }

    function hasContractCode(address a) external view returns (bool) {
        return Delegation7702.hasContractCode(a);
    }
}

contract Pingable {
    function ping() external {}
}

/// @notice Step 2 (detection library) and step 3 (Registry delegate allowlist) of the EIP-7702 patch.
contract Delegation7702Test is TenantFixture {
    DelegationProbe internal probe;
    Pingable internal delegateA;
    Pingable internal delegateB;

    function setUp() public {
        _setUpTenant();
        probe = new DelegationProbe();
        delegateA = new Pingable();
        delegateB = new Pingable();
    }

    // ---------------------------------------------------------------- detection library

    function test_lib_plainEOA() public {
        assertEq(carol.code.length, 0);
        assertEq(probe.delegateOf(carol), address(0));
        assertFalse(probe.isDelegated(carol));
        assertFalse(probe.hasContractCode(carol));
    }

    function test_lib_delegatedEOA() public {
        _delegate(carolPk, carol, address(delegateA));
        assertEq(probe.delegateOf(carol), address(delegateA));
        assertTrue(probe.isDelegated(carol));
        assertFalse(probe.hasContractCode(carol), "a delegated EOA must not count as a contract");
    }

    function test_lib_redelegationFollowsLatestDelegate() public {
        _delegate(carolPk, carol, address(delegateA));
        _delegate(carolPk, carol, address(delegateB));
        assertEq(probe.delegateOf(carol), address(delegateB));
    }

    function test_lib_realContract() public {
        assertEq(probe.delegateOf(address(delegateA)), address(0));
        assertFalse(probe.isDelegated(address(delegateA)));
        assertTrue(probe.hasContractCode(address(delegateA)));
        // real deployed protocol contracts on the fork
        assertTrue(probe.hasContractCode(USDC));
        assertTrue(probe.hasContractCode(instance.interact));
        assertTrue(probe.hasContractCode(registry));
    }

    /// @dev A contract whose runtime is exactly 23 bytes but is not a designator is still a contract.
    function test_lib_23ByteContractIsNotADelegation() public {
        // initcode: copy the 23 trailing bytes to memory and return them as runtime (23 x STOP)
        bytes memory initcode = abi.encodePacked(hex"6017600c60003960176000f3", new bytes(23));
        address c;
        assembly {
            c := create(0, add(initcode, 0x20), mload(initcode))
        }
        assertEq(c.code.length, 23);
        assertEq(probe.delegateOf(c), address(0));
        assertTrue(probe.hasContractCode(c));
    }

    // ---------------------------------------------------------------- registry allowlist

    function test_registry_viewsTrackDelegation() public {
        assertEq(reg.delegateOf(carol), address(0));
        assertTrue(reg.isActorUsable(carol), "plain EOA must be usable");
        assertTrue(reg.isActorUsable(instance.interact), "a contract must be usable");

        _delegate(carolPk, carol, address(delegateA));
        assertEq(reg.delegateOf(carol), address(delegateA));
        assertFalse(reg.isActorUsable(carol), "delegated to an unapproved delegate");
        assertEq(reg.getAllowedDelegateCount(), 0, "allowlist must start empty");
    }

    /// @notice Approving delegates is opt-in: until governance configures the delegate timelock
    ///         category, nobody can approve one, not even the admin.
    function test_registry_allowDelegateNeedsCategoryConfig() public {
        vm.prank(tenantOwner);
        vm.expectRevert(
            abi.encodeWithSignature("TimelockCategoryNotConfigured(bytes32)", keccak256("timelock.category.delegate"))
        );
        reg.allowDelegate(address(delegateA));

        _configureDelegateCategory(0);
        vm.prank(tenantOwner);
        reg.allowDelegate(address(delegateA));
        assertTrue(reg.isDelegateAllowed(address(delegateA)));
    }

    function test_registry_onlyAdminCanAllow() public {
        _configureDelegateCategory(0);
        vm.prank(carol);
        vm.expectRevert();
        reg.allowDelegate(address(delegateA));
        assertFalse(reg.isDelegateAllowed(address(delegateA)));
    }

    function test_registry_rejectsBadDelegates() public {
        _configureDelegateCategory(0);
        vm.startPrank(tenantOwner);
        vm.expectRevert(bytes4(keccak256("DelegateZero()")));
        reg.allowDelegate(address(0));

        vm.expectRevert(abi.encodeWithSignature("DelegateNotContract(address)", outsider));
        reg.allowDelegate(outsider);
        vm.stopPrank();

        // a delegated EOA cannot itself be approved as a delegate
        _delegate(bobPk, bob, address(delegateA));
        vm.prank(tenantOwner);
        vm.expectRevert(abi.encodeWithSignature("DelegateNotContract(address)", bob));
        reg.allowDelegate(bob);
    }

    function test_registry_allowAndDisallow() public {
        _configureDelegateCategory(0);
        _delegate(carolPk, carol, address(delegateA));
        assertFalse(reg.isActorUsable(carol));

        vm.prank(tenantOwner);
        reg.allowDelegate(address(delegateA));
        assertTrue(reg.isDelegateAllowed(address(delegateA)));
        assertTrue(reg.isActorUsable(carol), "approved delegate");
        assertEq(reg.getAllowedDelegateCount(), 1);
        (address d, bytes32 h) = reg.getAllowedDelegateAt(0);
        assertEq(d, address(delegateA));
        assertEq(h, address(delegateA).codehash);

        // approval is per delegate: another delegate is still refused
        _delegate(carolPk, carol, address(delegateB));
        assertFalse(reg.isActorUsable(carol), "re-delegated to an unapproved delegate");

        vm.startPrank(tenantOwner);
        vm.expectRevert(abi.encodeWithSignature("DelegateAlreadyAllowed(address)", address(delegateA)));
        reg.allowDelegate(address(delegateA));

        reg.disallowDelegate(address(delegateA));
        assertFalse(reg.isDelegateAllowed(address(delegateA)));
        assertEq(reg.getAllowedDelegateCount(), 0);

        vm.expectRevert(abi.encodeWithSignature("DelegateNotAllowed(address)", address(delegateA)));
        reg.disallowDelegate(address(delegateA));
        vm.stopPrank();
    }

    /// @dev The approval pins the delegate's runtime codehash: different code at the same address is refused.
    function test_registry_codehashDriftRevokesApproval() public {
        _configureDelegateCategory(0);
        vm.prank(tenantOwner);
        reg.allowDelegate(address(delegateA));
        assertTrue(reg.isDelegateAllowed(address(delegateA)));

        // Test-only: replace the code at the approved address to model an address whose code changed.
        vm.etch(address(delegateA), address(probe).code);
        assertFalse(reg.isDelegateAllowed(address(delegateA)), "approval must not survive a code change");
    }
}
