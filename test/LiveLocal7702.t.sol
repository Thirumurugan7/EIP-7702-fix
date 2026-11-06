// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.36;

import {console2} from "forge-std/console2.sol";

import {OKFactory} from "../src/OKFactory.sol";

import {IERC20, IRegistryAdmin, IInteract, TenantFixture} from "./TenantFixture.sol";

contract LiveDelegate {
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

/// @notice Runs against the PATCHED factory already deployed on the local anvil chain (port 8546),
///         while the background traffic generator keeps producing blocks. No contracts are deployed
///         by this test except the tenant it creates through the live factory and its own delegates.
///         Point it at the live chain:
///           LOCAL_RPC=http://127.0.0.1:8546 FOUNDRY_SOLC=$HOME/dev/oksolc/zig-out/bin/oksolc \
///             forge test --match-contract LiveLocal7702Test -vv
contract LiveLocal7702Test is TenantFixture {
    address internal constant LIVE_FACTORY = 0x9DA61baA639778e193Ff08a06E07c62dEDBa5813;
    LiveDelegate internal delegate;

    function setUp() public {
        (tenantOwner, tenantOwnerPk) = makeAddrAndKey("chainwall-live tenant owner");
        (alice, alicePk) = makeAddrAndKey("chainwall-live alice");
        (bob, bobPk) = makeAddrAndKey("chainwall-live bob");
        (carol, carolPk) = makeAddrAndKey("chainwall-live carol");

        // fork the LOCAL chain, not the public RPC
        vm.createSelectFork(vm.envString("LOCAL_RPC"));
        assertEq(block.chainid, 42161, "local fork is not Arbitrum One");
        _requirePlainEOA(tenantOwner);
        _requirePlainEOA(alice);
        _requirePlainEOA(bob);
        _requirePlainEOA(carol);

        factory = OKFactory(LIVE_FACTORY);
        require(address(factory).code.length != 0, "no factory at the live address");
        _deployTenant(tenantOwner, 0, keccak256("chainwall live local tenant"));
        _bindTenant();
        _configureTenant();
        delegate = new LiveDelegate();
    }

    function _actorDelegated(address actor) internal view returns (bytes memory) {
        return abi.encodeWithSignature("ActorDelegated(address,address)", actor, address(delegate));
    }

    /// @notice The deployed factory produces a correct tenant and a working 2-of-2 lifecycle.
    function test_live_lifecycle() public {
        console2.log("registry ", registry);
        console2.log("interact ", instance.interact);
        console2.log("vault    ", vault);

        uint256[] memory args = _transferArgs(recipient, 250e6);
        uint256 deadline = block.timestamp + 1 days;
        bytes32 payloadHash = interact.getPayloadHash(TRANSFER_INTERACTION, args, TREASURY_POLICY, deadline, 0, vault);
        vm.prank(alice);
        uint256 opId = interact.propose(payloadHash, TREASURY_POLICY, deadline, 0, vault);
        vm.prank(bob);
        assertTrue(interact.approveOperation(opId), "2 of 2");
        vm.prank(alice);
        interact.executeFromAccount(opId, TRANSFER_INTERACTION, args, 10_000);
        assertEq(IERC20(USDC).balanceOf(recipient), 250e6, "payout");
        assertEq(IERC20(USDC).balanceOf(vault), 750e6, "vault");
    }

    /// @notice The forged-signature attack is refused on the live deployment.
    function test_live_forgedSignatureRefused() public {
        _delegate(carolPk, carol, address(delegate));
        vm.prank(attacker);
        vm.expectRevert(_actorDelegated(carol));
        interact.directExecuteFromAccount(
            vault, OPS_POLICY, TRANSFER_INTERACTION, _transferArgs(attacker, 1_000e6), 10_000, 0,
            block.timestamp + 1 hours, carol, hex"deadbeef"
        );
        assertEq(IERC20(USDC).balanceOf(vault), 1_000e6);
    }

    /// @notice Delegate code cannot act as the actor on the live deployment.
    function test_live_delegateCodeCannotPropose() public {
        _delegate(carolPk, carol, address(delegate));
        uint256 deadline = block.timestamp + 1 days;
        bytes32 payloadHash =
            interact.getPayloadHash(TRANSFER_INTERACTION, _transferArgs(attacker, 1_000e6), OPS_POLICY, deadline, 0, vault);
        vm.prank(attacker);
        vm.expectRevert(_actorDelegated(carol));
        LiveDelegate(carol).exec(
            address(interact), abi.encodeCall(interact.propose, (payloadHash, OPS_POLICY, deadline, 0, vault))
        );
        assertEq(IERC20(USDC).balanceOf(attacker), 0);
    }

    /// @notice On the live deployment an approved delegate works and the allowlist is governed.
    function test_live_approvedDelegateWorks() public {
        _delegate(carolPk, carol, address(delegate));
        _configureDelegateCategory(0);
        vm.prank(tenantOwner);
        reg.allowDelegate(address(delegate));
        assertTrue(reg.isActorUsable(carol), "approved delegate usable");

        uint256 deadline = block.timestamp + 1 days;
        uint256[] memory args = _transferArgs(recipient, 100e6);
        bytes32 payloadHash = interact.getPayloadHash(TRANSFER_INTERACTION, args, OPS_POLICY, deadline, 0, vault);
        bytes memory ret = LiveDelegate(carol).exec(
            address(interact), abi.encodeCall(interact.propose, (payloadHash, OPS_POLICY, deadline, 0, vault))
        );
        uint256 opId = abi.decode(ret, (uint256));
        LiveDelegate(carol).exec(
            address(interact), abi.encodeCall(interact.executeFromAccount, (opId, TRANSFER_INTERACTION, args, 10_000))
        );
        assertEq(IERC20(USDC).balanceOf(recipient), 100e6);
    }
}
