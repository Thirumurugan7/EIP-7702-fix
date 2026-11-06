// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.36;

import {console2} from "forge-std/console2.sol";

import {ContractAddress} from "@chainwall/interfaces/RegistryTypes.sol";

import {IERC20, TenantFixture} from "./TenantFixture.sol";

/// @notice What an attacker would point a hijacked actor at: it calls every signature valid
///         (ERC-1271) and lets anyone make the account call anything.
contract AttackerDelegate {
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

/// @notice Code behind a delegated EOA that is registered as a contract target.
contract HookImpl {
    event Pinged(address self);

    function ping() external {
        emit Pinged(address(this));
    }
}

/// @notice EIP-7702 attack tests. Each `test_attack_*` asserts the SECURE outcome, so it FAILS on the
///         unpatched protocol (the attack works) and must pass once the actor guard is in place.
///         Each `test_control_*` passes before and after: it pins down what is and is not the bug.
contract Attack7702Test is TenantFixture {
    AttackerDelegate internal attackerDelegate;

    /// @dev Output of `miniscript compile test/scripts/hook-ping.core.ls` (Chainwall CLI 0.3.1):
    ///      WRITE keccak("acme/hook").ping() and require it to succeed.
    bytes internal constant HOOK_SCRIPT =
        hex"02fa7edbbe41f8a99072fb3c4146249d3cee91e93648d3741f5c85a98c605a180503000000005c36b186010021180101ff";
    bytes32 internal constant HOOK_INTERACTION = keccak256("hook-ping");

    function setUp() public {
        _setUpTenant();
        _configureTenant();
        attackerDelegate = new AttackerDelegate();
    }

    // ------------------------------------------------------------------------------------------
    // 1. Forged actor signature (ERC-1271 path of SignatureChecker)
    // ------------------------------------------------------------------------------------------

    /// @notice Control: with carol a plain EOA, a garbage signature for her is rejected.
    function test_control_forgedSignatureRejectedForPlainEOA() public {
        uint256[] memory args = _transferArgs(attacker, 1_000e6);
        vm.prank(attacker);
        vm.expectRevert(bytes4(keccak256("InvalidActorSignature()")));
        interact.directExecuteFromAccount(
            vault, OPS_POLICY, TRANSFER_INTERACTION, args, 10_000, 0, block.timestamp + 1 hours, carol, hex"deadbeef"
        );
    }

    /// @notice carol's key signs ONE 7702 authorization. After that the attacker, who is not a
    ///         Chainwall user and never touches carol's key again, drains the vault with a
    ///         garbage "signature", because the signature check asks carol's delegate code.
    function test_attack_forgedSignatureAfterDelegation() public {
        _delegate(carolPk, carol, address(attackerDelegate));

        uint256[] memory args = _transferArgs(attacker, 1_000e6);
        vm.prank(attacker);
        try interact.directExecuteFromAccount(
            vault, OPS_POLICY, TRANSFER_INTERACTION, args, 10_000, 0, block.timestamp + 1 hours, carol, hex"deadbeef"
        ) {
            console2.log("attack executed: forged signature accepted");
        } catch {
            console2.log("attack refused");
        }
        console2.log("attacker USDC", IERC20(USDC).balanceOf(attacker));
        console2.log("vault USDC   ", IERC20(USDC).balanceOf(vault));
        assertEq(IERC20(USDC).balanceOf(attacker), 0, "VULNERABLE: forged signature for a delegated actor drained the vault");
        assertEq(IERC20(USDC).balanceOf(vault), 1_000e6, "vault balance changed");
    }

    // ------------------------------------------------------------------------------------------
    // 2. msg.sender paths driven by delegate code
    // ------------------------------------------------------------------------------------------

    /// @notice After one delegation the attacker makes carol's address call propose and execute.
    ///         No signature is involved at all: Interact sees msg.sender == carol.
    function test_attack_delegateCodeActsAsMsgSender() public {
        _delegate(carolPk, carol, address(attackerDelegate));

        uint256[] memory args = _transferArgs(attacker, 1_000e6);
        uint256 deadline = block.timestamp + 1 days;
        bytes32 payloadHash = interact.getPayloadHash(TRANSFER_INTERACTION, args, OPS_POLICY, deadline, 0, vault);

        vm.startPrank(attacker);
        try AttackerDelegate(carol).exec(
            address(interact), abi.encodeCall(interact.propose, (payloadHash, OPS_POLICY, deadline, 0, vault))
        ) returns (bytes memory ret) {
            uint256 opId = abi.decode(ret, (uint256));
            console2.log("attack step 1: proposed as carol, operation", opId);
            try AttackerDelegate(carol).exec(
                address(interact),
                abi.encodeCall(interact.executeFromAccount, (opId, TRANSFER_INTERACTION, args, 10_000))
            ) {
                console2.log("attack step 2: executed as carol");
            } catch {
                console2.log("execute refused");
            }
        } catch {
            console2.log("propose refused");
        }
        vm.stopPrank();

        console2.log("attacker USDC", IERC20(USDC).balanceOf(attacker));
        assertEq(IERC20(USDC).balanceOf(attacker), 0, "VULNERABLE: delegate code acted as the actor and drained the vault");
    }

    /// @notice Control: one hijacked approver is one vote. With alice delegated, the attacker can
    ///         propose as alice but cannot meet the 2-of-2 threshold without bob.
    function test_control_oneDelegatedApproverCannotMeetThreshold() public {
        _delegate(alicePk, alice, address(attackerDelegate));

        uint256[] memory args = _transferArgs(attacker, 1_000e6);
        uint256 deadline = block.timestamp + 1 days;
        bytes32 payloadHash = interact.getPayloadHash(TRANSFER_INTERACTION, args, TREASURY_POLICY, deadline, 0, vault);

        vm.startPrank(attacker);
        uint256 opId;
        try AttackerDelegate(alice).exec(
            address(interact), abi.encodeCall(interact.propose, (payloadHash, TREASURY_POLICY, deadline, 0, vault))
        ) returns (bytes memory ret) {
            opId = abi.decode(ret, (uint256));
            try AttackerDelegate(alice).exec(
                address(interact),
                abi.encodeCall(interact.executeFromAccount, (opId, TRANSFER_INTERACTION, args, 10_000))
            ) {
                console2.log("executed with one approval");
            } catch {
                console2.log("execute refused: threshold not met");
            }
        } catch {
            console2.log("propose refused");
        }
        vm.stopPrank();
        assertEq(IERC20(USDC).balanceOf(attacker), 0, "one hijacked approver moved funds past a 2-of-2 policy");
    }

    // ------------------------------------------------------------------------------------------
    // 3. Direct capability actors
    // ------------------------------------------------------------------------------------------

    /// @notice Control: on a factory-deployed tenant, direct capability actors are locked during
    ///         deployment, so an EOA cannot be given a dormant direct capability to activate later.
    function test_control_directActorGrantsLockedAfterDeployment() public {
        vm.prank(tenantOwner);
        vm.expectRevert(bytes4(keccak256("ActorGrantsLocked()")));
        reg.grantCapabilityActor(ACCOUNT_MANAGER, carol);
    }

    // ------------------------------------------------------------------------------------------
    // 4. Delegated EOA accepted as a contract target
    // ------------------------------------------------------------------------------------------

    function _registerHook(address target) internal {
        vm.startPrank(tenantOwner);
        reg.upsertOrg("acme", tenantOwner, false, new address[](0));
        reg.addContractVersion("acme", "hook", ContractAddress(target, bytes32("1"), address(0)), bytes32(0));
        _publishInteraction(HOOK_INTERACTION, HOOK_SCRIPT);
        vm.stopPrank();
    }

    /// @notice Control: a target with no code is refused by the engine.
    function test_control_targetWithoutCodeRefused() public {
        address plain = makeAddr("chainwall-test plain target");
        _registerHook(plain);
        vm.prank(carol);
        vm.expectRevert();
        interact.directExecuteFromAccount(
            vault, OPS_POLICY, HOOK_INTERACTION, new uint256[](0), 10_000, 0, 0, carol, ""
        );
    }

    /// @notice The realistic bypass: an address is registered while it is a plain EOA (registration
    ///         does not require code), and delegates afterwards. Without the fix the engine's
    ///         "target has code" check then passes and the vault calls whatever code the key holder
    ///         points the address at, with no Registry timelock involved.
    function test_attack_delegatedEOAAcceptedAsTarget() public {
        (address dave, uint256 davePk) = makeAddrAndKey("chainwall-test dave");
        _requirePlainEOA(dave);
        _registerHook(dave);
        _delegate(davePk, dave, address(new HookImpl()));

        bool executed;
        vm.prank(carol);
        try interact.directExecuteFromAccount(
            vault, OPS_POLICY, HOOK_INTERACTION, new uint256[](0), 10_000, 0, 0, carol, ""
        ) {
            executed = true;
            console2.log("vault called a delegated EOA as a registered contract");
        } catch {
            console2.log("delegated target refused");
        }
        assertFalse(executed, "VULNERABLE: a 7702-delegated EOA was accepted as a contract target");
    }

    /// @notice A delegated EOA must not be registrable as a contract in the first place.
    function test_attack_delegatedEOARegisteredAsContract() public {
        (address dave, uint256 davePk) = makeAddrAndKey("chainwall-test dave");
        _delegate(davePk, dave, address(new HookImpl()));

        vm.startPrank(tenantOwner);
        reg.upsertOrg("acme", tenantOwner, false, new address[](0));
        bool registered;
        try reg.addContractVersion("acme", "hook", ContractAddress(dave, bytes32("1"), address(0)), bytes32(0)) {
            registered = true;
        } catch (bytes memory reason) {
            assertEq(reason, abi.encodeWithSignature("ContractAddressDelegated(address)", dave), "wrong revert");
        }
        vm.stopPrank();
        assertFalse(registered, "VULNERABLE: a 7702-delegated EOA was registered as a contract");
    }
}
