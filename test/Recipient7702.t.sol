// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.36;

import {IERC20, TenantFixture} from "./TenantFixture.sol";

contract Sweeper {
    function ping() external {}
}

/// @notice Paying out to a delegated EOA. This is not an authority question (the recipient gains no
///         power over the vault), so the protocol does not forbid it. A tenant that wants to refuse
///         such recipients, for example to avoid paying into an account that was "ambushed" with a
///         sweeper delegate, can say so in a policy program using the Registry's `delegateOf` view.
contract Recipient7702Test is TenantFixture {
    address internal payee;
    uint256 internal payeePk;

    function setUp() public {
        _setUpTenant();
        _configureTenant();
        (payee, payeePk) = makeAddrAndKey("chainwall-test payee");
        _requirePlainEOA(payee);
    }

    /// @dev Output of `miniscript compile test/scripts/recipient-not-delegated.core.ls` (Chainwall CLI
    ///      0.3.1), with the 32-byte Registry placeholder replaced by this tenant's Registry address,
    ///      exactly as the CLI's `__REGISTRY__` template marker does:
    ///        let recipient = $subjectArg(0)
    ///        in $require($read(REGISTRY, delegateOf(address), {recipient}) == 0)
    function _recipientNotDelegatedProgram() internal view returns (bytes memory) {
        return abi.encodePacked(
            hex"01073202", bytes32(uint256(uint160(registry))), hex"03000000008d22ea2a010120010060180101ff"
        );
    }

    function _pay(address to, uint256 amount) internal returns (bool ok) {
        vm.prank(carol);
        try interact.directExecuteFromAccount(
            vault, OPS_POLICY, TRANSFER_INTERACTION, _transferArgs(to, amount), 10_000, 0, 0, carol, ""
        ) {
            ok = true;
        } catch {
            ok = false;
        }
    }

    /// @notice Default behavior, unchanged by the patch: a delegated EOA can be paid.
    function test_default_delegatedRecipientCanBePaid() public {
        _delegate(payeePk, payee, address(new Sweeper()));
        assertTrue(_pay(payee, 100e6), "payout failed");
        assertEq(IERC20(USDC).balanceOf(payee), 100e6);
    }

    /// @notice With the recipient policy attached: plain recipients are paid, delegated ones refused.
    function test_policy_refusesDelegatedRecipient() public {
        vm.prank(tenantOwner);
        reg.setPolicyProgram(OPS_POLICY, _recipientNotDelegatedProgram(), 10_000);

        assertTrue(_pay(recipient, 100e6), "plain recipient must still be paid");
        assertEq(IERC20(USDC).balanceOf(recipient), 100e6);

        _delegate(payeePk, payee, address(new Sweeper()));
        assertFalse(_pay(payee, 100e6), "delegated recipient was paid despite the policy");
        assertEq(IERC20(USDC).balanceOf(payee), 0);

        _clearDelegation(payeePk, payee);
        assertTrue(_pay(payee, 100e6), "recipient is payable again once the delegation is cleared");
        assertEq(IERC20(USDC).balanceOf(payee), 100e6);
    }
}
