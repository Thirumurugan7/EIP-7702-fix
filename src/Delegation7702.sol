// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @title Delegation7702
/// @notice Detects EIP-7702 delegation designators.
/// @dev A delegated EOA's code is exactly 23 bytes: `0xef0100 || delegate`. EXTCODESIZE, EXTCODECOPY and
///      EXTCODEHASH operate on that designator, while CALL executes the delegate's code in the EOA's
///      context. EIP-3541 forbids deploying contract code that starts with 0xef, so a 23-byte code with
///      this prefix can only be a designator.
///
///      Two consequences matter to Chainwall:
///      - `account.code.length != 0` does not mean "is a contract": a delegated EOA still has a private
///        key, and its behavior can be replaced with one signed authorization.
///      - ERC-1271 validation of such an account asks the delegate's code, not the key.
library Delegation7702 {
    uint256 internal constant DESIGNATOR_LENGTH = 23;
    uint256 private constant DESIGNATOR_PREFIX = 0xef0100;

    /// @notice Return the delegate of `account`, or zero when `account` carries no EIP-7702 delegation.
    function delegateOf(address account) internal view returns (address delegate) {
        assembly ("memory-safe") {
            if eq(extcodesize(account), 23) {
                // Scratch space: the 23 code bytes occupy the high bytes of the word at 0x00.
                mstore(0x00, 0)
                extcodecopy(account, 0x00, 0, 23)
                let word := mload(0x00)
                if eq(shr(232, word), DESIGNATOR_PREFIX) {
                    delegate := and(shr(72, word), 0xffffffffffffffffffffffffffffffffffffffff)
                }
            }
        }
    }

    /// @notice Return whether `account` is an EOA that currently delegates to contract code.
    function isDelegated(address account) internal view returns (bool) {
        return delegateOf(account) != address(0);
    }

    /// @notice Return whether `account` has deployed contract code of its own.
    /// @dev Use instead of `account.code.length != 0` wherever the question is "is this a contract".
    ///      One EXTCODESIZE for every account; the 3-byte prefix is read only for 23-byte code.
    function hasContractCode(address account) internal view returns (bool own) {
        assembly ("memory-safe") {
            let size := extcodesize(account)
            own := iszero(iszero(size))
            if eq(size, 23) {
                mstore(0x00, 0)
                extcodecopy(account, 0x00, 0, 3)
                if eq(shr(232, mload(0x00)), DESIGNATOR_PREFIX) { own := 0 }
            }
        }
    }
}
