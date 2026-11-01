// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/**
 * @title KeccakHelpers
 * @notice Optimized keccak helpers shared by the diamond and facets.
 * @dev These routines avoid intermediate allocations and use inline assembly
 *      to concatenate and hash identifiers deterministically.
 */
library KeccakHelpers {
    error IdentifierContainsSlash();

    bytes32 internal constant CAPABILITY_ACTOR_SCOPE_TAG =
        0x56dbc22572ae0f5a75a7f74d599fef7d26da6767b0e26260668620fd81737979;

    /// @notice Returns keccak256(s) over the raw string bytes.
    /// @param s Input string.
    /// @return h keccak256 hash of the string.
    function stringHash(string memory s) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            h := keccak256(add(s, 0x20), mload(s))
        }
    }

    /// @notice Returns keccak256(abi.encodePacked(a, "/", b)).
    /// @dev Writes a, one byte '/', then b into a scratch buffer before hashing.
    /// @param a Left label (e.g., org).
    /// @param b Right label (e.g., id).
    /// @return h keccak256 of the concatenation.
    function joinSlash(string memory a, string memory b) internal pure returns (bytes32 h) {
        requireNoSlash(a);
        requireNoSlash(b);
        assembly ("memory-safe") {
            let al := mload(a)
            let bl := mload(b)
            let total := add(add(al, bl), 1)
            let ptr := mload(0x40)
            // copy a
            {
                let src := add(a, 0x20)
                let end := add(src, al)
                for { let off := 0 } lt(add(src, off), end) { off := add(off, 0x20) } {
                    mstore(add(ptr, off), mload(add(src, off)))
                }
            }
            // '/'
            mstore8(add(ptr, al), 0x2f)
            // copy b
            {
                let src2 := add(b, 0x20)
                let dst2 := add(add(ptr, al), 1)
                let end2 := add(src2, bl)
                for { let off2 := 0 } lt(add(src2, off2), end2) { off2 := add(off2, 0x20) } {
                    mstore(add(dst2, off2), mload(add(src2, off2)))
                }
            }
            h := keccak256(ptr, total)
            mstore(0x40, add(ptr, and(add(total, 31), not(31))))
        }
    }

    /// @notice Returns keccak256(abi.encodePacked("token/", org, "/", id)).
    /// @dev Used to namespace token submitter keys in Authority storage to avoid collision with contract submitter.
    /// @param org Organization identifier.
    /// @param id Token identifier.
    /// @return h Namespaced keccak256 hash.
    function tokenAuthKey(string memory org, string memory id) internal pure returns (bytes32 h) {
        requireNoSlash(org);
        requireNoSlash(id);
        assembly ("memory-safe") {
            let al := mload(org)
            let bl := mload(id)
            let total := add(add(al, bl), 7) // len("token/") + '/'
            let ptr := mload(0x40)
            // write "token/" (6 bytes)
            mstore(ptr, 0x746f6b656e2f00000000000000000000000000000000000000000000000000)
            // copy org
            {
                let src := add(org, 0x20)
                let dst := add(ptr, 6)
                let end := add(src, al)
                for { let off := 0 } lt(add(src, off), end) { off := add(off, 0x20) } {
                    mstore(add(dst, off), mload(add(src, off)))
                }
            }
            // '/'
            mstore8(add(add(ptr, 6), al), 0x2f)
            // copy id
            {
                let src2 := add(id, 0x20)
                let dst2 := add(add(add(ptr, 6), al), 1)
                let end2 := add(src2, bl)
                for { let off2 := 0 } lt(add(src2, off2), end2) { off2 := add(off2, 0x20) } {
                    mstore(add(dst2, off2), mload(add(src2, off2)))
                }
            }
            h := keccak256(ptr, total)
            mstore(0x40, add(ptr, and(add(total, 31), not(31))))
        }
    }

    function capabilityScope(bytes32 capability, bytes32 groupHash, bool grantOp) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, capability)
            mstore(add(ptr, 0x20), groupHash)
            mstore(add(ptr, 0x40), grantOp)
            h := keccak256(ptr, 0x60)
            mstore(0x40, add(ptr, 0x60))
        }
    }

    /// @notice Returns keccak256(abi.encode(tag, capability, actor, grantOp)).
    /// @dev Tag ensures actor scopes never collide with group scopes.
    function capabilityActorScope(bytes32 capability, address actor, bool grantOp) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, CAPABILITY_ACTOR_SCOPE_TAG)
            mstore(add(ptr, 0x20), capability)
            mstore(add(ptr, 0x40), actor)
            mstore(add(ptr, 0x60), grantOp)
            h := keccak256(ptr, 0x80)
            mstore(0x40, add(ptr, 0x80))
        }
    }

    /// @dev Slash is the on-chain namespace delimiter. Allowing it inside a
    ///      component makes distinct `(left, right)` pairs hash identically.
    function requireNoSlash(string memory value) internal pure {
        bytes memory raw = bytes(value);
        for (uint256 i; i < raw.length; ++i) {
            // Every namespace byte must exclude slash; skipping a delimiter would admit ambiguous identifiers.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (raw[i] == 0x2f) revert IdentifierContainsSlash();
        }
    }
}
