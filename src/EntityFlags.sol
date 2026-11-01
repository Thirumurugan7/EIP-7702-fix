// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @title EntityFlags
/// @notice Shared bit flags for registry entities that can be activated or deactivated.
library EntityFlags {
    /// @notice Entity is stored but unavailable for runtime resolution/execution.
    uint256 internal constant INACTIVE = 1 << 1;

    /// @notice Bitmask of every currently-supported contract/token entity flag.
    uint256 internal constant MASK = INACTIVE;

    function isInactive(uint256 flags) internal pure returns (bool) {
        return flags & INACTIVE != 0;
    }

    function setActive(uint256 flags, bool active) internal pure returns (uint256) {
        return active ? flags & ~INACTIVE : flags | INACTIVE;
    }
}
