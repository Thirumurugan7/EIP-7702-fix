// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @title InteractionFlags
/// @notice Bit flags stored alongside registry interactions.
/// @dev These flags let the registry and runtime agree on interaction state
///      without changing the interaction bytecode itself.
library InteractionFlags {
    /// @notice Interaction is stored but unavailable for runtime execution.
    uint256 internal constant INACTIVE = 1 << 1;

    /// @notice Opts approvals into following live executable catalog state.
    /// @dev Without this flag, operation hashes and direct signatures bind the
    ///      current script/private commit, CALLI dependencies, resolved target
    ///      configuration, and complete policy configuration. With this flag,
    ///      approvals intentionally follow interaction/contract/token changes,
    ///      but policy criteria and program remain pinned.
    ///      Use only when approving an interaction identity rather than exact
    ///      executable state is the intended security boundary.
    uint256 internal constant UNPINNED_APPROVALS = 1 << 2;

    /// @notice Bitmask of every currently-supported flag.
    /// @dev Registry write paths validate incoming flags against this mask so
    ///      unknown bits cannot silently change future behavior.
    uint256 internal constant MASK = INACTIVE | UNPINNED_APPROVALS;

    function isInactive(uint256 flags) internal pure returns (bool) {
        return flags & INACTIVE != 0;
    }

    function hasUnpinnedApprovals(uint256 flags) internal pure returns (bool) {
        return flags & UNPINNED_APPROVALS != 0;
    }

    function setActive(uint256 flags, bool active) internal pure returns (uint256) {
        return active ? flags & ~INACTIVE : flags | INACTIVE;
    }
}
