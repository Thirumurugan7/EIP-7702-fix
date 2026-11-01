// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @title DiamondAdminStorage
/// @notice Namespaced storage for diamond admin flags.
library DiamondAdminStorage {
    /// @dev Namespace key for dispatcher admin state.
    bytes32 internal constant SLOT = keccak256("okc.storage.diamond.admin");

    /// @notice Dispatcher-level admin state shared across registry upgrades.
    struct Layout {
        /// @notice Permanent switch that blocks future facet cuts.
        bool cutsFrozen;
        /// @notice One-way switch that routes governed role grants/revokes through capabilities and timelock.
        /// @dev Does not configure timelock delays; category defaults stay explicit registry configuration.
        bool roleGovernanceEnabled;
        /// @notice Whether the factory-only immediate ownership handover was consumed.
        bool ownershipHandoverCompleted;
        /// @notice One-way switch disabling owner-derived Registry governance authority.
        bool ownerBootstrapFinalized;
        /// @notice Depth counter used to distinguish explicit self-calls from accidental recursion.
        uint256 selfCallDepth;
    }

    /// @notice Return the diamond admin storage layout for the active registry instance.
    function state() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }
}
