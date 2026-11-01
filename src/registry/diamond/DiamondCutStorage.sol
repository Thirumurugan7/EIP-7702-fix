// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @title DiamondCutStorage
/// @notice Namespaced commitments for timelocked diamond cuts.
library DiamondCutStorage {
    bytes32 internal constant SLOT = keccak256("okc.storage.diamond.cut");

    struct Layout {
        /// @notice Hash of every proposed facet/init runtime code hash, keyed by action id.
        mapping(bytes32 => bytes32) queuedCodeCommitment;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }
}
