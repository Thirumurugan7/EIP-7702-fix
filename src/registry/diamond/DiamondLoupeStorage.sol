// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/// @title DiamondLoupeStorage
/// @notice Namespaced storage for facet enumeration and selector mapping.
/// @dev The namespace predates ERC-7201 and must not be changed to the ERC-7201
///      derivation formula because doing so would move deployed Registry state.
library DiamondLoupeStorage {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @dev Namespace key for the loupe storage layout.
    bytes32 internal constant SLOT = keccak256("okc.storage.diamond.loupe");

    /// @notice Loupe state used to enumerate facets and selectors.
    struct Layout {
        /// @notice Set of facet addresses currently installed on the registry.
        EnumerableSet.AddressSet facetAddrs;
        /// @notice Mapping from facet address to the selectors it currently serves.
        mapping(address => EnumerableSet.Bytes32Set) selectorsOf;
        /// @notice Reverse mapping used by the ERC-2535 `facetAddress` query.
        mapping(bytes4 => address) selectorToFacet;
        /// @notice Runtime code hash approved when a facet was installed.
        /// @dev Fallback dispatch checks this value so mutable-code chains fail closed
        ///      if code changes at the approved facet address. This does not pin
        ///      behavior reached transitively through a proxy or delegatecall;
        ///      production facets must therefore be reviewed as immutable direct
        ///      implementations unless governance explicitly accepts that trust.
        mapping(address => bytes32) codehashOf;
    }

    /// @notice Return the loupe storage layout for the active registry instance.
    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Cast a stored `bytes32` set entry back into a selector.
    function _b4(bytes32 x) internal pure returns (bytes4 y) {
        // casting to 'bytes4' to obtain a selector
        // forge-lint: disable-next-line(unsafe-typecast)
        return bytes4(x);
    }

    /// @notice Cast a selector into its `bytes32` set representation.
    function _b32(bytes4 x) internal pure returns (bytes32 y) {
        return bytes32(x);
    }
}
