// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {DiamondLoupeStorage} from "../diamond/DiamondLoupeStorage.sol";
import {DiamondSelectors} from "../diamond/DiamondSelectors.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/// @title IDiamondLoupe (ERC-2535 minimal)
/// @notice Minimal ERC-2535 loupe view exposed by the registry.
interface IDiamondLoupe {
    /// @notice One facet together with the selectors it currently serves.
    struct Facet {
        address facetAddress;
        bytes4[] functionSelectors;
    }

    /// @notice Return every facet and its selector set.
    function facets() external view returns (Facet[] memory facets_);
    /// @notice Return the selector set currently served by `facet`.
    function facetFunctionSelectors(address facet) external view returns (bytes4[] memory facetFunctionSelectors_);
    /// @notice Return every currently installed facet address.
    function facetAddresses() external view returns (address[] memory facetAddresses_);
    /// @notice Return the facet currently serving `functionSelector`, if any.
    function facetAddress(bytes4 functionSelector) external view returns (address facetAddress_);
}

/// @notice OKcontract extensions for facet metadata.
interface IDiamondLoupeExtended is IDiamondLoupe {
    /// @notice Facet address paired with its reported `VERSION()` value.
    struct FacetVersion {
        address facetAddress;
        bool available;
        uint256 version;
    }

    /// @notice Return the `VERSION()` value reported by one facet.
    function facetVersion(address facet) external view returns (uint256 version);
    /// @notice Return every facet with its `VERSION()` value.
    function facetVersions() external view returns (FacetVersion[] memory versions);
}

/// @title DiamondLoupeFacet
/// @notice Read-only enumeration of facets/selectors maintained by the dispatcher.
/// @dev Operators use this facet to inspect live registry composition after upgrades.
contract DiamondLoupeFacet is IDiamondLoupe, IDiamondLoupeExtended {
    using DiamondLoupeStorage for DiamondLoupeStorage.Layout;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    uint256 public constant VERSION = 1;

    /// @notice Return every installed facet together with its selector set.
    function facets() external view returns (Facet[] memory facets_) {
        DiamondLoupeStorage.Layout storage L = DiamondLoupeStorage.getLayout();
        uint256 storedCount = L.facetAddrs.length();
        bool directStored = L.facetAddrs.contains(address(this));
        uint256 n = storedCount + (directStored ? 0 : 1);
        facets_ = new Facet[](n);
        for (uint256 i = 0; i < storedCount;) {
            address fa = L.facetAddrs.at(i);
            bytes4[] memory sels = fa == address(this) ? DiamondSelectors.directSelectors() : _storedSelectors(L, fa);
            facets_[i] = Facet({facetAddress: fa, functionSelectors: sels});
            unchecked {
                ++i;
            }
        }
        if (!directStored) {
            facets_[storedCount] =
                Facet({facetAddress: address(this), functionSelectors: DiamondSelectors.directSelectors()});
        }
    }

    /// @notice Return the selectors currently served by `facet`.
    function facetFunctionSelectors(address facet) external view returns (bytes4[] memory facetFunctionSelectors_) {
        if (facet == address(this)) return DiamondSelectors.directSelectors();
        DiamondLoupeStorage.Layout storage L = DiamondLoupeStorage.getLayout();
        return _storedSelectors(L, facet);
    }

    /// @notice Return every currently installed facet address.
    function facetAddresses() external view returns (address[] memory facetAddresses_) {
        DiamondLoupeStorage.Layout storage L = DiamondLoupeStorage.getLayout();
        uint256 storedCount = L.facetAddrs.length();
        bool directStored = L.facetAddrs.contains(address(this));
        uint256 n = storedCount + (directStored ? 0 : 1);
        facetAddresses_ = new address[](n);
        for (uint256 i = 0; i < storedCount;) {
            facetAddresses_[i] = L.facetAddrs.at(i);
            unchecked {
                ++i;
            }
        }
        if (!directStored) facetAddresses_[storedCount] = address(this);
    }

    /// @notice Return the facet currently serving `functionSelector`, if any.
    function facetAddress(bytes4 functionSelector) external view returns (address facetAddress_) {
        if (DiamondSelectors.isDirect(functionSelector)) return address(this);
        facetAddress_ = DiamondLoupeStorage.getLayout().selectorToFacet[functionSelector];
    }

    /// @notice Returns the VERSION() value exposed by a facet.
    function facetVersion(address facet) public view returns (uint256 version) {
        if (facet.code.length == 0) revert("FacetVersion:no code");
        (bool available, uint256 value) = _tryFacetVersion(facet);
        if (!available) revert("FacetVersion:query failed");
        return value;
    }

    /// @notice Returns all facet addresses with their VERSION() values.
    function facetVersions() external view returns (FacetVersion[] memory versions) {
        DiamondLoupeStorage.Layout storage L = DiamondLoupeStorage.getLayout();
        uint256 storedCount = L.facetAddrs.length();
        bool directStored = L.facetAddrs.contains(address(this));
        uint256 n = storedCount + (directStored ? 0 : 1);
        versions = new FacetVersion[](n);
        for (uint256 i = 0; i < n;) {
            address fa = i < storedCount ? L.facetAddrs.at(i) : address(this);
            (bool available, uint256 version) = _tryFacetVersion(fa);
            versions[i] = FacetVersion({facetAddress: fa, available: available, version: version});
            unchecked {
                ++i;
            }
        }
    }

    function _storedSelectors(DiamondLoupeStorage.Layout storage L, address facet)
        private
        view
        returns (bytes4[] memory selectors)
    {
        uint256 n = L.selectorsOf[facet].length();
        selectors = new bytes4[](n);
        for (uint256 i = 0; i < n;) {
            selectors[i] = DiamondLoupeStorage._b4(L.selectorsOf[facet].at(i));
            unchecked {
                ++i;
            }
        }
    }

    function _tryFacetVersion(address facet) private view returns (bool available, uint256 version) {
        if (facet.code.length == 0) return (false, 0);
        // VERSION is queried through STATICCALL; unavailable versions return an explicit false result without
        // changing state.
        // forge-lint: disable-next-line(calls-loop)
        (bool ok, bytes memory ret) = facet.staticcall(abi.encodeWithSignature("VERSION()"));
        if (!ok || ret.length < 32) return (false, 0);
        return (true, abi.decode(ret, (uint256)));
    }
}
