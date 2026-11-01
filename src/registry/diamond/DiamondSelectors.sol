// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @title DiamondSelectors
/// @notice Selector inventories that define the Registry's hybrid UUPS/diamond boundary.
/// @dev Direct selectors execute in RegistryDiamond before fallback dispatch. They are
///      therefore immutable to diamond cuts, although a governed UUPS upgrade can
///      still change their implementation.
library DiamondSelectors {
    bytes private constant _CORE_SELECTORS = hex"1f931c1c7a0ed627adfca15e52ef6b2ccdffacc6c799ece5e293bf6c";

    // Ordered, four-byte selector inventory for functions implemented directly by
    // RegistryDiamond. Packing avoids duplicating a long comparison tree in every
    // facet that validates or reports the immutable dispatcher surface.
    bytes private constant _DIRECT_SELECTORS =
        hex"75b238fc79ba5097a217fddff72c0d8bad3cb1ccf04e283e168fefc00df9a711ba4e520bfa7428deb63e11856733f2f0248a9ca32f2ff15d91d148548129fc1c58366f45ac9650d88da5cb5b8456cb59e30c39785c975abb52d1902dca5a0fae715018a636568abed547741fba2ae384b915554e01ffc9a7f2fde38b3f4ba83a4f1ef28610ddd8dc04e4ffb1f27c07b3a6d953172561f1b0df84bc99758a7549d7f4e94651bad0aa";

    function isCore(bytes4 selector) internal pure returns (bool) {
        return _contains(_CORE_SELECTORS, selector);
    }

    function isDirect(bytes4 selector) internal pure returns (bool) {
        return _contains(_DIRECT_SELECTORS, selector);
    }

    function _contains(bytes memory packed, bytes4 selector) private pure returns (bool) {
        for (uint256 offset = 0; offset < packed.length;) {
            bytes4 candidate;
            assembly ("memory-safe") {
                candidate := mload(add(add(packed, 0x20), offset))
            }
            if (candidate == selector) return true;
            // Only the fixed, four-byte-aligned inventories above reach this loop.
            unchecked {
                offset += 4;
            }
        }
        return false;
    }

    function directSelectors() internal pure returns (bytes4[] memory selectors) {
        bytes memory packed = _DIRECT_SELECTORS;
        selectors = new bytes4[](packed.length / 4);
        for (uint256 i; i < selectors.length; ++i) {
            bytes4 selector;
            assembly ("memory-safe") {
                selector := mload(add(add(packed, 0x20), mul(i, 4)))
            }
            selectors[i] = selector;
        }
    }
}
