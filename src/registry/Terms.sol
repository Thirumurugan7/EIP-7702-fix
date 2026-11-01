// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {IFactoryTerms} from "@chainwall/interfaces/IFactoryTerms.sol";
import {IRegistryTerms} from "@chainwall/interfaces/IRegistryTerms.sol";
import {AcceptanceRecord, TermsDocument} from "@chainwall/interfaces/TermsTypes.sol";

library TermsDocumentLib {
    error TermsDocumentHashZero();
    error TermsIpfsUriInvalid();

    /// @notice SHA-256 and raw CIDv1 of the exact checked-in config/terms/chainwall-V2.md bytes.
    /// @dev This default cannot be supplied by a factory deployer or changed by a publisher.
    function initial() internal pure returns (TermsDocument memory) {
        return TermsDocument(
            "ipfs://bafkreiga2c3ags3zofsi76btf5aaeem3bm4tldhijveglkibah6ceiflqa",
            0xc0d0b6034b7971648ff8332f4002119b0b39358ce84d4865a90101fc2220ab80
        );
    }

    /// @dev Clients additionally validate the CID/path and SHA-256 of retrieved bytes.
    function validate(string memory ipfsUri, bytes32 documentHash) internal pure {
        if (documentHash == bytes32(0)) revert TermsDocumentHashZero();
        bytes memory uri = bytes(ipfsUri);
        if (uri.length <= 7 || uri.length > 4096) revert TermsIpfsUriInvalid();
        bytes memory prefix = "ipfs://";
        for (uint256 i; i < prefix.length; ++i) {
            // All seven prefix bytes must match ipfs://; partial matching cannot validate a document URI.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (uri[i] != prefix[i]) revert TermsIpfsUriInvalid();
        }
    }
}

/// @notice Fresh-deployment storage, separate from the former authority/version layout.
library TermsStorage {
    bytes32 internal constant SLOT = keccak256("okc.storage.terms.factory");

    struct Layout {
        address factory;
        TermsDocument initialTerms;
        mapping(bytes32 => AcceptanceRecord) acceptedTerms;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }

    function hasAcceptedTerms(Layout storage l, bytes32 documentHash) internal view returns (bool) {
        return l.acceptedTerms[documentHash].acceptedBy != address(0);
    }
}
