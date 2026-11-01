// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @notice Document identity. The digest is SHA-256 of the exact document bytes.
struct TermsDocument {
    string ipfsUri;
    bytes32 documentHash;
}

/// @notice First acceptance of a document by this instance.
struct AcceptanceRecord {
    address acceptedBy;
    uint64 acceptedAt;
    string ipfsUri;
}

