// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {ContractAddress, ERCToken, InteractionBundleInput} from "../RegistryTypes.sol";
import {InteractionBundleLib} from "./InteractionBundleLib.sol";

/// @title SecretCommitLib
/// @notice Hashing helpers for commit-reveal flows used across the registry.
/// @dev Chainwall uses commit-reveal when operators want to reserve an action now
///      but publish the cleartext payload later.
///
///      This library currently supports four commit families:
///      - private interaction publication in `RegistryInteractionsFacet`
///      - private contract publication in `RegistryContractsFacet`
///      - private token publication in `RegistryTokenCommitsFacet`
///      - private recipient allowlists in policy state
///
///      All commits are schema-versioned so future hash formats can be introduced
///      without breaking older commitments.
library SecretCommitLib {
    /// @notice Current schema version encoded into every commitment.
    uint256 internal constant SCHEMA_VERSION = 1;
    /// @notice Typed-data style hash prefix for private contract commitments.
    bytes32 internal constant CONTRACT_COMMIT_TYPEHASH =
        keccak256("ContractCommit(bytes32 key,bytes32 payloadHash,bytes32 salt,uint256 schema)");
    /// @notice Typed-data style hash prefix for private token commitments.
    bytes32 internal constant TOKEN_COMMIT_TYPEHASH =
        keccak256("TokenCommit(bytes32 key,bytes32 payloadHash,bytes32 salt,uint256 schema)");
    /// @notice Typed-data style hash prefix for recipient allowlist commitments.
    bytes32 internal constant RECIPIENT_COMMIT_TYPEHASH =
        keccak256("RecipientCommit(address recipient,bytes32 salt,uint256 schema)");
    /// @notice Schema version for policy- and vault-bound recipient commitments.
    uint256 internal constant RECIPIENT_COMMIT_SCHEMA_V2 = 2;
    /// @notice Typed-data style hash prefix for v2 recipient allowlist commitments.
    bytes32 internal constant RECIPIENT_COMMIT_TYPEHASH_V2 =
        keccak256("RecipientCommitV2(bytes32 policyId,address vault,address recipient,bytes32 mask,uint256 schema)");

    /// @notice Convenience bundle for contract commit inputs.
    struct ContractInputs {
        /// @notice Precomputed contract key, typically `keccak256(org "/" id)`.
        bytes32 key;
        /// @notice Contract payload that will later be revealed.
        ContractAddress addrData;
        /// @notice Optional human-friendly version label.
        bytes32 label;
        /// @notice Secret salt chosen by the committer.
        bytes32 salt;
    }

    /// @notice Convenience bundle for token commit inputs.
    struct TokenInputs {
        /// @notice Precomputed token key, typically `keccak256(org "/" id)`.
        bytes32 key;
        /// @notice Token metadata that will later be revealed.
        ERCToken data;
        /// @notice Token flags that will be installed with the metadata.
        uint256 flags;
        /// @notice Secret salt chosen by the committer.
        bytes32 salt;
    }

    /// @notice Compute the commitment hash for a private interaction reveal.
    /// @dev Validates canonical bundle and related-contract ordering before hashing.
    /// @param bundle Complete interaction snapshot that will be revealed.
    /// @param related Canonical related-contract list bound by the reveal.
    /// @param salt Secret chosen by the committer.
    /// @return Schema-versioned complete-bundle commitment.
    function computeInteractionCommit(InteractionBundleInput calldata bundle, bytes32[] calldata related, bytes32 salt)
        internal
        pure
        returns (bytes32)
    {
        InteractionBundleInput memory bundleMem = bundle;
        bytes32[] memory relatedMem = related;
        InteractionBundleLib.validate(bundleMem);
        InteractionBundleLib.validateRelatedContracts(relatedMem);
        return InteractionBundleLib.commitHash(bundleMem, relatedMem, salt);
    }

    /// @notice Hash the cleartext payload used by private contract publication.
    function hashContractPayload(bytes32 key, ContractAddress calldata addrData, bytes32 label)
        internal
        pure
        returns (bytes32)
    {
        bytes memory encoded = abi.encode(key, addrData.addr, addrData.version, addrData.implementation, label);
        bytes32 digest;
        assembly ("memory-safe") {
            digest := keccak256(add(encoded, 0x20), mload(encoded))
        }
        return digest;
    }

    /// @notice Compute the commitment hash for a private contract reveal.
    function computeContractCommit(bytes32 key, ContractAddress calldata addrData, bytes32 label, bytes32 salt)
        internal
        pure
        returns (bytes32)
    {
        bytes memory encoded = abi.encode(
            CONTRACT_COMMIT_TYPEHASH, key, hashContractPayload(key, addrData, label), salt, SCHEMA_VERSION
        );
        bytes32 digest;
        assembly ("memory-safe") {
            digest := keccak256(add(encoded, 0x20), mload(encoded))
        }
        return digest;
    }

    /// @notice Hash the cleartext payload used by private token publication.
    /// @dev The canonical org/id key binds the identifiers. Flags are part of the
    ///      hidden payload so reveal cannot silently change activation state.
    function hashTokenPayload(bytes32 key, ERCToken calldata data, uint256 flags) internal pure returns (bytes32) {
        bytes memory encoded = abi.encode(key, data.symbol, data.decimals, data.price, data.priceFeedDecimals, flags);
        bytes32 digest;
        assembly ("memory-safe") {
            digest := keccak256(add(encoded, 0x20), mload(encoded))
        }
        return digest;
    }

    /// @notice Compute the commitment hash for a private token reveal.
    function computeTokenCommit(bytes32 key, ERCToken calldata data, uint256 flags, bytes32 salt)
        internal
        pure
        returns (bytes32)
    {
        bytes memory encoded =
            abi.encode(TOKEN_COMMIT_TYPEHASH, key, hashTokenPayload(key, data, flags), salt, SCHEMA_VERSION);
        bytes32 digest;
        assembly ("memory-safe") {
            digest := keccak256(add(encoded, 0x20), mload(encoded))
        }
        return digest;
    }

    /// @notice Compute the commitment hash for a recipient allowlist entry.
    function computeRecipientCommit(address recipient, bytes32 salt) internal pure returns (bytes32) {
        bytes memory encoded = abi.encode(RECIPIENT_COMMIT_TYPEHASH, recipient, salt, SCHEMA_VERSION);
        bytes32 digest;
        assembly ("memory-safe") {
            digest := keccak256(add(encoded, 0x20), mload(encoded))
        }
        return digest;
    }

    /// @notice Compute a policy- and vault-bound recipient allowlist commitment.
    function computeRecipientCommitV2(bytes32 policyId, address vault, address recipient, bytes32 mask)
        internal
        pure
        returns (bytes32)
    {
        bytes memory encoded =
            abi.encode(RECIPIENT_COMMIT_TYPEHASH_V2, policyId, vault, recipient, mask, RECIPIENT_COMMIT_SCHEMA_V2);
        bytes32 digest;
        assembly ("memory-safe") {
            digest := keccak256(add(encoded, 0x20), mload(encoded))
        }
        return digest;
    }
}
