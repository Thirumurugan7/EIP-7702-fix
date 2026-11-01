// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/**
 * @title RegistryTypes
 * @notice Data structures for the OKcontract registry, defining users, groups, policies, contracts, tokens, and interactions.
 */
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {
    AuthCredentialLink,
    CatalogImportKind,
    ContractAddress,
    ContractImportProvenance,
    ContractRecord,
    ERCToken,
    GroupCriteria,
    ImportProvenance,
    Interaction,
    InteractionBundleInput,
    InteractionImportProvenance,
    InteractionRef,
    LinkedArtifact,
    LinkedArtifactInput,
    Policy,
    StoredBundleRevealPayload,
    TokenImportProvenance,
    ValueTokenV1b
} from "@chainwall/interfaces/RegistryTypes.sol";

/// @notice Represents a group of users within the registry.
/// @param id Canonical 32-byte identifier (opaque, may be encrypted client-side).
/// @param members Set of Ethereum addresses belonging to the group.
/// @dev Existence is inferred by `id != bytes32(0)`.
struct Group {
    bytes32 id;
    EnumerableSet.AddressSet members;
}

/// @notice Represents a smart contract in the registry.
/// @param org Organization identifier.
/// @param id Contract identifier.
/// @param versions Mapping from version number to contract address data.
/// @param latest Latest version number.
/// @param labels Mapping from human-readable labels to version numbers.
/// @dev Submitter is tracked via Authority by `keccak256(abi.encodePacked(org,"/",id))`.
struct DappContract {
    string org;
    string id;
    mapping(uint32 => ContractAddress) versions;
    uint32 latest;
    mapping(bytes32 => uint32) labels;
}

/// @notice Represents an organization in the registry.
/// @param id Organization identifier.
/// @param rugged Flag indicating if the org is rugged.
/// @param members Set of organization member addresses.
/// @dev Owner is tracked via Authority by `keccak256(bytes(id))`.
struct Org {
    string id;
    bool rugged;
    EnumerableSet.AddressSet members;
}
