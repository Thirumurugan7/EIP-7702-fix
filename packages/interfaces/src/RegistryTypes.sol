// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @title RegistryTypes
/// @notice Public ABI records shared by Chainwall contracts and integrations.

/// @notice Criteria specifying a group and its threshold for a policy.
/// @param groupHash Hash of the group identifier.
/// @param threshold Minimum number of members required.
struct GroupCriteria {
    bytes32 groupHash;
    uint256 threshold;
}

/// @notice Represents a policy composed of group criteria and an optional program.
/// @param id Unique identifier for the policy (non-zero implies existence).
/// @param criteria List of group criteria for the policy.
/// @param program Optional MiniScript policy program bytes.
/// @param programMaxSteps Interpreter step cap for `program`.
/// @param programVersion Monotonic version counter for `program` updates.
/// @param programHash keccak256 hash of `program`.
struct Policy {
    bytes32 id;
    GroupCriteria[] criteria;
    bytes program;
    uint32 programMaxSteps;
    uint64 programVersion;
    bytes32 programHash;
}

/// @notice Represents a deployed contract address and its metadata.
/// @param addr Deployed contract address.
/// @param version Version label as bytes32 (e.g., bytes32("v3.2.1")).
/// @param implementation Last known implementation address.
struct ContractAddress {
    address addr;
    bytes32 version;
    address implementation;
}

/// @notice Lightweight contract record returned by view helpers.
struct ContractRecord {
    string org;
    string id;
    address submitter;
    uint32 latestVersion;
    ContractAddress latest;
}

/// @notice Catalog import kinds tracked in sync provenance.
enum CatalogImportKind {
    None,
    Contract,
    Token,
    Interaction
}

/// @notice Common provenance metadata for an imported catalog record.
struct ImportProvenance {
    address sourceRegistry;
    uint64 importedAt;
    address importedBy;
    bytes32 sourceKeyHash;
    bytes32 sourcePayloadHash;
    CatalogImportKind importKind;
}

/// @notice Active or historical provenance for one imported contract record.
struct ContractImportProvenance {
    ImportProvenance common;
    uint32 sourceVersion;
    bytes32 label;
    uint32 localVersion;
}

/// @notice Active or historical provenance for one imported token record.
struct TokenImportProvenance {
    ImportProvenance common;
}

/// @notice Active or historical provenance for one imported interaction record.
/// @param common Source, importer, timestamp, and import-kind metadata.
/// @param sourceContentHash Activation-independent content hash observed at import.
/// @param sourceBundleHash Complete source bundle hash observed at import.
struct InteractionImportProvenance {
    ImportProvenance common;
    bytes32 sourceContentHash;
    bytes32 sourceBundleHash;
}

/// @notice Reference to a specific contract version.
/// @param contractHash Hash of the contract (org/id).
/// @param version Version number of the contract.
struct InteractionRef {
    bytes32 contractHash;
    uint32 version;
}

/// @notice Represents an ERC token associated with a contract.
/// @param org Organization identifier.
/// @param id Token identifier.
/// @param symbol Token symbol.
/// @param decimals Number of decimals.
/// @param price Price feed contract address.
/// @param priceFeedDecimals Expected decimals reported by the price feed.
/// @dev Submitter is tracked via Authority by the contract hash `keccak256(abi.encodePacked(org,"/",id))`.
// forge-lint: disable-next-line(pascal-case-struct)
struct ERCToken {
    string org;
    string id;
    string symbol; // not unique
    uint8 decimals;
    address price; // ChainLink price feed
    uint8 priceFeedDecimals;
}

// Value spec (V1).
/// @notice Token + quantity entry for computing USD value (V1b compact format).
/// @dev `contractHash` is the keccak256 hash of the token's org/id as used in the registry mapping.
///      `amount` is the token quantity in the token's base units (i.e., `decimals`).
struct ValueTokenV1b {
    bytes32 contractHash;
    uint256 amount;
}

/// @notice Registry-side link from a WebAuthn credential id key to a protocol-user account.
/// @param account Deployed AuthAccount that owns and verifies the credential.
/// @param credHash SHA-256 hash of the WebAuthn credential id (rawId).
/// @param active Whether the registry link is currently usable for lookup.
/// @dev Account-local credential material and WebAuthn verification live in AuthAccount.
struct AuthCredentialLink {
    address account;
    bytes32 credHash;
    bool active;
}

/// @notice Represents an interaction definition.
/// @param id Interaction identifier.
/// @param script MiniScript bytecode for this interaction.
/// @dev Submitter is tracked via Authority by the interaction id (bytes32 key).
struct Interaction {
    bytes32 id;
    bytes script;
    uint256 flags;
}

/// @notice Opaque payload linked atomically to one base interaction.
/// @param relation Versioned relation that defines how a consumer interprets the payload.
/// @param payload Opaque bytes stored under the base interaction's authority.
struct LinkedArtifactInput {
    bytes32 relation;
    bytes payload;
}

/// @notice Complete desired state for one interaction publication.
/// @param id Base interaction identifier.
/// @param script Main MiniScript bytecode.
/// @param flags Interaction flags. INACTIVE is initial-only and preserved on updates.
/// @param linked Strictly sorted complete linked-artifact snapshot.
struct InteractionBundleInput {
    bytes32 id;
    bytes script;
    uint256 flags;
    LinkedArtifactInput[] linked;
}

/// @notice Full reveal payload used by private execution paths.
/// @param bundle Complete interaction snapshot being revealed.
/// @param relatedContracts Canonical related-contract list bound by the commitment.
/// @param salt Secret bound by the commitment.
/// @param signature Optional committer authorization for delegated reveal.
struct StoredBundleRevealPayload {
    InteractionBundleInput bundle;
    bytes32[] relatedContracts;
    bytes32 salt;
    bytes signature;
}

/// @notice Stored linked artifact in the namespace separate from ordinary interactions.
/// @param baseId Base interaction that owns the artifact.
/// @param relation Versioned relation within the base namespace.
/// @param payload Opaque linked payload.
struct LinkedArtifact {
    bytes32 baseId;
    bytes32 relation;
    bytes payload;
}
