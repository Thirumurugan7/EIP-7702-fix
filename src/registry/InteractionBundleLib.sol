// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {InteractionFlags} from "../InteractionFlags.sol";
import {InteractionBundleInput, LinkedArtifactInput} from "../RegistryTypes.sol";

/// @title InteractionBundleLib
/// @notice Canonical validation and hashing for atomic interaction bundles.
library InteractionBundleLib {
    /// @dev Maximum linked artifacts in one atomic snapshot.
    uint256 internal constant MAX_LINKED_ARTIFACTS = 16;
    /// @dev Maximum bytes in the main interaction program.
    uint256 internal constant MAX_INTERACTION_SCRIPT_BYTES = 8_192;
    /// @dev Maximum bytes in one linked payload.
    uint256 internal constant MAX_LINKED_ARTIFACT_BYTES = 8_192;
    /// @dev Maximum main-plus-linked payload bytes in one bundle.
    uint256 internal constant MAX_INTERACTION_BUNDLE_PAYLOAD_BYTES = 16_384;
    /// @dev Maximum related contract identifiers bound by a private commitment.
    uint256 internal constant MAX_PRIVATE_RELATED_CONTRACTS = 128;
    /// @dev Schema version included in every private bundle commitment.
    uint256 internal constant INTERACTION_BUNDLE_COMMIT_SCHEMA = 1;

    bytes32 internal constant LINKED_ARTIFACT_HASH_TYPEHASH =
        keccak256("LinkedArtifactHash(bytes32 relation,bytes32 payloadHash)");
    bytes32 internal constant INTERACTION_CONTENT_TYPEHASH =
        keccak256("InteractionContent(bytes32 id,bytes32 scriptHash,uint256 flags,bytes32 linkedArtifactsHash)");
    bytes32 internal constant INTERACTION_BUNDLE_TYPEHASH =
        keccak256("InteractionBundle(bytes32 contentHash,bool active)");
    bytes32 internal constant INTERACTION_BUNDLE_COMMIT_TYPEHASH = keccak256(
        "InteractionBundleCommit(bytes32 bundleHash,bytes32 relatedContractsHash,bytes32 salt,uint256 schema)"
    );
    bytes32 internal constant INTERACTION_BUNDLE_MISSING_TYPEHASH = keccak256("InteractionBundleMissing(bytes32 id)");
    bytes32 internal constant LINKED_ARTIFACT_BINDING_TYPEHASH =
        keccak256("LinkedArtifactBinding(bytes32 baseId,bytes32 relation,bytes32 payloadHash,bool active)");
    bytes32 internal constant LINKED_ARTIFACT_MISSING_TYPEHASH =
        keccak256("LinkedArtifactMissing(bytes32 baseId,bytes32 relation,bool active)");

    /// @notice Thrown when a bundle uses the zero base identifier.
    error InvalidInteractionId();
    /// @notice Thrown when a bundle contains an unsupported interaction flag.
    error InvalidInteractionFlags();
    /// @notice Thrown when an interaction has no main script.
    error EmptyInteractionScript();
    /// @notice Thrown when the main script exceeds its byte limit.
    error InteractionScriptTooLarge();
    /// @notice Thrown when a bundle contains too many linked artifacts.
    error TooManyLinkedArtifacts();
    /// @notice Thrown when a linked artifact uses the zero relation.
    error InvalidLinkedRelation();
    /// @notice Thrown when linked relations are duplicated or not canonically sorted.
    error LinkedRelationsNotStrictlyIncreasing();
    /// @notice Thrown when a linked artifact payload is empty.
    error EmptyLinkedArtifact();
    /// @notice Thrown when one linked payload exceeds its byte limit.
    error LinkedArtifactTooLarge();
    /// @notice Thrown when aggregate main-plus-linked bytes exceed the bundle limit.
    error InteractionBundleTooLarge();
    /// @notice Thrown when a private commitment lists too many related contracts.
    error TooManyRelatedContracts();
    /// @notice Thrown when a related-contract list contains the zero identifier.
    error InvalidRelatedContract();
    /// @notice Thrown when related contracts are duplicated or not canonically sorted.
    error RelatedContractsNotStrictlyIncreasing();

    /// @notice Validate canonical bundle shape, flags, ordering, and payload bounds.
    /// @param bundle Complete interaction snapshot to validate.
    function validate(InteractionBundleInput memory bundle) internal pure {
        if (bundle.id == bytes32(0)) revert InvalidInteractionId();
        if (bundle.flags & ~InteractionFlags.MASK != 0) revert InvalidInteractionFlags();
        if (bundle.script.length == 0) revert EmptyInteractionScript();
        if (bundle.script.length > MAX_INTERACTION_SCRIPT_BYTES) revert InteractionScriptTooLarge();
        if (bundle.linked.length > MAX_LINKED_ARTIFACTS) revert TooManyLinkedArtifacts();

        uint256 totalBytes = bundle.script.length;
        bytes32 previous = bytes32(0);
        for (uint256 i; i < bundle.linked.length; ++i) {
            LinkedArtifactInput memory linked = bundle.linked[i];
            // The committed bundle requires all payload bounds and canonical ordering; partial validation changes
            // its meaning.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (linked.relation == bytes32(0)) revert InvalidLinkedRelation();
            // The committed bundle requires all payload bounds and canonical ordering; partial validation changes
            // its meaning.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (i != 0 && linked.relation <= previous) revert LinkedRelationsNotStrictlyIncreasing();
            // The committed bundle requires all payload bounds and canonical ordering; partial validation changes
            // its meaning.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (linked.payload.length == 0) revert EmptyLinkedArtifact();
            // The committed bundle requires all payload bounds and canonical ordering; partial validation changes
            // its meaning.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (linked.payload.length > MAX_LINKED_ARTIFACT_BYTES) revert LinkedArtifactTooLarge();
            totalBytes += linked.payload.length;
            // The committed bundle requires all payload bounds and canonical ordering; partial validation changes
            // its meaning.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (totalBytes > MAX_INTERACTION_BUNDLE_PAYLOAD_BYTES) revert InteractionBundleTooLarge();
            previous = linked.relation;
        }
    }

    /// @notice Validate the canonical related-contract list bound by a private reveal.
    /// @param relatedContracts Strictly increasing nonzero contract identifiers.
    function validateRelatedContracts(bytes32[] memory relatedContracts) internal pure {
        if (relatedContracts.length > MAX_PRIVATE_RELATED_CONTRACTS) revert TooManyRelatedContracts();
        bytes32 previous = bytes32(0);
        for (uint256 i; i < relatedContracts.length; ++i) {
            bytes32 related = relatedContracts[i];
            // The committed bundle requires all payload bounds and canonical ordering; partial validation changes
            // its meaning.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (related == bytes32(0)) revert InvalidRelatedContract();
            // The committed bundle requires all payload bounds and canonical ordering; partial validation changes
            // its meaning.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (i != 0 && related <= previous) revert RelatedContractsNotStrictlyIncreasing();
            previous = related;
        }
    }

    /// @notice Derive the deterministic public identity of one base-scoped artifact.
    /// @param baseId Base interaction identifier.
    /// @param relation Versioned relation within the base namespace.
    /// @return Domain identity used for events and collision checks.
    function artifactId(bytes32 baseId, bytes32 relation) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(baseId, relation));
    }

    /// @notice Hash activation-independent interaction content.
    /// @dev The INACTIVE bit is removed because activation has separate governance.
    /// @param bundle Complete interaction snapshot.
    /// @return Canonical content hash of main script, non-activation flags, and linked payloads.
    function contentHash(InteractionBundleInput memory bundle) internal pure returns (bytes32) {
        bytes32[] memory artifactHashes = new bytes32[](bundle.linked.length);
        for (uint256 i; i < bundle.linked.length; ++i) {
            artifactHashes[i] = keccak256(
                abi.encode(
                    LINKED_ARTIFACT_HASH_TYPEHASH, bundle.linked[i].relation, keccak256(bundle.linked[i].payload)
                )
            );
        }
        return keccak256(
            abi.encode(
                INTERACTION_CONTENT_TYPEHASH,
                bundle.id,
                keccak256(bundle.script),
                bundle.flags & ~InteractionFlags.INACTIVE,
                keccak256(abi.encode(artifactHashes))
            )
        );
    }

    /// @notice Hash complete interaction content together with current activation.
    /// @param bundle Complete interaction snapshot.
    /// @return Canonical compare-and-swap bundle hash.
    function bundleHash(InteractionBundleInput memory bundle) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(INTERACTION_BUNDLE_TYPEHASH, contentHash(bundle), !InteractionFlags.isInactive(bundle.flags))
        );
    }

    /// @notice Derive the compare-and-swap sentinel for an absent interaction.
    /// @param id Absent base interaction identifier.
    /// @return Domain-separated missing-bundle hash.
    function missingBundleHash(bytes32 id) internal pure returns (bytes32) {
        return keccak256(abi.encode(INTERACTION_BUNDLE_MISSING_TYPEHASH, id));
    }

    /// @notice Hash one present linked artifact and the base activation state.
    /// @param baseId Base interaction identifier.
    /// @param relation Versioned relation within the base namespace.
    /// @param payload Stored linked payload.
    /// @param active Whether the base interaction is active.
    /// @return Exact linked-artifact approval binding.
    function linkedBindingHash(bytes32 baseId, bytes32 relation, bytes memory payload, bool active)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(LINKED_ARTIFACT_BINDING_TYPEHASH, baseId, relation, keccak256(payload), active));
    }

    /// @notice Hash one missing linked relation and the base activation state.
    /// @param baseId Base interaction identifier.
    /// @param relation Missing relation within the base namespace.
    /// @param active Whether the base interaction is active.
    /// @return Domain-separated missing-artifact binding.
    function missingLinkedHash(bytes32 baseId, bytes32 relation, bool active) internal pure returns (bytes32) {
        return keccak256(abi.encode(LINKED_ARTIFACT_MISSING_TYPEHASH, baseId, relation, active));
    }

    /// @notice Hash the canonical related-contract list for private publication.
    /// @param relatedContracts Strictly increasing related contract identifiers.
    /// @return ABI-encoded list hash.
    function hashRelatedContracts(bytes32[] memory relatedContracts) internal pure returns (bytes32) {
        return keccak256(abi.encode(relatedContracts));
    }

    /// @notice Compute the schema-versioned commitment for one complete private bundle.
    /// @param bundle Complete interaction snapshot to reveal.
    /// @param relatedContracts Canonical related-contract list.
    /// @param salt Secret chosen by the committer.
    /// @return Commitment bound to bundle content, activation, relations, and schema.
    function commitHash(InteractionBundleInput memory bundle, bytes32[] memory relatedContracts, bytes32 salt)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                INTERACTION_BUNDLE_COMMIT_TYPEHASH,
                bundleHash(bundle),
                hashRelatedContracts(relatedContracts),
                salt,
                INTERACTION_BUNDLE_COMMIT_SCHEMA
            )
        );
    }
}
