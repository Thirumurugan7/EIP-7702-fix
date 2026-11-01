// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {ERCToken, InteractionBundleInput} from "./RegistryTypes.sol";

/// @title Minimal external Registry interface
/// @notice Subset used by out-of-tree contracts when linking against the Registry.
/// @dev Runtime contracts such as `Interact`, `MiniScriptEngine`, and tenant helpers intentionally depend on this
///      slim interface so they can resolve addresses and interaction scripts without importing every facet type.
interface IRegistry {
    /// @notice Return the revision of Registry state that can affect interaction execution.
    function getExecutionCatalogVersion() external view returns (uint64);
    /// @notice Return the revision of shared runtime semantics and global price configuration.
    function getExecutionRuntimeVersion() external view returns (uint64);
    /// @notice Return the live revision used to reject Registry semantic changes during one execution transaction.
    /// @dev Unlike approval bindings, this revision is sampled at execution time and is not persisted in an intent.
    function getExecutionSemanticsRevision() external view returns (uint64);
    /// @notice Resolve the latest address for a precomputed (org/id) key.
    function getAddressByHash(bytes32 h) external view returns (address);
    /// @notice Batch resolve addresses by keys.
    function getAddressesByHash(bytes32[] calldata hs) external view returns (address[] memory addrs, bool[] memory ok);
    /// @notice Return token metadata for a precomputed contract key.
    /// @dev An empty `id` means the key is not registered as a token.
    function getTokenByHash(bytes32 h) external view returns (ERCToken memory);
    /// @notice Return whether a precomputed contract key has a token record.
    function isTokenByHash(bytes32 h) external view returns (bool);
    /// @notice Return the activation flags for a precomputed contract key.
    function getContractFlagsByHash(bytes32 h) external view returns (uint256);
    /// @notice Return the activation flags for a precomputed token key.
    function getTokenFlagsByHash(bytes32 h) external view returns (uint256);
    /// @notice Return the exact conservative USD18 value of a token amount.
    /// @param tokenHash Precomputed active token key.
    /// @param amount Amount in the token's native decimals.
    /// @param maxAge Required nonzero freshness bound in seconds.
    /// @return Exact-ceiling USD value scaled to 18 decimals.
    function getTokenUsdValue18Ceil(bytes32 tokenHash, uint256 amount, uint256 maxAge) external view returns (uint256);
    /// @notice Return the exact conservative USD18 value of native wei.
    /// @param amountWei Native value in wei.
    /// @param maxAge Required nonzero freshness bound in seconds.
    /// @return Exact-ceiling USD value scaled to 18 decimals.
    function getNativeUsdValue18Ceil(uint256 amountWei, uint256 maxAge) external view returns (uint256);
    /// @notice Return the native USD feed and its Registry-bound decimal count.
    /// @return feed Configured Chainlink-compatible feed, or zero when unset.
    /// @return priceFeedDecimals Decimal count governance bound to `feed`.
    function getNativeUsdFeedConfig() external view returns (address feed, uint8 priceFeedDecimals);
    /// @notice Return the reviewed heartbeat/max age for one price feed.
    /// @param feed Chainlink-compatible feed address.
    /// @return Maximum accepted age in seconds, or zero when the feed is disabled.
    function getFeedMaxAge(address feed) external view returns (uint64);
    /// @notice Return the optional global maximum feed staleness in seconds.
    /// @return Maximum age in seconds, or zero when globally disabled.
    function getMaxFeedStaleness() external view returns (uint256);
    /// @notice Return the stored script for an interaction key.
    function getInteractionScript(bytes32 key) external view returns (bytes memory);
    /// @notice Return the exact script or private-commit binding for approvals.
    function getInteractionBindingHash(bytes32 key) external view returns (bytes32);
    /// @notice Return the complete public interaction bundle.
    /// @param key Base interaction identifier.
    /// @return Main script, flags, and ordered linked artifacts.
    function getInteractionBundle(bytes32 key) external view returns (InteractionBundleInput memory);
    /// @notice Return the activation-independent content hash for a public interaction.
    /// @param key Base interaction identifier.
    /// @return Canonical content hash excluding activation state.
    function getInteractionContentHash(bytes32 key) external view returns (bytes32);
    /// @notice Return the public bundle hash or the domain-separated missing hash.
    /// @param key Base interaction identifier.
    /// @return Canonical present or missing bundle hash.
    function getInteractionBundleHash(bytes32 key) external view returns (bytes32);
    /// @notice Return one linked artifact payload.
    /// @param baseId Base interaction identifier.
    /// @param relation Versioned linked-artifact relation.
    /// @return Stored payload, or empty bytes when absent.
    function getLinkedArtifact(bytes32 baseId, bytes32 relation) external view returns (bytes memory);
    /// @notice Return the ordered linked relations for a base interaction.
    /// @param baseId Base interaction identifier.
    /// @return Strictly increasing relation identifiers.
    function getLinkedArtifactRelations(bytes32 baseId) external view returns (bytes32[] memory);
    /// @notice Return a present or missing linked-artifact binding hash.
    /// @param baseId Base interaction identifier.
    /// @param relation Versioned linked-artifact relation.
    /// @return Hash binding payload presence and base activation.
    function getLinkedArtifactBindingHash(bytes32 baseId, bytes32 relation) external view returns (bytes32);
    /// @notice Return flags for an interaction key.
    function getInteractionFlags(bytes32 key) external view returns (uint256);
    /// @notice Reveal a private interaction commitment and atomically publish its complete bundle.
    /// @param bundle Canonical complete interaction snapshot committed by the author.
    /// @param relatedContracts Canonical related-contract list bound by the commitment.
    /// @param salt Secret bound by the commitment.
    /// @param actorSignature Optional committer authorization for a delegated reveal.
    function revealInteractionCommit(
        InteractionBundleInput calldata bundle,
        bytes32[] calldata relatedContracts,
        bytes32 salt,
        bytes calldata actorSignature
    ) external;
}
