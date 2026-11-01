// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {InteractionFlags} from "../../InteractionFlags.sol";
import {
    CatalogImportKind,
    ImportProvenance,
    InteractionBundleInput,
    InteractionImportProvenance
} from "../../RegistryTypes.sol";
import {CapabilitiesLib, CapabilityIds} from "../Capabilities.sol";
import {InteractionBundleLib} from "../InteractionBundleLib.sol";
import {Authority, InteractionCommitsStorage, InteractionsStorage, SyncStorage} from "../RegistryShared.sol";
import {TimelockLib, TimelockRequest} from "../TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/// @notice Minimal trusted-source surface used to bind an imported interaction snapshot.
interface IRegistryInteractionSyncSource {
    /// @param key Base interaction identifier.
    /// @return bundleHash Canonical complete bundle hash currently published by the source.
    function getInteractionBundleHash(bytes32 key) external view returns (bytes32);
}

/// @title RegistryInteractionSyncFacet
/// @notice Imports complete interaction bundles from trusted Registry sources.
contract RegistryInteractionSyncFacet is FacetGuard {
    /// @notice Initial standalone interaction-sync facet version.
    uint256 public constant VERSION = 1;
    /// @notice Registry administrator role recognized by this facet.
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    /// @notice Thrown when the logical actor lacks import authority for the target interaction.
    error NotAuthorized();
    /// @notice Thrown when the requested source Registry is zero.
    error SourceRegistryZero();
    /// @notice Thrown when the requested source Registry has no code.
    error SourceRegistryNotContract();
    /// @notice Thrown when the source Registry is not currently allowlisted.
    error SourceRegistryNotAllowed(address sourceRegistry);
    /// @notice Thrown when a private commitment conflicts with the target public interaction.
    error InteractionArtifactConflict(bytes32 id);
    /// @notice Thrown when the source no longer publishes the expected complete bundle.
    error SourceInteractionMismatch();
    /// @notice Thrown when the target compare-and-swap precondition no longer holds.
    error InteractionBundleHashMismatch(bytes32 expected, bytes32 actual);

    /// @notice Emitted after one complete source bundle is imported locally.
    event InteractionImported(address indexed sourceRegistry, bytes32 indexed id, address indexed operator);

    /// @notice Import one complete interaction snapshot from an allowlisted Registry.
    /// @dev The source bundle hash and target compare-and-swap hash are checked
    ///      before queueing and again before execution. Existing target activation
    ///      is preserved so content import cannot bypass activation governance.
    /// @param sourceRegistry Trusted Registry that currently publishes `expectedSourceBundle`.
    /// @param expectedCurrentTargetBundleHash Exact current target bundle or missing-state hash.
    /// @param expectedSourceBundle Complete source snapshot expected at execution time.
    function importInteractionBundle(
        address sourceRegistry,
        bytes32 expectedCurrentTargetBundleHash,
        InteractionBundleInput calldata expectedSourceBundle
    ) external whenNotPausedD nonReentrantD {
        InteractionBundleInput memory sourceBundle = expectedSourceBundle;
        InteractionBundleLib.validate(sourceBundle);
        bytes32 id = sourceBundle.id;
        address actor = _msgSenderD();
        if (!_canImportInteraction(actor)) revert NotAuthorized();
        _requireAllowedSource(sourceRegistry);
        _requireTargetBundleHash(id, expectedCurrentTargetBundleHash);

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryInteraction(), scope: id, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(
                this.importInteractionBundle.selector,
                sourceRegistry,
                expectedCurrentTargetBundleHash,
                expectedSourceBundle
            )
        );
        if (!executing) return;

        _requireAllowedSource(sourceRegistry);
        _requireTargetBundleHash(id, expectedCurrentTargetBundleHash);
        bytes32 sourceBundleHash = InteractionBundleLib.bundleHash(sourceBundle);
        if (IRegistryInteractionSyncSource(sourceRegistry).getInteractionBundleHash(id) != sourceBundleHash) {
            revert SourceInteractionMismatch();
        }

        InteractionsStorage.Layout storage interactions = InteractionsStorage.getLayout();
        if (InteractionCommitsStorage.getLayout().commits[id].hash != bytes32(0)) {
            revert InteractionArtifactConflict(id);
        }
        if (InteractionsStorage.exists(interactions, id)) {
            sourceBundle.flags = InteractionFlags.setActive(
                sourceBundle.flags, !InteractionFlags.isInactive(interactions.interactions[id].flags)
            );
        }
        InteractionsStorage.setBundle(interactions, sourceBundle, true);
        if (Authority._getSubmitter(id) == address(0)) Authority._setSubmitterIfUnset(id, actor);

        SyncStorage.recordInteractionImport(
            SyncStorage.getLayout(),
            id,
            InteractionImportProvenance({
                common: ImportProvenance({
                    sourceRegistry: sourceRegistry,
                    importedAt: SafeCast.toUint64(block.timestamp),
                    importedBy: actor,
                    sourceKeyHash: id,
                    sourcePayloadHash: InteractionBundleLib.contentHash(sourceBundle),
                    importKind: CatalogImportKind.Interaction
                }),
                sourceContentHash: InteractionBundleLib.contentHash(expectedSourceBundle),
                sourceBundleHash: sourceBundleHash
            })
        );
        // Import holds nonReentrantD and reads the source through STATICCALL before writing the snapshot and event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit InteractionImported(sourceRegistry, id, actor);
    }

    /// @dev Immutable submitter data is provenance only; imports require current interaction-writing authority.
    function _canImportInteraction(address actor) private view returns (bool) {
        if (actor == address(0)) return false;
        if (IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor)) return true;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.REGISTRY_MANAGER)) return true;
        return CapabilitiesLib.hasCapability(actor, CapabilityIds.INTERACTION_AUTHOR);
    }

    /// @dev Require a deployed source currently present in the Registry sync allowlist.
    function _requireAllowedSource(address sourceRegistry) private view {
        if (sourceRegistry == address(0)) revert SourceRegistryZero();
        if (sourceRegistry.code.length == 0) revert SourceRegistryNotContract();
        if (!SyncStorage.getLayout().isSyncSourceAllowed[sourceRegistry]) {
            revert SourceRegistryNotAllowed(sourceRegistry);
        }
    }

    /// @dev Enforce compare-and-swap against exact current target state.
    function _requireTargetBundleHash(bytes32 id, bytes32 expected) private view {
        InteractionsStorage.Layout storage interactions = InteractionsStorage.getLayout();
        bytes32 actual = InteractionsStorage.exists(interactions, id)
            ? InteractionBundleLib.bundleHash(InteractionsStorage.getBundle(interactions, id))
            : InteractionBundleLib.missingBundleHash(id);
        if (actual != expected) revert InteractionBundleHashMismatch(expected, actual);
    }
}
