// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {InteractionFlags} from "../../InteractionFlags.sol";
import {PagedIndex} from "../../PagedIndex.sol";
import {Interaction, InteractionBundleInput, LinkedArtifact, LinkedArtifactInput} from "../../RegistryTypes.sol";
import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {DelegationGuard} from "../../registry/DelegationGuard.sol";
import {InteractionBundleLib} from "../../registry/InteractionBundleLib.sol";
import {
    Authority,
    ExecutionCatalogStorage,
    InteractionCommitsStorage,
    InteractionsStorage,
    SyncStorage
} from "../../registry/RegistryShared.sol";
import {TimelockLib, TimelockRequest} from "../../registry/TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title RegistryInteractionsFacet
/// @notice Publishes each interaction and all linked artifacts as one governed snapshot.
/// @dev This facet is the source of truth for executable interaction bundles:
///      1. Public authors submit the complete desired snapshot with {upsertInteractionBundle}.
///      2. Private authors commit the complete bundle hash with {commitInteractionPrivate}.
///      3. {revealInteractionCommit} validates and publishes that bundle atomically.
///      4. Activation changes use a separate compare-and-swap timelock action.
///
///      Linked artifacts are never independently writable. They inherit the base
///      interaction's submitter, timelock, activation, private lifecycle, and sync provenance.
contract RegistryInteractionsFacet is FacetGuard {
    using PagedIndex for PagedIndex.Index;

    /// @notice Breaking interaction bundle facet version.
    uint256 public constant VERSION = 2;
    /// @notice Registry administrator role recognized by this facet.
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint256 internal constant MAX_INTERACTION_COMMIT_LIFETIME = 90 days;
    bytes32 private constant COMMIT_BINDING_TYPEHASH =
        keccak256("InteractionCommitBinding(bytes32 id,bytes32 commitHash)");
    bytes32 private constant MAIN_BINDING_TYPEHASH =
        keccak256("InteractionMainBinding(bytes32 id,bytes32 scriptHash,uint256 flags)");

    /// @notice Thrown when the logical actor lacks authority over the base interaction.
    error NotAuthorized();
    /// @notice Thrown when a private commitment already exists for the interaction.
    error CommitExists();
    /// @notice Thrown when no private commitment exists for the requested interaction.
    error CommitMissing();
    /// @notice Thrown when a private commitment is revealed after its deadline.
    error CommitExpired();
    /// @notice Thrown when a zero or mismatched commitment hash is supplied.
    error CommitHashMismatch();
    /// @notice Thrown when delegated reveal requires a committer signature but none is supplied.
    error RevealSignatureRequired();
    /// @notice Thrown when a delegated reveal signature is invalid.
    error RevealSignatureInvalid();
    /// @notice Thrown when neither the committer nor the revealer retains interaction-writing authority.
    error CommitterNoLongerAuthorized();
    /// @notice Thrown when a private commitment deadline is absent, expired, or too distant.
    error CommitDeadlineInvalid();
    /// @notice Thrown when an operation requires an existing public interaction.
    error InteractionMissing();
    /// @notice Thrown when public content and a private commitment coexist for one id.
    error InteractionArtifactConflict(bytes32 id);
    /// @notice Thrown when compare-and-swap expected and current bundle hashes differ.
    error InteractionBundleHashMismatch(bytes32 expected, bytes32 actual);
    /// @notice Thrown when a content update attempts to bypass activation governance.
    error InteractionActivationMustBePreserved();
    /// @notice ABI declaration for bundle validation's unsupported-flags failure.
    error InvalidInteractionFlags();
    /// @notice ABI declaration for bundle validation's missing-main-script failure.
    error EmptyInteractionScript();
    /// @notice ABI declaration for bundle validation's zero-id failure.
    error InvalidInteractionId();

    /// @notice Emitted after a complete interaction snapshot is published.
    event InteractionBundleUpsert(bytes32 indexed id, bytes32 indexed bundleHash, address indexed operator);
    /// @notice Emitted for every linked artifact present in a newly published snapshot.
    event LinkedArtifactUpsert(
        bytes32 indexed baseId, bytes32 indexed relation, bytes32 indexed artifactId, bytes32 payloadHash
    );
    /// @notice Emitted for every linked artifact removed from the previous snapshot.
    event LinkedArtifactRemoved(bytes32 indexed baseId, bytes32 indexed relation, bytes32 indexed artifactId);
    /// @notice Emitted when bundle publication or activation establishes new flags.
    event InteractionFlagsSet(bytes32 indexed id, uint256 flags, address indexed operator);
    /// @notice Emitted when a private complete-bundle commitment is recorded.
    event InteractionCommitCreated(
        bytes32 indexed id,
        address indexed committer,
        bytes32 commitHash,
        uint64 deadline,
        address forwarder,
        bytes32 hint
    );
    /// @notice Emitted when an unpublished private commitment is cancelled.
    event InteractionCommitCancelled(bytes32 indexed id, address indexed operator);
    /// @notice Emitted after a private commitment publishes its complete bundle.
    event InteractionCommitRevealed(bytes32 indexed id, address indexed operator, bytes32 commitHash);

    /// @notice Create or replace one complete interaction bundle.
    /// @dev Existing bundles must preserve their INACTIVE bit. The complete call
    ///      is queued and executed under one interaction-category timelock action.
    /// @param expectedCurrentBundleHash Current bundle hash, or the missing-bundle sentinel for creation.
    /// @param bundle Strictly canonical complete desired snapshot.
    function upsertInteractionBundle(bytes32 expectedCurrentBundleHash, InteractionBundleInput calldata bundle)
        external
        whenNotPausedD
        nonReentrantD
    {
        InteractionBundleInput memory bundleMem = bundle;
        InteractionBundleLib.validate(bundleMem);
        _assertBundleAuthority(bundle.id);
        _requireCurrentBundleHash(bundle.id, expectedCurrentBundleHash);
        _requireActivationPreserved(bundleMem);

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryInteraction(),
                scope: bundle.id,
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            abi.encodeWithSelector(this.upsertInteractionBundle.selector, expectedCurrentBundleHash, bundle)
        );
        if (!executing) return;

        _requireCurrentBundleHash(bundle.id, expectedCurrentBundleHash);
        _requireActivationPreserved(bundleMem);
        _applyBundle(bundleMem, address(0), false, true);
    }

    /// @notice Change activation without allowing a queued action to target newer content.
    /// @param expectedCurrentBundleHash Exact bundle hash whose activation may change.
    /// @param baseId Existing base interaction identifier.
    /// @param active Desired activation state.
    function setInteractionActive(bytes32 expectedCurrentBundleHash, bytes32 baseId, bool active)
        external
        whenNotPausedD
        nonReentrantD
    {
        _assertExistingAuthority(baseId);
        _requireCurrentBundleHash(baseId, expectedCurrentBundleHash);
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryActivation(),
                scope: baseId,
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            abi.encodeWithSelector(
                // ABI selectors are the leading four keccak256 bytes.
                // forge-lint: disable-next-line(unsafe-typecast)
                bytes4(keccak256("setInteractionActive(bytes32,bytes32,bool)")),
                expectedCurrentBundleHash,
                baseId,
                active
            )
        );
        if (!executing) return;

        _requireCurrentBundleHash(baseId, expectedCurrentBundleHash);
        InteractionsStorage.Layout storage interactions = InteractionsStorage.getLayout();
        Interaction storage interaction = interactions.interactions[baseId];
        uint256 flags = InteractionFlags.setActive(interaction.flags, active);
        if (flags == interaction.flags) return;
        interaction.flags = flags;
        ExecutionCatalogStorage.bump();
        (uint256 indexId, bool isIndexed) = interactions.interactionIds.idOf(baseId);
        if (isIndexed) interactions.interactionIds.update(indexId, baseId);
        SyncStorage.clearActiveInteractionImport(SyncStorage.getLayout(), baseId);
        // Bundle writes use internal storage helpers; signature validation is STATICCALL and entrypoints hold
        // nonReentrantD.
        // forge-lint: disable-next-line(reentrancy-events)
        emit InteractionFlagsSet(baseId, flags, _msgSenderD());
    }

    /// @notice Return the complete public snapshot for an existing interaction.
    /// @param baseId Base interaction identifier.
    /// @return Stored main script, flags, and ordered linked artifacts.
    function getInteractionBundle(bytes32 baseId) external view whenNotPausedD returns (InteractionBundleInput memory) {
        InteractionsStorage.Layout storage interactions = InteractionsStorage.getLayout();
        if (!InteractionsStorage.exists(interactions, baseId)) revert InteractionMissing();
        return InteractionsStorage.getBundle(interactions, baseId);
    }

    /// @notice Return the activation-independent content hash of a public interaction.
    /// @param baseId Base interaction identifier.
    /// @return Canonical hash of script, non-activation flags, and linked artifacts.
    function getInteractionContentHash(bytes32 baseId) external view whenNotPausedD returns (bytes32) {
        InteractionsStorage.Layout storage interactions = InteractionsStorage.getLayout();
        if (!InteractionsStorage.exists(interactions, baseId)) revert InteractionMissing();
        return InteractionBundleLib.contentHash(InteractionsStorage.getBundle(interactions, baseId));
    }

    /// @notice Return the compare-and-swap hash for present or missing interaction state.
    /// @param baseId Base interaction identifier.
    /// @return Canonical public bundle hash or the missing-bundle sentinel.
    function getInteractionBundleHash(bytes32 baseId) public view whenNotPausedD returns (bytes32) {
        InteractionsStorage.Layout storage interactions = InteractionsStorage.getLayout();
        if (!InteractionsStorage.exists(interactions, baseId)) return InteractionBundleLib.missingBundleHash(baseId);
        return InteractionBundleLib.bundleHash(InteractionsStorage.getBundle(interactions, baseId));
    }

    /// @notice Return one linked payload from a base-scoped artifact namespace.
    /// @param baseId Base interaction identifier.
    /// @param relation Versioned linked-artifact relation.
    /// @return payload Stored payload, or empty bytes when the relation is absent.
    function getLinkedArtifact(bytes32 baseId, bytes32 relation)
        external
        view
        whenNotPausedD
        returns (bytes memory payload)
    {
        (LinkedArtifact storage artifact, bool exists) =
            InteractionsStorage.linkedArtifact(InteractionsStorage.getLayout(), baseId, relation);
        if (!exists) return payload;
        return artifact.payload;
    }

    /// @notice Return the canonically ordered linked relations for one base interaction.
    /// @param baseId Base interaction identifier.
    /// @return Strictly increasing relation identifiers.
    function getLinkedArtifactRelations(bytes32 baseId) external view whenNotPausedD returns (bytes32[] memory) {
        return InteractionsStorage.linkedRelations(InteractionsStorage.getLayout(), baseId);
    }

    /// @notice Return the approval binding for one present or missing linked relation.
    /// @param baseId Base interaction identifier.
    /// @param relation Versioned linked-artifact relation.
    /// @return Hash binding payload presence and base activation.
    function getLinkedArtifactBindingHash(bytes32 baseId, bytes32 relation)
        external
        view
        whenNotPausedD
        returns (bytes32)
    {
        InteractionsStorage.Layout storage interactions = InteractionsStorage.getLayout();
        bool active = InteractionsStorage.exists(interactions, baseId)
            && !InteractionFlags.isInactive(interactions.interactions[baseId].flags);
        (LinkedArtifact storage artifact, bool exists) =
            InteractionsStorage.linkedArtifact(interactions, baseId, relation);
        if (!exists) return InteractionBundleLib.missingLinkedHash(baseId, relation, active);
        return InteractionBundleLib.linkedBindingHash(baseId, relation, artifact.payload, active);
    }

    /// @notice Return the main script stored for an interaction.
    /// @param key Base interaction identifier.
    /// @return Main MiniScript bytecode, or empty bytes when absent.
    function getInteractionScript(bytes32 key) external view whenNotPausedD returns (bytes memory) {
        return InteractionsStorage.getLayout().interactions[key].script;
    }

    /// @notice Return the executable artifact currently bound to new approvals.
    /// @param key Base interaction identifier.
    /// @return bindingHash Public main binding, private commitment binding, or missing sentinel.
    function getInteractionBindingHash(bytes32 key) external view whenNotPausedD returns (bytes32) {
        InteractionsStorage.Layout storage interactions = InteractionsStorage.getLayout();
        bool exists = InteractionsStorage.exists(interactions, key);
        bytes32 commitHash = InteractionCommitsStorage.getLayout().commits[key].hash;
        if (exists && commitHash != bytes32(0)) revert InteractionArtifactConflict(key);
        if (exists) {
            Interaction storage interaction = interactions.interactions[key];
            return keccak256(abi.encode(MAIN_BINDING_TYPEHASH, key, keccak256(interaction.script), interaction.flags));
        }
        if (commitHash != bytes32(0)) return keccak256(abi.encode(COMMIT_BINDING_TYPEHASH, key, commitHash));
        return InteractionBundleLib.missingBundleHash(key);
    }

    /// @notice Return flags stored for an interaction.
    /// @param key Base interaction identifier.
    /// @return Stored interaction flags, or zero when absent.
    function getInteractionFlags(bytes32 key) external view whenNotPausedD returns (uint256) {
        return InteractionsStorage.getLayout().interactions[key].flags;
    }

    /// @notice Return the number of indexed public interactions.
    /// @return Number of live interaction keys.
    function getInteractionCount() external view returns (uint256) {
        return InteractionsStorage.getLayout().interactionIds.length();
    }

    /// @notice Return the interaction key at a dense live index.
    /// @param index Zero-based live index.
    /// @return Interaction identifier at `index`.
    function getInteractionKeyAt(uint256 index) external view returns (bytes32) {
        return InteractionsStorage.getLayout().interactionIds.valueAt(index);
    }

    /// @notice Return a dense page of live interaction keys.
    /// @param start Zero-based live offset.
    /// @param count Maximum keys to return.
    /// @return Interaction identifiers in live-index order.
    function getInteractionKeysPage(uint256 start, uint256 count) external view returns (bytes32[] memory) {
        return InteractionsStorage.getLayout().interactionIds.page(start, count);
    }

    /// @notice Return the next stable id allocated by the paged interaction index.
    /// @return Next never-before-used index id.
    function getInteractionIndexNextId() external view returns (uint256) {
        return InteractionsStorage.getLayout().interactionIds.nextId();
    }

    /// @notice Return the current paged-index journal epoch.
    /// @return Current mutation epoch.
    function getInteractionIndexCurrentEpoch() external view returns (uint64) {
        return InteractionsStorage.getLayout().interactionIds.currentEpoch;
    }

    /// @notice Return one alive-bit page from the interaction index.
    /// @param pageIndex Alive bitmap page index.
    /// @return Bit set for each currently live stable id in the page.
    function getInteractionIndexAlivePage(uint256 pageIndex) external view returns (uint256) {
        return InteractionsStorage.getLayout().interactionIds.alivePage(pageIndex);
    }

    /// @notice Resolve stable interaction index ids to raw stored values.
    /// @dev Pair this result with {getInteractionIndexAlivePage} to determine which ids are live.
    /// @param ids Stable index ids.
    /// @return Interaction keys; deleted ids retain their historical key and unknown ids return zero.
    function getInteractionIndexValues(uint256[] calldata ids) external view returns (bytes32[] memory) {
        return InteractionsStorage.getLayout().interactionIds.getValues(ids);
    }

    /// @notice Return the number of journal pages touched in one epoch.
    /// @param epoch Journal epoch.
    /// @return Number of touched pages.
    function getInteractionIndexEpochPageCount(uint64 epoch) external view returns (uint256) {
        return InteractionsStorage.getLayout().interactionIds.epochPageCount(epoch);
    }

    /// @notice Return one touched page identifier from an epoch journal.
    /// @param epoch Journal epoch.
    /// @param i Zero-based position in the touched-page list.
    /// @return Touched page identifier.
    function getInteractionIndexEpochPageAt(uint64 epoch, uint256 i) external view returns (uint128) {
        return InteractionsStorage.getLayout().interactionIds.epochPageAt(epoch, i);
    }

    /// @notice Return update and deletion bitmaps for one journal page.
    /// @param epoch Journal epoch.
    /// @param pageIndex Stable-id page identifier.
    /// @return updates Bits whose values were inserted or updated.
    /// @return deletes Bits whose values were removed.
    function getInteractionIndexJournal(uint64 epoch, uint128 pageIndex)
        external
        view
        returns (uint256 updates, uint256 deletes)
    {
        return InteractionsStorage.getLayout().interactionIds.journal(epoch, pageIndex);
    }

    /// @notice Record a private commitment to one complete interaction bundle.
    /// @dev Public content and a private commitment cannot coexist for one id.
    ///      The absolute deadline must be in the future and no more than 90 days
    ///      away when the commit is stored. A timelocked caller must include
    ///      that delay in the deadline.
    /// @param id Interaction identifier reserved by the commitment.
    /// @param commitHash Schema-versioned full-bundle commitment hash.
    /// @param deadline Last timestamp at which reveal is accepted; must be within the next 90 days.
    /// @param forwarder Optional address authorized to relay the reveal with a committer signature.
    /// @param hint Opaque offchain discovery hint.
    function commitInteractionPrivate(bytes32 id, bytes32 commitHash, uint64 deadline, address forwarder, bytes32 hint)
        external
        whenNotPausedD
        nonReentrantD
    {
        if (id == bytes32(0)) revert InteractionBundleLib.InvalidInteractionId();
        address actor = _msgSenderD();
        if (!_canWriteInteraction(actor)) revert NotAuthorized();
        if (commitHash == bytes32(0)) revert CommitHashMismatch();
        // An authorized committer chooses a bounded reveal window measured in chain time.
        // forge-lint: disable-next-line(block-timestamp)
        if (deadline <= block.timestamp || uint256(deadline) > block.timestamp + MAX_INTERACTION_COMMIT_LIFETIME) {
            revert CommitDeadlineInvalid();
        }

        InteractionCommitsStorage.Layout storage commits = InteractionCommitsStorage.getLayout();
        if (commits.commits[id].hash != bytes32(0)) revert CommitExists();
        if (InteractionsStorage.exists(InteractionsStorage.getLayout(), id)) revert InteractionArtifactConflict(id);

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryInteraction(), scope: id, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.commitInteractionPrivate.selector, id, commitHash, deadline, forwarder, hint)
        );
        if (!executing) return;

        InteractionCommitsStorage.upsert(
            commits,
            id,
            InteractionCommitsStorage.Commit({
                hash: commitHash, committer: actor, forwarder: forwarder, deadline: deadline, hint: hint
            })
        );
        // Bundle writes use internal storage helpers; signature validation is STATICCALL and entrypoints hold
        // nonReentrantD.
        // forge-lint: disable-next-line(reentrancy-events)
        emit InteractionCommitCreated(id, actor, commitHash, deadline, forwarder, hint);
    }

    /// @notice Cancel an unpublished private interaction commitment.
    /// @dev Before expiry, the committer, a current writer, or CANCEL_INTERACTION holder may cancel.
    ///      Once expired, anyone may remove the unusable commitment, including while paused.
    /// @param id Interaction identifier whose commitment is removed.
    function cancelInteractionCommit(bytes32 id) external nonReentrantD {
        InteractionCommitsStorage.Layout storage commits = InteractionCommitsStorage.getLayout();
        InteractionCommitsStorage.Commit memory commit = commits.commits[id];
        if (commit.hash == bytes32(0)) revert CommitMissing();
        address actor = _msgSenderD();
        // After the chain-time reveal window closes, anyone may delete the unpublished commitment.
        // forge-lint: disable-next-line(block-timestamp)
        bool expired = block.timestamp > commit.deadline;
        if (!(expired || actor == commit.committer || _canWriteInteraction(actor)
                    || CapabilitiesLib.hasCapability(actor, CapabilityIds.CANCEL_INTERACTION))) {
            revert NotAuthorized();
        }
        InteractionCommitsStorage.clear(commits, id);
        // Bundle writes use internal storage helpers; signature validation is STATICCALL and entrypoints hold
        // nonReentrantD.
        // forge-lint: disable-next-line(reentrancy-events)
        emit InteractionCommitCancelled(id, actor);
    }

    /// @notice Validate and atomically publish a committed complete interaction bundle.
    /// @param bundle Complete canonical bundle whose hash was committed.
    /// @param relatedContracts Canonical related-contract list bound by the commitment.
    /// @param salt Secret bound by the commitment.
    /// @param actorSignature Optional committer authorization for a delegated reveal.
    function revealInteractionCommit(
        InteractionBundleInput calldata bundle,
        bytes32[] calldata relatedContracts,
        bytes32 salt,
        bytes calldata actorSignature
    ) external whenNotPausedD nonReentrantD {
        InteractionBundleInput memory bundleMem = bundle;
        bytes32[] memory relatedMem = relatedContracts;
        _revealInteractionBundle(bundleMem, relatedMem, salt, actorSignature);
    }

    /// @notice Return the pending private commitment for one interaction id.
    /// @param id Interaction identifier.
    /// @return Stored commitment metadata, or the zero record when absent.
    function getInteractionCommit(bytes32 id) external view returns (InteractionCommitsStorage.Commit memory) {
        return InteractionCommitsStorage.getLayout().commits[id];
    }

    /// @notice Return a dense page of pending private interaction ids.
    /// @param start Zero-based live offset.
    /// @param count Maximum ids to return.
    /// @return Pending interaction identifiers.
    function getInteractionCommitKeysPage(uint256 start, uint256 count) external view returns (bytes32[] memory) {
        return InteractionCommitsStorage.getLayout().commitIds.page(start, count);
    }

    /// @dev Verify live authority, expiry, payload hash, and any delegated signature before publication.
    function _revealInteractionBundle(
        InteractionBundleInput memory bundle,
        bytes32[] memory relatedContracts,
        bytes32 salt,
        bytes calldata actorSignature
    ) private {
        InteractionBundleLib.validate(bundle);
        InteractionBundleLib.validateRelatedContracts(relatedContracts);
        bytes32 id = bundle.id;
        InteractionCommitsStorage.Layout storage commits = InteractionCommitsStorage.getLayout();
        InteractionCommitsStorage.Commit memory commit = commits.commits[id];
        if (commit.hash == bytes32(0)) revert CommitMissing();
        // Chain time bounds reveal validity; commitment and current writer authorization are checked below.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > commit.deadline) revert CommitExpired();

        address actor = _msgSenderD();
        bool currentActorAuthorized = _canWriteInteraction(actor);
        bool currentCommitterAuthorized = _canWriteInteraction(commit.committer);
        if (!(currentActorAuthorized || currentCommitterAuthorized)) revert CommitterNoLongerAuthorized();

        bool isCommitter = actor == commit.committer;
        bool isForwarder = commit.forwarder != address(0) && actor == commit.forwarder;
        bool hasSignature = actorSignature.length != 0;
        bool needsSignature = false;
        if (!isCommitter) {
            if (isForwarder) {
                needsSignature = true;
            } else if (!currentActorAuthorized) {
                if (!hasSignature) revert NotAuthorized();
                needsSignature = true;
            }
        }

        bytes32 expectedCommit = InteractionBundleLib.commitHash(bundle, relatedContracts, salt);
        if (expectedCommit != commit.hash) revert CommitHashMismatch();
        if (needsSignature && actorSignature.length == 0) revert RevealSignatureRequired();
        if (hasSignature) {
            _verifyRevealSignature(commit.committer, id, expectedCommit, salt, actor, actorSignature);
        }

        InteractionCommitsStorage.clearForReveal(commits, id);
        _applyBundle(bundle, commit.committer, true, true);
        // Bundle writes use internal storage helpers; signature validation is STATICCALL and entrypoints hold
        // nonReentrantD.
        // forge-lint: disable-next-line(reentrancy-events)
        emit InteractionCommitRevealed(id, actor, expectedCommit);
    }

    /// @dev Replace the complete main-plus-linked snapshot and emit its removal/addition audit trail.
    function _applyBundle(
        InteractionBundleInput memory bundle,
        address submitterHint,
        bool allowDelegated,
        bool clearImport
    ) private {
        InteractionsStorage.Layout storage interactions = InteractionsStorage.getLayout();
        if (InteractionCommitsStorage.getLayout().commits[bundle.id].hash != bytes32(0)) {
            revert InteractionArtifactConflict(bundle.id);
        }
        address actor = _msgSenderD();
        if (!(_canWriteInteraction(actor) || (allowDelegated && _canWriteInteraction(submitterHint)))) {
            revert NotAuthorized();
        }
        address currentSubmitter = Authority._getSubmitter(bundle.id);
        if (currentSubmitter == address(0)) {
            address targetSubmitter = submitterHint == address(0) ? actor : submitterHint;
            Authority._setSubmitterIfUnset(bundle.id, targetSubmitter);
        } else if (submitterHint != address(0) && submitterHint != currentSubmitter) {
            revert NotAuthorized();
        }

        bytes32[] memory oldRelations = InteractionsStorage.linkedRelations(interactions, bundle.id);
        for (uint256 i; i < oldRelations.length; ++i) {
            // Bundle writes use internal storage helpers; signature validation is STATICCALL and entrypoints hold
            // nonReentrantD.
            // forge-lint: disable-start(reentrancy-events)
            emit LinkedArtifactRemoved(
                bundle.id, oldRelations[i], InteractionBundleLib.artifactId(bundle.id, oldRelations[i])
            );
            // forge-lint: disable-end(reentrancy-events)
        }
        InteractionsStorage.setBundle(interactions, bundle, true);
        for (uint256 i; i < bundle.linked.length; ++i) {
            LinkedArtifactInput memory linked = bundle.linked[i];
            // Bundle writes use internal storage helpers; signature validation is STATICCALL and entrypoints hold
            // nonReentrantD.
            // forge-lint: disable-start(reentrancy-events)
            emit LinkedArtifactUpsert(
                bundle.id,
                linked.relation,
                InteractionBundleLib.artifactId(bundle.id, linked.relation),
                keccak256(linked.payload)
            );
            // forge-lint: disable-end(reentrancy-events)
        }
        if (clearImport) SyncStorage.clearActiveInteractionImport(SyncStorage.getLayout(), bundle.id);
        // Bundle writes use internal storage helpers; signature validation is STATICCALL and entrypoints hold
        // nonReentrantD.
        // forge-lint: disable-next-line(reentrancy-events)
        emit InteractionFlagsSet(bundle.id, bundle.flags, actor);
        // Bundle writes use internal storage helpers; signature validation is STATICCALL and entrypoints hold
        // nonReentrantD.
        // forge-lint: disable-next-line(reentrancy-events)
        emit InteractionBundleUpsert(bundle.id, InteractionBundleLib.bundleHash(bundle), actor);
    }

    /// @dev Prevent content-category updates from changing the separately governed INACTIVE bit.
    function _requireActivationPreserved(InteractionBundleInput memory bundle) private view {
        InteractionsStorage.Layout storage interactions = InteractionsStorage.getLayout();
        if (!InteractionsStorage.exists(interactions, bundle.id)) return;
        if (
            InteractionFlags.isInactive(interactions.interactions[bundle.id].flags)
                != InteractionFlags.isInactive(bundle.flags)
        ) revert InteractionActivationMustBePreserved();
    }

    /// @dev Enforce compare-and-swap against the exact current public bundle state.
    function _requireCurrentBundleHash(bytes32 id, bytes32 expected) private view {
        bytes32 actual = getInteractionBundleHash(id);
        if (actual != expected) revert InteractionBundleHashMismatch(expected, actual);
    }

    /// @dev Immutable submitter data is provenance only; every write requires current authority.
    function _assertBundleAuthority(bytes32 id) private view {
        if (id == bytes32(0)) revert InteractionBundleLib.InvalidInteractionId();
        if (!_canWriteInteraction(_msgSenderD())) revert NotAuthorized();
    }

    /// @dev Require an existing bundle and current interaction-writing authority.
    function _assertExistingAuthority(bytes32 id) private view {
        if (!InteractionsStorage.exists(InteractionsStorage.getLayout(), id)) revert InteractionMissing();
        if (!_canWriteInteraction(_msgSenderD())) revert NotAuthorized();
    }

    /// @dev Executable artifacts require a dedicated live writer capability.
    function _canWriteInteraction(address actor) private view returns (bool) {
        if (actor == address(0)) return false;
        if (IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor)) return true;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.REGISTRY_MANAGER)) return true;
        // DIRECTORY_MANAGER must not implicitly become an executable-script author.
        return CapabilitiesLib.hasCapability(actor, CapabilityIds.INTERACTION_AUTHOR);
    }

    /// @dev Verify the committer's Ethereum-signed authorization for this exact forwarder and reveal.
    function _verifyRevealSignature(
        address committer,
        bytes32 id,
        bytes32 commitHash,
        bytes32 salt,
        address forwarder,
        bytes calldata actorSignature
    ) private view {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "RevealInteraction(bytes32 id,bytes32 commitHash,bytes32 salt,uint256 chainId,address forwarder)"
                ),
                id,
                commitHash,
                salt,
                block.chainid,
                forwarder
            )
        );
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        // A delegated committer's ERC-1271 answer comes from its delegate's code, not from its key.
        DelegationGuard.requireActorUsable(committer);
        if (!SignatureChecker.isValidSignatureNow(committer, ethHash, actorSignature)) {
            revert RevealSignatureInvalid();
        }
    }
}
