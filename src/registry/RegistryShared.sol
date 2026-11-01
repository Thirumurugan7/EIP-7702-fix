// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {IRegistry} from "@chainwall/interfaces/IRegistry.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {EntityFlags} from "../EntityFlags.sol";
import {PagedIndex} from "../PagedIndex.sol";
import {GovernanceData, GovernanceDataLib} from "./GovernanceData.sol";
import {InteractionBundleLib} from "./InteractionBundleLib.sol";
import {PendingActionList} from "./PendingActionList.sol";

import {
    AuthCredentialLink,
    CatalogImportKind,
    ContractAddress,
    ContractImportProvenance,
    DappContract,
    ERCToken,
    Group,
    Interaction,
    InteractionBundleInput,
    InteractionImportProvenance,
    LinkedArtifact,
    LinkedArtifactInput,
    Org,
    Policy,
    TokenImportProvenance
} from "../RegistryTypes.sol";

/// @title StorageKeys
/// @notice EIP-7201 reserved storage keys (namespaced) used across facets.
/// @dev These constants define the storage slots under which layouts are stored. Every facet and helper library
///      reads or writes through these namespaces so upgrades can share storage safely.
library StorageKeys {
    /// @notice Slot for organizations (Org records + index).
    bytes32 internal constant ORGS_SLOT = keccak256("okc.storage.orgs");
    /// @notice Slot for user address allowlist.
    bytes32 internal constant USER_ADDRS_SLOT = keccak256("okc.storage.user_addrs");
    /// @notice Slot for Safe address allowlist.
    bytes32 internal constant SAFE_ADDRS_SLOT = keccak256("okc.storage.safe_addrs");
    /// @notice Slot for Account address allowlist.
    bytes32 internal constant ACCOUNT_ADDRS_SLOT = keccak256("okc.storage.account_addrs");
    /// @notice Slot for groups (Group records + index).
    bytes32 internal constant GROUPS_SLOT = keccak256("okc.storage.groups");
    /// @notice Slot for policies (Policy records + index).
    bytes32 internal constant POLICIES_SLOT = keccak256("okc.storage.policies");
    /// @notice Slot for contracts (DappContract records + index).
    bytes32 internal constant CONTRACTS_SLOT = keccak256("okc.storage.contracts");
    /// @notice Slot for tokens (ERCToken records + index).
    bytes32 internal constant TOKENS_SLOT = keccak256("okc.storage.tokens");
    /// @notice Slot for interactions (Interaction records + index).
    bytes32 internal constant INTERACTIONS_SLOT = keccak256("okc.storage.interactions");
    /// @notice Slot for metadata (entityHash x keyHash => bytes).
    bytes32 internal constant META_SLOT = keccak256("okc.storage.meta");
    /// @notice Slot for policy-owned typed state and scoped meters.
    bytes32 internal constant POLICY_STATE_SLOT = keccak256("okc.storage.policy_state");
    /// @notice Slot for WebAuthn protocol account credential links.
    bytes32 internal constant AUTH_LINKS_SLOT = keccak256("okc.storage.auth.links");
    /// @notice Slot for Authority (owner/submitter mappings).
    bytes32 internal constant AUTH_SLOT = keccak256("okc.storage.authority");
    /// @notice Slot for timelock core storage (actions, queues, nonce).
    bytes32 internal constant TIMELOCK_CORE_SLOT = keccak256("okc.storage.timelock.core");
    /// @notice Slot for timelock configuration (categories and overrides).
    bytes32 internal constant TIMELOCK_CONFIG_SLOT = keccak256("okc.storage.timelock.config");
    /// @notice Slot for timelock payload storage (action calldata blobs).
    bytes32 internal constant TIMELOCK_PAYLOAD_SLOT = keccak256("okc.storage.timelock.payload");
    /// @notice Slot for timelock approval tallies and trackers.
    bytes32 internal constant TIMELOCK_APPROVAL_SLOT = keccak256("okc.storage.timelock.approval");
    /// @notice Slot for execution context when replaying timelocked actions.
    bytes32 internal constant EXECUTION_CONTEXT_SLOT = keccak256("okc.storage.timelock.exec");
    /// @notice Slot for optional indexing configuration.
    bytes32 internal constant INDEXING_SLOT = keccak256("okc.storage.indexing");
    /// @notice Slot for capability-to-group assignments.
    bytes32 internal constant CAPABILITIES_SLOT = keccak256("okc.storage.capabilities");
    /// @notice Slot for private interaction commitments.
    bytes32 internal constant INTERACTION_COMMITS_SLOT = keccak256("okc.storage.interactions.commits");
    /// @notice Slot for private contract commitments.
    bytes32 internal constant CONTRACT_COMMITS_SLOT = keccak256("okc.storage.contracts.commits");
    /// @notice Slot for private token commitments.
    bytes32 internal constant TOKEN_COMMITS_SLOT = keccak256("okc.storage.tokens.commits");
    /// @notice Slot for catalog sync allowlists and import provenance.
    bytes32 internal constant SYNC_SLOT = keccak256("okc.storage.sync");
    /// @notice Slot for the revision that invalidates approvals after executable catalog changes.
    bytes32 internal constant EXECUTION_CATALOG_SLOT = keccak256("okc.storage.execution.catalog");
}

/// @title ExecutionCatalogStorage
/// @notice Monotonic revision of Registry state that can change interaction execution.
/// @dev Interact binds this revision into approvals and direct signatures. Any
///      interaction, resolved contract, token/feed configuration, or governed
///      runtime upgrade must advance it so previously approved payloads fail
///      closed instead of silently following new executable state.
library ExecutionCatalogStorage {
    /// @dev Registry-wide EIP-1153 counter shared by every facet during one transaction.
    ///      It deliberately resets between transactions so live Registry changes do not
    ///      invalidate approvals that are evaluated in a later transaction.
    bytes32 internal constant SEMANTICS_REVISION_TRANSIENT_SLOT =
        keccak256("okc.transient.execution.semantics.revision");

    struct Layout {
        /// @dev Full catalog revision used when private interaction dependencies are hidden.
        uint64 version;
        /// @dev Shared execution-semantics revision used with dependency-specific public bindings.
        uint64 runtimeVersion;
    }

    event ExecutionCatalogVersionAdvanced(uint64 indexed version);
    event ExecutionRuntimeVersionAdvanced(uint64 indexed version);

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.EXECUTION_CATALOG_SLOT;
        assembly {
            l.slot := slot
        }
    }

    function initialize() internal {
        Layout storage L = getLayout();
        if (L.version == 0) {
            L.version = 1;
            // This helper writes local namespaced storage and emits immediately; it makes no external call.
            // forge-lint: disable-next-line(reentrancy-events)
            emit ExecutionCatalogVersionAdvanced(1);
        }
        if (L.runtimeVersion == 0) {
            L.runtimeVersion = 1;
            // This helper writes local namespaced storage and emits immediately; it makes no external call.
            // forge-lint: disable-next-line(reentrancy-events)
            emit ExecutionRuntimeVersionAdvanced(1);
        }
    }

    function bump() internal returns (uint64 next) {
        Layout storage L = getLayout();
        next = L.version + 1;
        L.version = next;
        // This helper writes local namespaced storage and emits immediately; it makes no external call.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ExecutionCatalogVersionAdvanced(next);
        bumpSemantics();
    }

    /// @notice Advance both broad runtime semantics and the full private catalog revision.
    /// @dev Facet/runtime upgrades and global price settings affect every script.
    ///      Record-local writes should call {bump} only; public interactions bind
    ///      their concrete dependencies and must not be invalidated by unrelated authors.
    function bumpRuntime() internal returns (uint64 next) {
        bump();
        Layout storage L = getLayout();
        next = L.runtimeVersion + 1;
        L.runtimeVersion = next;
        // This helper writes local namespaced storage and emits immediately; it makes no external call.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ExecutionRuntimeVersionAdvanced(next);
    }

    function version() internal view returns (uint64) {
        return getLayout().version;
    }

    function runtimeVersion() internal view returns (uint64) {
        return getLayout().runtimeVersion;
    }

    /// @notice Advance the Registry-wide transaction-local execution semantics revision.
    function bumpSemantics() internal returns (uint64 next) {
        next = semanticsRevision() + 1;
        bytes32 slot = SEMANTICS_REVISION_TRANSIENT_SLOT;
        assembly ("memory-safe") {
            tstore(slot, next)
        }
    }

    function semanticsRevision() internal view returns (uint64 revision) {
        bytes32 slot = SEMANTICS_REVISION_TRANSIENT_SLOT;
        assembly ("memory-safe") {
            revision := tload(slot)
        }
    }
}

/// @title AuthorityStorage
/// @notice Namespaced storage for Authority owner/submitter mappings.
/// @dev Backing store for Authority library helpers.
library AuthorityStorage {
    struct Layout {
        mapping(bytes32 => address) ownerOf;
        mapping(bytes32 => address) submitterOf;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.AUTH_SLOT;
        assembly {
            l.slot := slot
        }
    }
}

/// @title IndexingStorage
/// @notice Optional indexing configuration for registry-backed helpers.
library IndexingStorage {
    struct Layout {
        bool enabled;
        uint64 startBlock;
    }

    function state() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.INDEXING_SLOT;
        assembly {
            l.slot := slot
        }
    }
}

/// @title Authority
/// @notice Owner/submitter helpers using EIP-7201 namespaced storage.
library Authority {
    error SubmitterLocked();

    event OwnerSet(bytes32 indexed key, address indexed owner);
    event SubmitterSet(bytes32 indexed key, address indexed submitter);

    /// @notice Returns the owner set for a namespaced key.
    function _getOwner(bytes32 h) internal view returns (address) {
        return AuthorityStorage.getLayout().ownerOf[h];
    }

    /// @notice Sets the owner for a namespaced key; emits OwnerSet.
    function _setOwner(bytes32 h, address newOwner) internal {
        AuthorityStorage.getLayout().ownerOf[h] = newOwner;
        // This helper writes local namespaced storage and emits immediately; it makes no external call.
        // forge-lint: disable-next-line(reentrancy-events)
        emit OwnerSet(h, newOwner);
    }

    /// @notice Returns the submitter (first writer) set for a namespaced key.
    function _getSubmitter(bytes32 h) internal view returns (address) {
        return AuthorityStorage.getLayout().submitterOf[h];
    }

    /// @notice Sets submitter for a key only when currently unset; emits SubmitterSet.
    /// @dev Reverts SubmitterLocked when submitter is already present.
    function _setSubmitterIfUnset(bytes32 h, address who) internal {
        AuthorityStorage.Layout storage L = AuthorityStorage.getLayout();
        if (L.submitterOf[h] == address(0)) {
            L.submitterOf[h] = who;
            // This helper writes local namespaced storage and emits immediately; it makes no external call.
            // forge-lint: disable-next-line(reentrancy-events)
            emit SubmitterSet(h, who);
        } else {
            revert SubmitterLocked();
        }
    }
}

library OrgsStorage {
    /// @title OrgsStorage
    /// @notice Storage layout and helpers for organization records and membership.
    using EnumerableSet for EnumerableSet.AddressSet;

    struct Layout {
        mapping(bytes32 => Org) orgs;
        PagedIndex.Index orgIds;
        // Organization-derived catalog authority is an explicit production
        // opt-in. Historical org records alone grant no contract/token power.
        bool catalogDelegationEnabled;
        mapping(bytes32 => bool) suspended;
        mapping(bytes32 => address) pendingOwner;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.ORGS_SLOT;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Returns true if `actor` is owner or member of the org, or is admin.
    function isOwnerOrMember(Layout storage l, bytes32 orgHash, address actor, bool isAdmin)
        internal
        view
        returns (bool)
    {
        if (isAdmin) return true;
        Org storage o = l.orgs[orgHash];
        return actor == Authority._getOwner(orgHash) || o.members.contains(actor);
    }

    /// @notice Return whether an active org delegates catalog authority to `actor`.
    function hasCatalogAuthority(Layout storage L, bytes32 orgHash, address actor) internal view returns (bool) {
        if (!L.catalogDelegationEnabled || L.suspended[orgHash] || !exists(L, orgHash)) return false;
        return actor == Authority._getOwner(orgHash) || L.orgs[orgHash].members.contains(actor);
    }

    /// @notice Returns true when an Org exists for the hash.
    function exists(Layout storage L, bytes32 orgHash) internal view returns (bool) {
        return bytes(L.orgs[orgHash].id).length != 0;
    }

    /// @notice Checks if address is a member of the org.
    function isMember(Layout storage L, bytes32 orgHash, address a) internal view returns (bool) {
        return L.orgs[orgHash].members.contains(a);
    }

    /// @notice Adds a member; returns true if added.
    function addMember(Layout storage L, bytes32 orgHash, address a) internal returns (bool) {
        return L.orgs[orgHash].members.add(a);
    }

    /// @notice Removes a member; returns true if removed.
    function removeMember(Layout storage L, bytes32 orgHash, address a) internal returns (bool) {
        return L.orgs[orgHash].members.remove(a);
    }
}

library GroupsStorage {
    /// @title GroupsStorage
    /// @notice Storage layout for group records and membership, plus group id index.
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using PagedIndex for PagedIndex.Index;

    error GroupMembershipChanged(bytes32 groupId, uint64 reviewedRevision, uint64 currentRevision);

    struct MembershipSnapshot {
        uint64 revision;
        bool exists;
    }

    struct Layout {
        mapping(bytes32 => Group) groups;
        PagedIndex.Index groupIds;
        // Reverse memberships bound user-removal cost to the number of groups
        // that user belongs to instead of every group in the registry.
        mapping(address => EnumerableSet.Bytes32Set) groupIdsByMember;
        // Exact queued-action references replace global pending-action scans.
        mapping(bytes32 => EnumerableSet.Bytes32Set) pendingActionsByGroup;
        mapping(bytes32 => bytes32[]) pendingGroupsByAction;
        // Monotonic per-group generation used by security-sensitive consumers
        // that must bind an exact reviewed membership set. This mapping is not
        // deleted when a group id is reused.
        mapping(bytes32 => uint64) membershipRevision;
        // Distinguish membership-bound assignments from dependencies that only require a live group.
        mapping(bytes32 => mapping(bytes32 => MembershipSnapshot)) reviewedMembership;
        mapping(bytes32 => PendingActionList.List) compactPendingActions;
        mapping(bytes32 => address) compactPendingGroups;
        // Maintained sum of memberships and their capability/policy references; zero means no memberships.
        mapping(address => uint256) governanceWeight;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.GROUPS_SLOT;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Returns true when a Group exists.
    function exists(Layout storage L, bytes32 gh) internal view returns (bool) {
        return L.groups[gh].id != bytes32(0);
    }

    /// @notice Checks if `user` is a member of group `gh`.
    function isMember(Layout storage L, bytes32 gh, address user) internal view returns (bool) {
        return L.groups[gh].members.contains(user);
    }

    /// @notice Adds a user to a group; returns true if added.
    function addMember(Layout storage L, bytes32 gh, address user) internal returns (bool added) {
        if (isMember(L, gh, user)) return false;
        GroupReferenceLimits.addMembership(L, gh, user);
        added = L.groups[gh].members.add(user);
        if (added) {
            bool reverseAdded = L.groupIdsByMember[user].add(gh);
            assert(reverseAdded);
            bumpMembershipRevision(L, gh);
        }
    }

    /// @notice Removes a user from a group; returns true if removed.
    function removeMember(Layout storage L, bytes32 gh, address user) internal returns (bool removed) {
        if (!isMember(L, gh, user)) return false;
        GroupReferenceLimits.removeMembership(L, gh, user);
        removed = L.groups[gh].members.remove(user);
        if (removed) {
            bool reverseRemoved = L.groupIdsByMember[user].remove(gh);
            assert(reverseRemoved);
            bumpMembershipRevision(L, gh);
        }
    }

    /// @notice Returns how many groups contain `user`.
    function memberGroupCount(Layout storage L, address user) internal view returns (uint256) {
        return L.groupIdsByMember[user].length();
    }

    /// @notice Returns one group containing `user`.
    function memberGroupAt(Layout storage L, address user, uint256 index) internal view returns (bytes32) {
        return L.groupIdsByMember[user].at(index);
    }

    /// @notice Register that a queued action depends on `groupId` remaining live.
    function registerPendingAction(Layout storage L, bytes32 actionId, bytes32 groupId) internal {
        if (L.pendingActionsByGroup[groupId].add(actionId)) {
            L.pendingGroupsByAction[actionId].push(groupId);
        }
    }

    /// @notice Bind a queued capability or policy assignment to its exact reviewed membership generation.
    function registerPendingMembership(Layout storage L, bytes32 actionId, bytes32 groupId) internal {
        registerPendingAction(L, actionId, groupId);
        L.reviewedMembership[actionId][groupId] =
            MembershipSnapshot({revision: L.membershipRevision[groupId], exists: true});
    }

    function pendingMembershipsCurrent(Layout storage L, bytes32 actionId) internal view returns (bool) {
        (bytes32 changed,,) = _changedMembership(L, actionId);
        return changed == bytes32(0);
    }

    function requirePendingMemberships(Layout storage L, bytes32 actionId) internal view {
        (bytes32 changed, uint64 reviewed, uint64 current) = _changedMembership(L, actionId);
        // Every reviewed group must remain unchanged; accepting a subset would change the assignment's authority.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (changed != bytes32(0)) revert GroupMembershipChanged(changed, reviewed, current);
    }

    function _changedMembership(Layout storage L, bytes32 actionId)
        private
        view
        returns (bytes32 changed, uint64 reviewed, uint64 current)
    {
        bytes32[] storage groups = L.pendingGroupsByAction[actionId];
        for (uint256 i; i < groups.length; ++i) {
            bytes32 groupId = groups[i];
            MembershipSnapshot storage snapshot = L.reviewedMembership[actionId][groupId];
            if (snapshot.exists && snapshot.revision != L.membershipRevision[groupId]) {
                return (groupId, snapshot.revision, L.membershipRevision[groupId]);
            }
        }
    }

    /// @notice Return one queued action that still references `groupId`.
    function pendingAction(Layout storage L, bytes32 groupId) internal view returns (bytes32) {
        EnumerableSet.Bytes32Set storage actions = L.pendingActionsByGroup[groupId];
        return actions.length() == 0
            ? PendingActionList.firstExcept(L.compactPendingActions[groupId], bytes32(0))
            : actions.at(0);
    }

    /// @notice Store one immutable dependency list for an atomic membership bundle.
    function registerCompactPendingAction(Layout storage L, bytes32 actionId, bytes32[] memory groupIds) internal {
        if (groupIds.length == 0) return;
        bytes memory positions = new bytes(groupIds.length);
        for (uint256 i; i < groupIds.length; ++i) {
            positions[i] = bytes1(PendingActionList.add(L.compactPendingActions[groupIds[i]], actionId));
        }
        L.compactPendingGroups[actionId] = address(new GovernanceData(abi.encode(groupIds, positions)));
    }

    /// @notice Clear every group dependency recorded for a terminal action.
    function clearPendingAction(Layout storage L, bytes32 actionId) internal {
        address pointer = L.compactPendingGroups[actionId];
        if (pointer != address(0)) {
            (bytes32[] memory compactGroups, bytes memory positions) =
                abi.decode(GovernanceDataLib.read(pointer), (bytes32[], bytes));
            for (uint256 i; i < compactGroups.length; ++i) {
                bool removed =
                    PendingActionList.remove(L.compactPendingActions[compactGroups[i]], uint8(positions[i]), actionId);
                assert(removed);
            }
            delete L.compactPendingGroups[actionId];
        }
        bytes32[] storage groups = L.pendingGroupsByAction[actionId];
        for (uint256 i; i < groups.length; ++i) {
            bool removed = L.pendingActionsByGroup[groups[i]].remove(actionId);
            assert(removed);
            delete L.reviewedMembership[actionId][groups[i]];
        }
        delete L.pendingGroupsByAction[actionId];
    }

    /// @notice Returns number of members in a group.
    function memberCount(Layout storage L, bytes32 gh) internal view returns (uint256) {
        return L.groups[gh].members.length();
    }

    /// @notice Return one member of `gh` by its current enumerable-set index.
    function memberAt(Layout storage L, bytes32 gh, uint256 index) internal view returns (address) {
        return L.groups[gh].members.at(index);
    }

    /// @notice Return the generation representing the current membership set.
    function currentMembershipRevision(Layout storage L, bytes32 gh) internal view returns (uint64) {
        return L.membershipRevision[gh];
    }

    /// @notice Advance the generation after group creation, deletion, or membership mutation.
    function bumpMembershipRevision(Layout storage L, bytes32 gh) internal returns (uint64 next) {
        next = L.membershipRevision[gh] + 1;
        L.membershipRevision[gh] = next;
    }
}

/// @notice Bound the independent governance requirements of any single membership change.
library GroupReferenceLimits {
    uint256 internal constant MAX_REFERENCES = 16;
    uint256 internal constant MAX_USER_WEIGHT = 128;
    uint256 internal constant MAX_REFERENCED_GROUP_MEMBERS = 128;

    error TooManyGroupReferences(bytes32 groupId);
    error TooManyGovernanceRequirements(address user, uint256 weight);
    error TooManyReferencedGroupMembers(bytes32 groupId);

    function groupWeight(bytes32 groupId) internal view returns (uint256) {
        return 1 + PoliciesStorage.groupRefs(PoliciesStorage.getLayout(), groupId)
            + CapabilitiesStorage.groupRefs(CapabilitiesStorage.getLayout(), groupId);
    }

    function addMembership(GroupsStorage.Layout storage groups, bytes32 groupId, address user) internal {
        uint256 weight = groupWeight(groupId);
        if (weight > 1 && GroupsStorage.memberCount(groups, groupId) >= MAX_REFERENCED_GROUP_MEMBERS) {
            revert TooManyReferencedGroupMembers(groupId);
        }
        _increase(groups, user, weight);
    }

    function removeMembership(GroupsStorage.Layout storage groups, bytes32 groupId, address user) internal {
        groups.governanceWeight[user] -= groupWeight(groupId);
    }

    function addReference(bytes32 groupId) internal {
        // Reject the entire assignment: dropping a reference would bypass membership governance.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (groupWeight(groupId) > MAX_REFERENCES) revert TooManyGroupReferences(groupId);
        GroupsStorage.Layout storage groups = GroupsStorage.getLayout();
        uint256 count = GroupsStorage.memberCount(groups, groupId);
        // A reference must update every member's budget; skipping a large group would break admission.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (count > MAX_REFERENCED_GROUP_MEMBERS) revert TooManyReferencedGroupMembers(groupId);
        for (uint256 i; i < count; ++i) {
            _increase(groups, GroupsStorage.memberAt(groups, groupId, i), 1);
        }
    }

    function removeReference(bytes32 groupId) internal {
        GroupsStorage.Layout storage groups = GroupsStorage.getLayout();
        uint256 count = GroupsStorage.memberCount(groups, groupId);
        for (uint256 i; i < count; ++i) {
            address user = GroupsStorage.memberAt(groups, groupId, i);
            --groups.governanceWeight[user];
        }
    }

    function _increase(GroupsStorage.Layout storage groups, address user, uint256 amount) private {
        uint256 weight = groups.governanceWeight[user] + amount;
        // Every member must remain atomically removable, including after a reference is added later.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (weight > MAX_USER_WEIGHT) revert TooManyGovernanceRequirements(user, weight);
        groups.governanceWeight[user] = weight;
    }
}

library PoliciesStorage {
    /// @title PoliciesStorage
    /// @notice Storage and helpers for policy records and index.
    using EnumerableSet for EnumerableSet.Bytes32Set;

    error GroupPolicyIndexIncomplete(bytes32 groupId);

    struct Layout {
        mapping(bytes32 => Policy) policies;
        PagedIndex.Index policyIds;
        mapping(bytes32 => uint256) groupRefCount;
        mapping(bytes32 => EnumerableSet.Bytes32Set) policiesByGroup;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.POLICIES_SLOT;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Returns a policy storage reference (may be unset).
    function get(Layout storage L, bytes32 id) internal view returns (Policy storage) {
        return L.policies[id];
    }

    /// @notice Returns true when a policy exists (id != 0).
    function exists(Layout storage L, bytes32 id) internal view returns (bool) {
        return L.policies[id].id != bytes32(0);
    }

    /// @notice Returns the number of live policy criteria currently referencing a group.
    function groupRefs(Layout storage L, bytes32 groupId) internal view returns (uint256) {
        return L.groupRefCount[groupId];
    }

    /// @notice Increments the live policy-criteria reference count for a group.
    function incrementGroupRef(Layout storage L, bytes32 groupId, bytes32 policyId) internal {
        GroupReferenceLimits.addReference(groupId);
        bool added = L.policiesByGroup[groupId].add(policyId);
        assert(added);
        L.groupRefCount[groupId] += 1;
    }

    /// @notice Decrements the live policy-criteria reference count for a group.
    function decrementGroupRef(Layout storage L, bytes32 groupId, bytes32 policyId) internal {
        GroupReferenceLimits.removeReference(groupId);
        bool removed = L.policiesByGroup[groupId].remove(policyId);
        assert(removed);
        L.groupRefCount[groupId] -= 1;
    }

    /// @notice Enumerate every affected policy and verify that its reverse index is complete.
    function groupPolicies(Layout storage L, bytes32 groupId) internal view returns (bytes32[] memory) {
        if (L.policiesByGroup[groupId].length() != L.groupRefCount[groupId]) {
            // An incomplete index would omit a required policy from membership governance; fail the whole write.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert GroupPolicyIndexIncomplete(groupId);
        }
        return L.policiesByGroup[groupId].values();
    }
}

library ContractsStorage {
    /// @title ContractsStorage
    /// @notice Versioned contract addresses and labels under a contract key.
    using PagedIndex for PagedIndex.Index;

    struct Layout {
        mapping(bytes32 => DappContract) contracts_;
        PagedIndex.Index contractKeys;
        mapping(bytes32 => uint256) flags;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.CONTRACTS_SLOT;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Returns a contract storage reference for `key` (may be unset).
    function get(Layout storage L, bytes32 key) internal view returns (DappContract storage c) {
        return L.contracts_[key];
    }

    /// @notice Appends a new version for `key` and optionally sets a label.
    /// @return newVersion The newly assigned version number.
    function addVersion(Layout storage L, bytes32 key, ContractAddress calldata addrData, bytes32 label)
        internal
        returns (uint32 newVersion)
    {
        DappContract storage c = L.contracts_[key];
        newVersion = c.latest + 1;
        c.versions[newVersion] = addrData;
        c.latest = newVersion;
        if (label != bytes32(0)) {
            c.labels[label] = newVersion;
        }
        // Existing ids double as semantic invalidation keys for incremental
        // clients. Fresh ids are discovered from nextId and are inserted by the
        // caller after its complete record has been initialized.
        touchIndex(L, key);
        ExecutionCatalogStorage.bump();
    }

    /// @notice Mark an existing contract record as semantically updated.
    function touchIndex(Layout storage L, bytes32 key) internal {
        (uint256 id, bool exists_) = L.contractKeys.idOf(key);
        if (exists_) L.contractKeys.update(id, key);
    }

    /// @notice Returns the latest version for a key (0 when none).
    function latest(Layout storage L, bytes32 key) internal view returns (uint32) {
        return L.contracts_[key].latest;
    }

    /// @notice Returns a specific version's ContractAddress storage reference.
    function version(Layout storage L, bytes32 key, uint32 v) internal view returns (ContractAddress storage) {
        return L.contracts_[key].versions[v];
    }

    /// @notice Resolves a label to the underlying version number (0 when unset).
    function labelToVersion(Layout storage L, bytes32 key, bytes32 label) internal view returns (uint32) {
        return L.contracts_[key].labels[label];
    }

    /// @notice Returns true if a contract record has been initialized for `key`.
    function exists(Layout storage L, bytes32 key) internal view returns (bool) {
        DappContract storage c = L.contracts_[key];
        return bytes(c.org).length != 0 && bytes(c.id).length != 0;
    }

    /// @notice Returns the latest address for `key` (zero when none).
    function latestAddr(Layout storage L, bytes32 key) internal view returns (address) {
        DappContract storage c = L.contracts_[key];
        return c.latest == 0 ? address(0) : c.versions[c.latest].addr;
    }

    /// @notice Returns the contract-level flags for `key`.
    function getFlags(Layout storage L, bytes32 key) internal view returns (uint256) {
        return L.flags[key];
    }

    /// @notice Sets contract-level flags for `key`.
    function setFlags(Layout storage L, bytes32 key, uint256 flags) internal {
        L.flags[key] = flags;
        touchIndex(L, key);
        ExecutionCatalogStorage.bump();
    }

    /// @notice Returns true if the contract key is not marked inactive.
    function isActive(Layout storage L, bytes32 key) internal view returns (bool) {
        return !EntityFlags.isInactive(L.flags[key]);
    }
}

library TokensStorage {
    /// @title TokensStorage
    /// @notice Storage for ERCToken records and token key index.
    using PagedIndex for PagedIndex.Index;

    struct Layout {
        mapping(bytes32 => ERCToken) tokens;
        PagedIndex.Index tokenKeys;
        mapping(bytes32 => uint256) flags;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.TOKENS_SLOT;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Returns true when a token record exists for `key`.
    function exists(Layout storage L, bytes32 key) internal view returns (bool) {
        return bytes(L.tokens[key].id).length != 0;
    }

    /// @notice Returns the token-level flags for `key`.
    function getFlags(Layout storage L, bytes32 key) internal view returns (uint256) {
        return L.flags[key];
    }

    /// @notice Sets token-level flags for `key`.
    function setFlags(Layout storage L, bytes32 key, uint256 flags) internal {
        L.flags[key] = flags;
        touchIndex(L, key);
        ExecutionCatalogStorage.bump();
    }

    /// @notice Mark an existing token record as semantically updated.
    function touchIndex(Layout storage L, bytes32 key) internal {
        (uint256 id, bool exists_) = L.tokenKeys.idOf(key);
        if (exists_) L.tokenKeys.update(id, key);
    }

    /// @notice Returns true if the token key is not marked inactive.
    function isActive(Layout storage L, bytes32 key) internal view returns (bool) {
        return !EntityFlags.isInactive(L.flags[key]);
    }
}

library InteractionsStorage {
    using PagedIndex for PagedIndex.Index;

    /// @notice Thrown when a derived artifact id resolves to another base/relation pair.
    error LinkedArtifactCollision(bytes32 artifactId);

    /// @title InteractionsStorage
    /// @notice Storage for base interactions, linked-artifact namespaces, and the id index.
    struct Layout {
        /// @dev Main scripts and flags keyed by base interaction id.
        mapping(bytes32 => Interaction) interactions;
        /// @dev Paged public base-interaction index.
        PagedIndex.Index interactionIds;
        /// @dev Whether a base id is currently represented in `interactionIds`.
        mapping(bytes32 => bool) isIndexed;
        /// @dev Canonically ordered relations stored for each base interaction.
        mapping(bytes32 => bytes32[]) linkedRelations;
        /// @dev Linked payloads keyed by `InteractionBundleLib.artifactId(baseId, relation)`.
        mapping(bytes32 => LinkedArtifact) linkedArtifacts;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.INTERACTIONS_SLOT;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Return whether a nonzero interaction id has been explicitly stored.
    function exists(Layout storage L, bytes32 key) internal view returns (bool) {
        return key != bytes32(0) && L.interactions[key].id == key;
    }

    /// @notice Set the script for an interaction, optionally tracking the id in the index.
    function setScript(Layout storage L, bytes32 key, bytes calldata script, bool trackIndex) internal {
        Interaction storage i = L.interactions[key];
        i.id = key;
        i.script = script;

        bool alreadyIndexed = L.isIndexed[key];
        if (trackIndex) {
            if (!alreadyIndexed) {
                L.interactionIds.insert(key);
                L.isIndexed[key] = true;
            } else {
                (uint256 id, bool found) = L.interactionIds.idOf(key);
                if (found) {
                    L.interactionIds.update(id, key);
                }
            }
        } else if (alreadyIndexed) {
            L.interactionIds.removeValue(key);
            L.isIndexed[key] = false;
        }
        ExecutionCatalogStorage.bump();
    }

    /// @notice Return the complete stored bundle for an existing base.
    /// @param L Interaction storage layout.
    /// @param key Existing base interaction identifier.
    /// @return bundle Main script, flags, and ordered linked-artifact snapshot.
    function getBundle(Layout storage L, bytes32 key) internal view returns (InteractionBundleInput memory bundle) {
        Interaction storage interaction = L.interactions[key];
        bundle.id = interaction.id;
        bundle.script = interaction.script;
        bundle.flags = interaction.flags;
        bytes32[] storage relations = L.linkedRelations[key];
        bundle.linked = new LinkedArtifactInput[](relations.length);
        for (uint256 i; i < relations.length; ++i) {
            bytes32 relation = relations[i];
            LinkedArtifact storage artifact = L.linkedArtifacts[InteractionBundleLib.artifactId(key, relation)];
            if (artifact.baseId != key || artifact.relation != relation) {
                // Every linked-artifact key must match its base and relation; a collision must abort the complete
                // snapshot.
                // forge-lint: disable-next-line(require-revert-in-loop)
                revert LinkedArtifactCollision(InteractionBundleLib.artifactId(key, relation));
            }
            bundle.linked[i] = LinkedArtifactInput({relation: relation, payload: artifact.payload});
        }
    }

    /// @notice Replace the main program and complete linked-artifact snapshot.
    /// @param L Interaction storage layout.
    /// @param bundle Canonical complete desired snapshot.
    /// @param trackIndex Whether the base id should remain in the public paged index.
    function setBundle(Layout storage L, InteractionBundleInput memory bundle, bool trackIndex) internal {
        bytes32 key = bundle.id;
        bytes32[] storage oldRelations = L.linkedRelations[key];
        for (uint256 i; i < oldRelations.length; ++i) {
            delete L.linkedArtifacts[InteractionBundleLib.artifactId(key, oldRelations[i])];
        }
        delete L.linkedRelations[key];

        for (uint256 i; i < bundle.linked.length; ++i) {
            LinkedArtifactInput memory input = bundle.linked[i];
            bytes32 id = InteractionBundleLib.artifactId(key, input.relation);
            LinkedArtifact storage existing = L.linkedArtifacts[id];
            if (existing.baseId != bytes32(0) && (existing.baseId != key || existing.relation != input.relation)) {
                // Every linked-artifact key must match its base and relation; a collision must abort the complete
                // snapshot.
                // forge-lint: disable-next-line(require-revert-in-loop)
                revert LinkedArtifactCollision(id);
            }
            L.linkedArtifacts[id] = LinkedArtifact({baseId: key, relation: input.relation, payload: input.payload});
            L.linkedRelations[key].push(input.relation);
        }

        Interaction storage interaction = L.interactions[key];
        interaction.id = key;
        interaction.script = bundle.script;
        interaction.flags = bundle.flags;
        _setIndexed(L, key, trackIndex);
        ExecutionCatalogStorage.bump();
    }

    /// @notice Return one linked artifact storage reference and exact-pair existence flag.
    function linkedArtifact(Layout storage L, bytes32 baseId, bytes32 relation)
        internal
        view
        returns (LinkedArtifact storage artifact, bool exists_)
    {
        artifact = L.linkedArtifacts[InteractionBundleLib.artifactId(baseId, relation)];
        exists_ = artifact.baseId == baseId && artifact.relation == relation && artifact.payload.length != 0;
    }

    /// @notice Copy the ordered linked relations stored under one base interaction.
    function linkedRelations(Layout storage L, bytes32 baseId) internal view returns (bytes32[] memory) {
        return L.linkedRelations[baseId];
    }

    function _setIndexed(Layout storage L, bytes32 key, bool trackIndex) private {
        bool alreadyIndexed = L.isIndexed[key];
        if (trackIndex) {
            if (!alreadyIndexed) {
                if (!L.interactionIds.contains(key)) {
                    L.interactionIds.insert(key);
                } else {
                    (uint256 id, bool found) = L.interactionIds.idOf(key);
                    if (found) L.interactionIds.update(id, key);
                }
                L.isIndexed[key] = true;
            } else {
                (uint256 id, bool found) = L.interactionIds.idOf(key);
                if (found) L.interactionIds.update(id, key);
            }
        } else if (alreadyIndexed) {
            L.interactionIds.removeValue(key);
            L.isIndexed[key] = false;
        }
    }
}

library SyncStorage {
    using PagedIndex for PagedIndex.Index;

    /// @title SyncStorage
    /// @notice Storage for source allowlists and import provenance.
    struct Layout {
        mapping(address => bool) isSyncSourceAllowed;
        PagedIndex.Index syncSources;
        mapping(bytes32 => ContractImportProvenance) activeContractImports;
        mapping(bytes32 => ContractImportProvenance[]) contractImportHistory;
        mapping(bytes32 => TokenImportProvenance) activeTokenImports;
        mapping(bytes32 => TokenImportProvenance[]) tokenImportHistory;
        mapping(bytes32 => InteractionImportProvenance) activeInteractionImports;
        mapping(bytes32 => InteractionImportProvenance[]) interactionImportHistory;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.SYNC_SLOT;
        assembly {
            l.slot := slot
        }
    }

    function setSourceAllowed(Layout storage L, address source, bool allowed) internal returns (bool changed) {
        bytes32 sourceKey = bytes32(uint256(uint160(source)));
        if (allowed) {
            if (L.isSyncSourceAllowed[source]) {
                return false;
            }
            L.isSyncSourceAllowed[source] = true;
            L.syncSources.insert(sourceKey);
            return true;
        }

        if (!L.isSyncSourceAllowed[source]) {
            return false;
        }
        L.isSyncSourceAllowed[source] = false;
        L.syncSources.removeValue(sourceKey);
        return true;
    }

    function clearActiveContractImport(Layout storage L, bytes32 key) internal {
        delete L.activeContractImports[key];
    }

    function recordContractImport(Layout storage L, bytes32 key, ContractImportProvenance memory provenance) internal {
        L.activeContractImports[key] = provenance;
        L.contractImportHistory[key].push(provenance);
    }

    function clearActiveTokenImport(Layout storage L, bytes32 key) internal {
        delete L.activeTokenImports[key];
    }

    function recordTokenImport(Layout storage L, bytes32 key, TokenImportProvenance memory provenance) internal {
        L.activeTokenImports[key] = provenance;
        L.tokenImportHistory[key].push(provenance);
    }

    function clearActiveInteractionImport(Layout storage L, bytes32 key) internal {
        delete L.activeInteractionImports[key];
    }

    function recordInteractionImport(Layout storage L, bytes32 key, InteractionImportProvenance memory provenance)
        internal
    {
        L.activeInteractionImports[key] = provenance;
        L.interactionImportHistory[key].push(provenance);
    }

    function hasActiveContractImport(Layout storage L, bytes32 key) internal view returns (bool) {
        return L.activeContractImports[key].common.importKind != CatalogImportKind.None;
    }

    function hasActiveTokenImport(Layout storage L, bytes32 key) internal view returns (bool) {
        return L.activeTokenImports[key].common.importKind != CatalogImportKind.None;
    }

    function hasActiveInteractionImport(Layout storage L, bytes32 key) internal view returns (bool) {
        return L.activeInteractionImports[key].common.importKind != CatalogImportKind.None;
    }
}

library InteractionCommitsStorage {
    using PagedIndex for PagedIndex.Index;

    struct Commit {
        bytes32 hash;
        address committer;
        address forwarder;
        uint64 deadline;
        bytes32 hint;
    }

    struct Layout {
        mapping(bytes32 => Commit) commits;
        PagedIndex.Index commitIds;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.INTERACTION_COMMITS_SLOT;
        assembly {
            l.slot := slot
        }
    }

    function upsert(Layout storage L, bytes32 id, Commit memory commit) internal {
        L.commits[id] = commit;
        if (!L.commitIds.contains(id)) {
            L.commitIds.insert(id);
        }
        // Hidden scripts force parent CALLI bindings onto the broad catalog
        // revision, so commit replacement must invalidate those approvals.
        ExecutionCatalogStorage.bump();
    }

    function clear(Layout storage L, bytes32 id) internal {
        clearForReveal(L, id);
        ExecutionCatalogStorage.bump();
    }

    /// @notice Remove a commitment as part of an atomic reveal that bumps through bundle storage.
    /// @param L Private interaction commitment storage.
    /// @param id Interaction identifier whose commitment is removed.
    function clearForReveal(Layout storage L, bytes32 id) internal {
        delete L.commits[id];
        L.commitIds.removeValue(id);
    }
}

library ContractCommitsStorage {
    using PagedIndex for PagedIndex.Index;

    struct Commit {
        bytes32 hash;
        address committer;
        address forwarder;
        uint64 deadline;
        bytes32 hint;
    }

    struct Layout {
        mapping(bytes32 => Commit) commits;
        PagedIndex.Index commitKeys;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.CONTRACT_COMMITS_SLOT;
        assembly {
            l.slot := slot
        }
    }

    function upsert(Layout storage L, bytes32 key, Commit memory commit) internal {
        L.commits[key] = commit;
        if (!L.commitKeys.contains(key)) {
            L.commitKeys.insert(key);
        }
    }

    function clear(Layout storage L, bytes32 key) internal {
        delete L.commits[key];
        L.commitKeys.removeValue(key);
    }
}

library TokenCommitsStorage {
    using PagedIndex for PagedIndex.Index;

    struct Commit {
        bytes32 hash;
        address committer;
        address forwarder;
        uint64 deadline;
        bytes32 hint;
    }

    struct Layout {
        mapping(bytes32 => Commit) commits;
        PagedIndex.Index commitKeys;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.TOKEN_COMMITS_SLOT;
        assembly {
            l.slot := slot
        }
    }

    function upsert(Layout storage L, bytes32 key, Commit memory commit) internal {
        L.commits[key] = commit;
        if (!L.commitKeys.contains(key)) {
            L.commitKeys.insert(key);
        }
    }

    function clear(Layout storage L, bytes32 key) internal {
        delete L.commits[key];
        L.commitKeys.removeValue(key);
    }
}

library AuthLinksStorage {
    /// @title AuthLinksStorage
    /// @notice Registry-side WebAuthn credential id links keyed by idKey.
    using EnumerableSet for EnumerableSet.Bytes32Set;

    struct Layout {
        mapping(bytes32 => AuthCredentialLink) links;
        mapping(address => EnumerableSet.Bytes32Set) accountAuthIds;
        mapping(address => bool) authAccountFactories;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.AUTH_LINKS_SLOT;
        assembly {
            l.slot := slot
        }
    }
}

library UserAddrsStorage {
    /// @title UserAddrsStorage
    /// @notice Storage wrapper for user allowlist (EnumerableSet of addresses).
    using EnumerableSet for EnumerableSet.AddressSet;

    struct Layout {
        EnumerableSet.AddressSet userAddrs;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.USER_ADDRS_SLOT;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Returns true if the allowlist contains address `a`.
    function contains(Layout storage L, address a) internal view returns (bool) {
        return L.userAddrs.contains(a);
    }

    /// @notice Adds `a` to the allowlist; returns true if added.
    function add(Layout storage L, address a) internal returns (bool) {
        return L.userAddrs.add(a);
    }

    /// @notice Removes `a` from the allowlist; returns true if removed.
    function remove(Layout storage L, address a) internal returns (bool) {
        return L.userAddrs.remove(a);
    }

    /// @notice Returns size of the allowlist.
    function length(Layout storage L) internal view returns (uint256) {
        return L.userAddrs.length();
    }

    /// @notice Returns allowlisted address at `index`.
    function valueAt(Layout storage L, uint256 index) internal view returns (address) {
        return L.userAddrs.at(index);
    }
}

library SafeAddrsStorage {
    /// @title SafeAddrsStorage
    /// @notice Storage wrapper for Safe allowlist (PagedIndex of addresses).
    using PagedIndex for PagedIndex.Index;

    struct Layout {
        PagedIndex.Index safeAddrs;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.SAFE_ADDRS_SLOT;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Returns true if the allowlist contains address `a`.
    function contains(Layout storage L, address a) internal view returns (bool) {
        return L.safeAddrs.contains(_key(a));
    }

    /// @notice Adds `a` to the allowlist; returns true if added.
    function add(Layout storage L, address a) internal returns (bool) {
        bytes32 key = _key(a);
        if (L.safeAddrs.contains(key)) return false;
        L.safeAddrs.insert(key);
        return true;
    }

    /// @notice Removes `a` from the allowlist; returns true if removed.
    function remove(Layout storage L, address a) internal returns (bool) {
        return L.safeAddrs.removeValue(_key(a));
    }

    /// @notice Returns size of the allowlist.
    function length(Layout storage L) internal view returns (uint256) {
        return L.safeAddrs.length();
    }

    /// @notice Returns allowlisted address at `index`.
    function valueAt(Layout storage L, uint256 index) internal view returns (address) {
        bytes32 value = L.safeAddrs.valueAt(index);
        return address(uint160(uint256(value)));
    }

    /// @notice Returns allowlisted addresses in the range [start, start+count).
    function page(Layout storage L, uint256 start, uint256 count) internal view returns (address[] memory out) {
        bytes32[] memory values = L.safeAddrs.page(start, count);
        out = new address[](values.length);
        for (uint256 i = 0; i < values.length; i++) {
            out[i] = address(uint160(uint256(values[i])));
        }
    }

    function _key(address a) private pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }
}

library AccountAddrsStorage {
    /// @title AccountAddrsStorage
    /// @notice Storage wrapper for Account allowlist (PagedIndex of addresses).
    using PagedIndex for PagedIndex.Index;

    struct Layout {
        PagedIndex.Index accountAddrs;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.ACCOUNT_ADDRS_SLOT;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Returns true if the allowlist contains address `a`.
    function contains(Layout storage L, address a) internal view returns (bool) {
        return L.accountAddrs.contains(_key(a));
    }

    /// @notice Adds `a` to the allowlist; returns true if added.
    function add(Layout storage L, address a) internal returns (bool) {
        bytes32 key = _key(a);
        if (L.accountAddrs.contains(key)) return false;
        L.accountAddrs.insert(key);
        return true;
    }

    /// @notice Removes `a` from the allowlist; returns true if removed.
    function remove(Layout storage L, address a) internal returns (bool) {
        return L.accountAddrs.removeValue(_key(a));
    }

    /// @notice Returns size of the allowlist.
    function length(Layout storage L) internal view returns (uint256) {
        return L.accountAddrs.length();
    }

    /// @notice Returns allowlisted address at `index`.
    function valueAt(Layout storage L, uint256 index) internal view returns (address) {
        bytes32 value = L.accountAddrs.valueAt(index);
        return address(uint160(uint256(value)));
    }

    /// @notice Returns allowlisted addresses in the range [start, start+count).
    function page(Layout storage L, uint256 start, uint256 count) internal view returns (address[] memory out) {
        bytes32[] memory values = L.accountAddrs.page(start, count);
        out = new address[](values.length);
        for (uint256 i = 0; i < values.length; i++) {
            out[i] = address(uint160(uint256(values[i])));
        }
    }

    function _key(address a) private pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }
}

library MetaStorage {
    /// @title MetaStorage
    /// @notice Raw metadata mapping: (entityHash, keyHash) => bytes with typed string helpers.
    struct Layout {
        mapping(bytes32 => mapping(bytes32 => bytes)) meta;
        // Field indexes enumerate metadata by entity.
        mapping(bytes32 => PagedIndex.Index) fieldIndexes;
        mapping(bytes32 => string) identifiers;
    }

    /// @notice Standard key hash for image field.
    bytes32 public constant KEY_IMAGE = keccak256("image");
    /// @notice Standard key hash for channels field.
    bytes32 public constant KEY_CHANNELS = keccak256("channels");
    /// @notice Standard key hash for foreignIds field.
    bytes32 public constant KEY_FOREIGN_IDS = keccak256("foreignIds");
    /// @notice Standard key hash for doc field.
    bytes32 public constant KEY_DOC = keccak256("doc");

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.META_SLOT;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Set a raw metadata value (no events).
    function set(bytes32 entityHash, bytes32 keyHash, bytes calldata value) internal {
        Layout storage l;
        bytes32 slot = StorageKeys.META_SLOT;
        assembly {
            l.slot := slot
        }
        l.meta[entityHash][keyHash] = value;
    }

    /// @notice Get a raw metadata value (empty bytes if unset).
    function get(bytes32 entityHash, bytes32 keyHash) internal view returns (bytes memory) {
        Layout storage l;
        bytes32 slot = StorageKeys.META_SLOT;
        assembly {
            l.slot := slot
        }
        return l.meta[entityHash][keyHash];
    }

    /// @notice Set a string metadata value (ABI-encoded).
    function setString(bytes32 entityHash, bytes32 keyHash, string memory s) internal {
        Layout storage l;
        bytes32 slot = StorageKeys.META_SLOT;
        assembly {
            l.slot := slot
        }
        l.meta[entityHash][keyHash] = abi.encode(s);
    }

    /// @notice Get a string metadata value with existence flag.
    function getStringFound(bytes32 entityHash, bytes32 keyHash) internal view returns (bool found, string memory out) {
        bytes memory v = get(entityHash, keyHash);
        if (v.length == 0) return (false, "");
        return (true, abi.decode(v, (string)));
    }

    /// @notice Delete a raw metadata value.
    function del(bytes32 entityHash, bytes32 keyHash) internal {
        Layout storage l;
        bytes32 slot = StorageKeys.META_SLOT;
        assembly {
            l.slot := slot
        }
        delete l.meta[entityHash][keyHash];
    }

    /// @notice Convenience getter for decoding a string value (empty string when unset).
    function getString(bytes32 entityHash, bytes32 keyHash) internal view returns (string memory) {
        bytes memory v = get(entityHash, keyHash);
        if (v.length == 0) return "";
        return abi.decode(v, (string));
    }
}

library PolicyStateStorage {
    /// @title PolicyStateStorage
    /// @notice Policy-owned typed values, scoped meters, and transient execution context.
    struct UintRecord {
        uint256 value;
        bool exists;
    }

    struct Layout {
        mapping(bytes32 => UintRecord) uints;
        mapping(bytes32 => uint256) meters;
        mapping(bytes32 => uint256) policyEpochs;
        bytes32 activePolicyId;
        address activeExecutor;
        address activeRunner;
        mapping(bytes32 => UintRecord) queuedUintWriteEpochs;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.POLICY_STATE_SLOT;
        assembly {
            l.slot := slot
        }
    }

    function bumpPolicyEpoch(bytes32 policyId) internal {
        Layout storage l = PolicyStateStorage.getLayout();
        unchecked {
            l.policyEpochs[policyId] = l.policyEpochs[policyId] + 1;
        }
    }

    function policyEpoch(bytes32 policyId) internal view returns (uint256) {
        return PolicyStateStorage.getLayout().policyEpochs[policyId];
    }

    function uintKey(bytes32 policyId, bytes32 namespace, bytes32 subject, bytes32 key)
        internal
        view
        returns (bytes32 h)
    {
        uint256 epoch = PolicyStateStorage.getLayout().policyEpochs[policyId];
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, policyId)
            mstore(add(ptr, 0x20), epoch)
            mstore(add(ptr, 0x40), namespace)
            mstore(add(ptr, 0x60), subject)
            mstore(add(ptr, 0x80), key)
            h := keccak256(ptr, 0xA0)
            mstore(0x40, add(ptr, 0xA0))
        }
    }

    function meterScope(bytes32 policyId, bytes32 meterId, bytes32 d0, bytes32 d1, bytes32 d2, bytes32 d3)
        internal
        view
        returns (bytes32 h)
    {
        uint256 epoch = PolicyStateStorage.getLayout().policyEpochs[policyId];
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, policyId)
            mstore(add(ptr, 0x20), epoch)
            mstore(add(ptr, 0x40), meterId)
            mstore(add(ptr, 0x60), d0)
            mstore(add(ptr, 0x80), d1)
            mstore(add(ptr, 0xA0), d2)
            mstore(add(ptr, 0xC0), d3)
            h := keccak256(ptr, 0xE0)
            mstore(0x40, add(ptr, 0xE0))
        }
    }

    function meterBucketKey(bytes32 scope, uint64 windowSeconds, uint256 bucket) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, scope)
            mstore(add(ptr, 0x20), windowSeconds)
            mstore(add(ptr, 0x40), bucket)
            h := keccak256(ptr, 0x60)
            mstore(0x40, add(ptr, 0x60))
        }
    }
}

library CapabilitiesStorage {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableSet for EnumerableSet.AddressSet;

    error GroupCapabilityIndexIncomplete(bytes32 groupId);

    struct Capability {
        EnumerableSet.Bytes32Set groups;
        EnumerableSet.AddressSet actors;
    }

    struct Layout {
        mapping(bytes32 => Capability) capabilities;
        bool actorGrantsLocked;
        mapping(bytes32 => uint256) groupRefCount;
        mapping(bytes32 => EnumerableSet.Bytes32Set) capabilitiesByGroup;
    }

    function getLayout() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.CAPABILITIES_SLOT;
        assembly {
            l.slot := slot
        }
    }

    function capability(Layout storage L, bytes32 capabilityId) internal view returns (Capability storage) {
        return L.capabilities[capabilityId];
    }

    /// @notice Returns the number of capability assignments currently referencing a group.
    function groupRefs(Layout storage L, bytes32 groupId) internal view returns (uint256) {
        return L.groupRefCount[groupId];
    }

    /// @notice Increments the live capability reference count for a group.
    function incrementGroupRef(Layout storage L, bytes32 groupId, bytes32 capabilityId) internal {
        GroupReferenceLimits.addReference(groupId);
        bool added = L.capabilitiesByGroup[groupId].add(capabilityId);
        assert(added);
        L.groupRefCount[groupId] += 1;
    }

    /// @notice Decrements the live capability reference count for a group.
    function decrementGroupRef(Layout storage L, bytes32 groupId, bytes32 capabilityId) internal {
        GroupReferenceLimits.removeReference(groupId);
        bool removed = L.capabilitiesByGroup[groupId].remove(capabilityId);
        assert(removed);
        L.groupRefCount[groupId] -= 1;
    }

    /// @notice Enumerate every affected capability, including custom ids, and verify reverse-index completeness.
    function groupCapabilities(Layout storage L, bytes32 groupId) internal view returns (bytes32[] memory) {
        if (L.capabilitiesByGroup[groupId].length() != L.groupRefCount[groupId]) {
            // An incomplete index would omit a capability grant/revoke requirement; fail the whole write.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert GroupCapabilityIndexIncomplete(groupId);
        }
        return L.capabilitiesByGroup[groupId].values();
    }
}
