// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {PagedIndex} from "../../PagedIndex.sol";
import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {CapabilitiesStorage, GroupsStorage, PoliciesStorage, UserAddrsStorage} from "../../registry/RegistryShared.sol";
import {TimelockLib, TimelockRequest} from "../../registry/TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {RegistryGroupGovernanceModule} from "./RegistryGroupGovernanceModule.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title RegistryUsersFacet
 * @notice User allowlist and group management.
 * @dev This facet is invoked via delegatecall from the `RegistryDiamond` dispatcher.
 *      - Allowlist and group writes are admin-gated and paused by `Pausable`.
 *      - Groups created here are later consumed by policies and capabilities.
 *      - Removing a user also strips that user out of every group tracked by the registry.
 */
contract RegistryUsersFacet is FacetGuard {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using PagedIndex for PagedIndex.Index;

    uint256 public constant VERSION = 1;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint256 internal constant MAX_GROUPS_PER_USER = 128;
    RegistryGroupGovernanceModule private immutable GOVERNANCE_MODULE = new RegistryGroupGovernanceModule();

    /// @notice Emitted when a user is added to the global allowlist.
    event UserAdded(address indexed user);
    /// @notice Emitted when a user is removed from the global allowlist.
    event UserRemoved(address indexed user);
    /// @notice Emitted when a new group id is created.
    event GroupCreated(bytes32 indexed id);
    /// @notice Emitted when a group id is deleted after all references are cleared.
    event GroupDeleted(bytes32 indexed id);
    /// @notice Emitted when a user joins a group.
    event UserAddedToGroup(address indexed user, bytes32 indexed groupId);
    /// @notice Emitted when a user leaves a group.
    event UserRemovedFromGroup(address indexed user, bytes32 indexed groupId);

    error AlreadyMember();
    error NotMember();
    error GroupNotFound();
    error GroupExists();
    error GroupNotEmpty(bytes32 groupId);
    error GroupInUseByPolicy(bytes32 groupId);
    error GroupInUseByCapability(bytes32 groupId);
    error GroupInUseByPendingAction(bytes32 groupId, bytes32 actionId);
    error UserExists();
    error UserMissing();
    error EmptyId();
    error TooManyGroupMemberships(address user);
    // Preserve dependency diagnostics and review events forwarded by the immutable governance module.
    error GroupCapabilityIndexIncomplete(bytes32 groupId);
    error GroupPolicyIndexIncomplete(bytes32 groupId);
    error TimelockGovernanceChanged(bytes32 actionId);
    error TooManyPendingActions();
    event ActionBundled(bytes32 indexed rootActionId, bytes32 indexed actionId);
    event ActionRequirement(bytes32 indexed rootActionId, bytes32 indexed category, bytes32 indexed scope);

    function _enforceMembership(
        bytes32 category,
        bytes32 scope,
        bytes32[] memory groupIds,
        bool adding,
        bytes memory payload
    ) private returns (bool) {
        address module = address(GOVERNANCE_MODULE);
        // The users facet's pinned runtime embeds the constructor-deployed module address.
        // The module has no upgrade, destruction, or mutable delegation path.
        // forge-lint: disable-start(controlled-delegatecall)
        (bool ok, bytes memory result) = module.delegatecall(
            abi.encodeCall(RegistryGroupGovernanceModule.enforceOrQueue, (category, scope, groupIds, adding, payload))
        );
        // forge-lint: disable-end(controlled-delegatecall)
        if (!ok) {
            assembly ("memory-safe") { revert(add(result, 32), mload(result)) }
        }
        return abi.decode(result, (bool));
    }

    // Users allowlist
    /// @notice Adds an address to the user allowlist.
    /// @param user Address to allowlist; must be non-zero and not already present.
    function addUser(address user) external whenNotPausedD nonReentrantD {
        _requireUserWriteRole();
        if (user == address(0)) revert("user=0");
        bytes32 scope = bytes32(uint256(uint160(user)));
        UserAddrsStorage.Layout storage ua = UserAddrsStorage.getLayout();
        if (UserAddrsStorage.contains(ua, user)) revert UserExists();

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryUser(), scope: scope, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.addUser.selector, user)
        );
        if (!executing) {
            return;
        }

        if (UserAddrsStorage.contains(ua, user)) revert UserExists();
        UserAddrsStorage.add(ua, user);
        // User/group entrypoints hold nonReentrantD; membership and index helpers operate on local
        // Registry storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit UserAdded(user);
    }

    /// @notice Removes an address from the user allowlist.
    /// @param user Address to remove; emits UserRemovedFromGroup for any groups affected.
    /// @dev Reverse membership indexing and the per-user membership cap keep this
    ///      cleanup bounded independently of the registry's total group count.
    function removeUser(address user) external whenNotPausedD nonReentrantD {
        _requireUserWriteRole();
        bytes32 scope = bytes32(uint256(uint160(user)));
        UserAddrsStorage.Layout storage ua = UserAddrsStorage.getLayout();
        if (!UserAddrsStorage.contains(ua, user)) revert UserMissing();
        GroupsStorage.Layout storage gl = GroupsStorage.getLayout();
        // Enforce the per-user bound before iterating reverse memberships.
        if (GroupsStorage.memberGroupCount(gl, user) > MAX_GROUPS_PER_USER) {
            revert TooManyGroupMemberships(user);
        }

        bytes32[] memory groupIds = new bytes32[](GroupsStorage.memberGroupCount(gl, user));
        for (uint256 i; i < groupIds.length; ++i) {
            groupIds[i] = GroupsStorage.memberGroupAt(gl, user, i);
        }
        bool executing = _enforceMembership(
            TimelockLib.categoryUser(), scope, groupIds, false, abi.encodeWithSelector(this.removeUser.selector, user)
        );
        if (!executing) {
            return;
        }

        if (!UserAddrsStorage.contains(ua, user)) revert UserMissing();
        if (GroupsStorage.memberGroupCount(gl, user) > MAX_GROUPS_PER_USER) {
            revert TooManyGroupMemberships(user);
        }
        while (GroupsStorage.memberGroupCount(gl, user) != 0) {
            bytes32 groupId = GroupsStorage.memberGroupAt(gl, user, GroupsStorage.memberGroupCount(gl, user) - 1);
            GroupsStorage.removeMember(gl, groupId, user);
            _touchGroupIndex(gl, groupId);
            // User/group entrypoints hold nonReentrantD; membership and index helpers operate on local
            // Registry storage.
            // forge-lint: disable-next-line(reentrancy-events)
            emit UserRemovedFromGroup(user, gl.groups[groupId].id);
        }
        UserAddrsStorage.remove(ua, user);
        // User/group entrypoints hold nonReentrantD; membership and index helpers operate on local
        // Registry storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit UserRemoved(user);
    }

    /// @notice Checks if an address is in the allowlist.
    /// @param user Address to check.
    /// @return True if allowlisted.
    function isUser(address user) external view returns (bool) {
        UserAddrsStorage.Layout storage ua = UserAddrsStorage.getLayout();
        return UserAddrsStorage.contains(ua, user);
    }

    /// @notice Returns the number of allowlisted users.
    /// @return count Number of allowlisted users.
    function getUserCount() external view returns (uint256) {
        UserAddrsStorage.Layout storage ua = UserAddrsStorage.getLayout();
        return UserAddrsStorage.length(ua);
    }

    /// @notice Returns the allowlisted user at index.
    /// @param index Position in the allowlist.
    /// @return addr Address at the given index.
    function getUserAt(uint256 index) external view returns (address) {
        UserAddrsStorage.Layout storage ua = UserAddrsStorage.getLayout();
        return UserAddrsStorage.valueAt(ua, index);
    }

    // Groups
    /// @notice Creates a new group.
    /// @param groupId Canonical group identifier (32 bytes, opaque).
    /// @return groupHash Hash key of the created group.
    function createGroup(bytes32 groupId) external whenNotPausedD nonReentrantD returns (bytes32 groupHash) {
        _requireGroupWriteRole();
        if (groupId == bytes32(0)) revert EmptyId();
        GroupsStorage.Layout storage gl = GroupsStorage.getLayout();
        if (GroupsStorage.exists(gl, groupId)) revert GroupExists();

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryGroup(), scope: groupId, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.createGroup.selector, groupId)
        );
        if (!executing) {
            return groupId;
        }

        if (GroupsStorage.exists(gl, groupId)) revert GroupExists();
        gl.groups[groupId].id = groupId;
        GroupsStorage.bumpMembershipRevision(gl, groupId);
        gl.groupIds.insert(groupId);
        // User/group entrypoints hold nonReentrantD; membership and index helpers operate on local
        // Registry storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit GroupCreated(groupId);
        return groupId;
    }

    /// @notice Deletes a group once it has no members and no live policy or capability references.
    /// @param groupId Canonical group identifier (32 bytes, opaque).
    function deleteGroup(bytes32 groupId) external whenNotPausedD nonReentrantD {
        _requireGroupWriteRole();
        GroupsStorage.Layout storage gl = GroupsStorage.getLayout();
        if (!GroupsStorage.exists(gl, groupId)) revert GroupNotFound();

        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryGroup(), scope: groupId, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.deleteGroup.selector, groupId)
        );
        if (!executing) {
            return;
        }

        if (!GroupsStorage.exists(gl, groupId)) revert GroupNotFound();
        if (GroupsStorage.memberCount(gl, groupId) != 0) revert GroupNotEmpty(groupId);
        if (PoliciesStorage.groupRefs(PoliciesStorage.getLayout(), groupId) != 0) {
            revert GroupInUseByPolicy(groupId);
        }
        if (CapabilitiesStorage.groupRefs(CapabilitiesStorage.getLayout(), groupId) != 0) {
            revert GroupInUseByCapability(groupId);
        }
        bytes32 blockingActionId = GroupsStorage.pendingAction(gl, groupId);
        if (blockingActionId != bytes32(0)) {
            revert GroupInUseByPendingAction(groupId, blockingActionId);
        }

        gl.groupIds.removeValue(groupId);
        GroupsStorage.bumpMembershipRevision(gl, groupId);
        // The checks above require an empty member set and no live references; member removal clears set entries.
        // forge-lint: disable-next-line(mapping-deletion)
        delete gl.groups[groupId];
        // User/group entrypoints hold nonReentrantD; membership and index helpers operate on local
        // Registry storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit GroupDeleted(groupId);
    }

    /// @notice Adds a user to a group under group governance and every affected capability/policy requirement.
    /// @param groupHash Group key (hash of label).
    /// @param user Address to add; must be allowlisted.
    function addGroupMember(bytes32 groupHash, address user) external whenNotPausedD nonReentrantD {
        _requireGroupWriteRole();
        GroupsStorage.Layout storage gl = GroupsStorage.getLayout();
        if (!GroupsStorage.exists(gl, groupHash)) revert GroupNotFound();
        UserAddrsStorage.Layout storage ua = UserAddrsStorage.getLayout();
        if (!UserAddrsStorage.contains(ua, user)) revert UserMissing();
        if (GroupsStorage.isMember(gl, groupHash, user)) revert AlreadyMember();
        if (GroupsStorage.memberGroupCount(gl, user) >= MAX_GROUPS_PER_USER) {
            revert TooManyGroupMemberships(user);
        }

        bytes32[] memory groupIds = new bytes32[](1);
        groupIds[0] = groupHash;
        bool executing = _enforceMembership(
            TimelockLib.categoryGroup(),
            groupHash,
            groupIds,
            true,
            abi.encodeWithSelector(this.addGroupMember.selector, groupHash, user)
        );
        if (!executing) {
            return;
        }

        if (!GroupsStorage.exists(gl, groupHash)) revert GroupNotFound();
        if (!UserAddrsStorage.contains(ua, user)) revert UserMissing();
        if (GroupsStorage.isMember(gl, groupHash, user)) revert AlreadyMember();
        if (GroupsStorage.memberGroupCount(gl, user) >= MAX_GROUPS_PER_USER) {
            revert TooManyGroupMemberships(user);
        }
        GroupsStorage.addMember(gl, groupHash, user);
        _touchGroupIndex(gl, groupHash);
        // User/group entrypoints hold nonReentrantD; membership and index helpers operate on local
        // Registry storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit UserAddedToGroup(user, gl.groups[groupHash].id);
    }

    /// @notice Removes a user under group governance and every affected capability/policy requirement.
    /// @param groupHash Group key (hash of label).
    /// @param user Address to remove.
    function removeGroupMember(bytes32 groupHash, address user) external whenNotPausedD nonReentrantD {
        _requireGroupWriteRole();
        GroupsStorage.Layout storage gl = GroupsStorage.getLayout();
        if (!GroupsStorage.exists(gl, groupHash)) revert GroupNotFound();
        if (!GroupsStorage.isMember(gl, groupHash, user)) revert NotMember();

        bytes32[] memory groupIds = new bytes32[](1);
        groupIds[0] = groupHash;
        bool executing = _enforceMembership(
            TimelockLib.categoryGroup(),
            groupHash,
            groupIds,
            false,
            abi.encodeWithSelector(this.removeGroupMember.selector, groupHash, user)
        );
        if (!executing) {
            return;
        }

        if (!GroupsStorage.exists(gl, groupHash)) revert GroupNotFound();
        if (!GroupsStorage.isMember(gl, groupHash, user)) revert NotMember();
        GroupsStorage.removeMember(gl, groupHash, user);
        _touchGroupIndex(gl, groupHash);
        // User/group entrypoints hold nonReentrantD; membership and index helpers operate on local
        // Registry storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit UserRemovedFromGroup(user, gl.groups[groupHash].id);
    }

    /// @notice Returns group member count.
    /// @param groupHash Group key (hash of label).
    /// @return memberCount Number of members.
    function getGroupInfo(bytes32 groupHash) external view returns (uint256 memberCount) {
        GroupsStorage.Layout storage gl = GroupsStorage.getLayout();
        if (!GroupsStorage.exists(gl, groupHash)) revert GroupNotFound();
        return GroupsStorage.memberCount(gl, groupHash);
    }

    /// @notice Return the generation of the exact current membership set.
    function getGroupMembershipRevision(bytes32 groupHash) external view returns (uint64) {
        GroupsStorage.Layout storage gl = GroupsStorage.getLayout();
        if (!GroupsStorage.exists(gl, groupHash)) revert GroupNotFound();
        return GroupsStorage.currentMembershipRevision(gl, groupHash);
    }

    /// @notice Returns total number of groups.
    function getGroupCount() external view returns (uint256) {
        return GroupsStorage.getLayout().groupIds.length();
    }

    /// @notice Returns group key at index.
    function getGroupKeyAt(uint256 index) external view returns (bytes32) {
        return GroupsStorage.getLayout().groupIds.valueAt(index);
    }

    /// @notice Returns a page of group keys for pagination UIs.
    function getGroupKeysPage(uint256 start, uint256 count) external view returns (bytes32[] memory) {
        return GroupsStorage.getLayout().groupIds.page(start, count);
    }

    function getGroupIndexNextId() external view returns (uint256) {
        return GroupsStorage.getLayout().groupIds.nextId();
    }

    function getGroupIndexCurrentEpoch() external view returns (uint64) {
        return GroupsStorage.getLayout().groupIds.currentEpoch;
    }

    function getGroupIndexAlivePage(uint256 pageIndex) external view returns (uint256) {
        return GroupsStorage.getLayout().groupIds.alivePage(pageIndex);
    }

    function getGroupIndexValues(uint256[] calldata ids) external view returns (bytes32[] memory) {
        return GroupsStorage.getLayout().groupIds.getValues(ids);
    }

    function getGroupIndexEpochPageCount(uint64 epoch) external view returns (uint256) {
        return GroupsStorage.getLayout().groupIds.epochPageCount(epoch);
    }

    function getGroupIndexEpochPageAt(uint64 epoch, uint256 i) external view returns (uint128) {
        return GroupsStorage.getLayout().groupIds.epochPageAt(epoch, i);
    }

    function getGroupIndexJournal(uint64 epoch, uint128 pageIndex)
        external
        view
        returns (uint256 updates, uint256 deletes)
    {
        return GroupsStorage.getLayout().groupIds.journal(epoch, pageIndex);
    }

    /// @notice Checks membership by group key.
    function isGroupMemberByHash(bytes32 groupHash, address user) external view returns (bool) {
        GroupsStorage.Layout storage gl = GroupsStorage.getLayout();
        if (!GroupsStorage.exists(gl, groupHash)) return false;
        return GroupsStorage.isMember(gl, groupHash, user);
    }

    /// @notice Returns all group members. For large groups prefer paging in client.
    function getGroupMembers(bytes32 groupHash) external view returns (address[] memory members) {
        GroupsStorage.Layout storage gl = GroupsStorage.getLayout();
        if (!GroupsStorage.exists(gl, groupHash)) return new address[](0);
        uint256 len = gl.groups[groupHash].members.length();
        members = new address[](len);
        for (uint256 i = 0; i < len;) {
            members[i] = gl.groups[groupHash].members.at(i);
            unchecked {
                ++i;
            }
        }
    }

    // Helpers
    function _requireUserWriteRole() private view {
        address actor = _msgSenderD();
        if (_canManageUsers(actor)) {
            return;
        }
        revert AccessControlUnauthorizedAccount(actor, ADMIN_ROLE);
    }

    function _requireGroupWriteRole() private view {
        address actor = _msgSenderD();
        if (_canManageGroups(actor)) {
            return;
        }
        revert AccessControlUnauthorizedAccount(actor, ADMIN_ROLE);
    }

    function _canManageUsers(address actor) private view returns (bool) {
        return _isAdmin(actor) || CapabilitiesLib.hasCapability(actor, CapabilityIds.DIRECTORY_MANAGER)
            || CapabilitiesLib.hasCapability(actor, CapabilityIds.USER_ONBOARDER);
    }

    function _canManageGroups(address actor) private view returns (bool) {
        return _isAdmin(actor) || CapabilitiesLib.hasCapability(actor, CapabilityIds.DIRECTORY_MANAGER)
            || CapabilitiesLib.hasCapability(actor, CapabilityIds.GROUP_CURATOR);
    }

    function _touchGroupIndex(GroupsStorage.Layout storage gl, bytes32 groupId) private {
        (uint256 id, bool exists_) = gl.groupIds.idOf(groupId);
        if (exists_) {
            gl.groupIds.update(id, groupId);
        }
    }

    function _isAdmin(address actor) private view returns (bool) {
        return IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor);
    }
}
