// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {Delegation7702} from "../Delegation7702.sol";
import {CapabilitiesStorage, GroupsStorage} from "./RegistryShared.sol";

/// @title CapabilityIds
/// @notice Canonical capability identifiers understood by registry facets and runtime contracts.
/// @dev These ids let the protocol delegate narrow powers to groups or specific
///      system actors without handing out blanket admin rights.
library CapabilityIds {
    bytes32 internal constant CONTRACT_WRITE = keccak256("cap.registry.contract.write");
    bytes32 internal constant DIRECTORY_MANAGER = keccak256("cap.directory.manage");
    bytes32 internal constant USER_ONBOARDER = keccak256("cap.directory.user.write");
    bytes32 internal constant GROUP_CURATOR = keccak256("cap.directory.group.write");
    bytes32 internal constant POLICY_AUTHOR = keccak256("cap.directory.policy.write");
    bytes32 internal constant REGISTRY_MANAGER = keccak256("cap.registry.manage");
    bytes32 internal constant ORG_MANAGER = keccak256("cap.registry.org.write");
    bytes32 internal constant TOKEN_MANAGER = keccak256("cap.registry.token.write");
    bytes32 internal constant INTERACTION_AUTHOR = keccak256("cap.registry.interaction.write");
    bytes32 internal constant INTERACTION_EXECUTOR = keccak256("cap.registry.interaction.execute");
    bytes32 internal constant METADATA_MANAGER = keccak256("cap.registry.metadata.write");
    bytes32 internal constant AUTH_MANAGER = keccak256("cap.registry.auth.write");
    bytes32 internal constant ACCOUNT_MANAGER = keccak256("cap.registry.account.write");
    bytes32 internal constant POLICY_STATE_RUNNER = keccak256("cap.registry.policy_state.run");
    /// @notice Narrow authority to seal sufficiently large Registry index epochs.
    bytes32 internal constant INDEX_MAINTAINER = keccak256("cap.registry.index.maintain");
    bytes32 internal constant CAPABILITY_ADMIN = keccak256("cap.registry.capability.write");
    bytes32 internal constant TIMELOCK_GOVERNOR = keccak256("cap.registry.timelock.write");
    bytes32 internal constant PAUSE_OPERATOR = keccak256("cap.registry.pause");
    /// @notice Capability to cancel any queued or ready Registry timelock action.
    bytes32 internal constant CANCEL_TIMELOCK = keccak256("cap.registry.timelock.cancel");
    /// @notice Capability to cancel another committer's private interaction commitment.
    bytes32 internal constant CANCEL_INTERACTION = keccak256("cap.registry.interaction.cancel");
    /// @notice Capability to cancel another submitter's pending Interact operation.
    bytes32 internal constant CANCEL_OPERATION = keccak256("cap.interact.operation.cancel");
    /// @notice Capability required to grant governed registry admin roles after role governance is enabled.
    bytes32 internal constant GRANT_ADMIN = keccak256("cap.registry.admin.grant");
    /// @notice Capability required to revoke governed registry admin roles after role governance is enabled.
    bytes32 internal constant REVOKE_ADMIN = keccak256("cap.registry.admin.revoke");
}

/// @title CapabilitiesLib
/// @notice Shared helpers for granting, revoking, and evaluating registry capabilities.
/// @dev Capability checks combine two sources:
///      - direct actor assignments, mainly for protocol system contracts
///      - group assignments, mainly for human operators managed through the registry
///
///      Example:
///      - governance maps `GROUP_CURATOR` to a reviewer group
///      - the same governance maps `ACCOUNT_MANAGER` directly to predicted factory actors
///      - facets can then authorize both humans and system contracts through one model
library CapabilitiesLib {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableSet for EnumerableSet.AddressSet;

    error CapabilityGroupExists();
    error CapabilityGroupMissing();
    error CapabilityActorExists();
    error CapabilityActorMissing();

    event CapabilityGroupGranted(bytes32 indexed capability, bytes32 indexed groupHash);
    event CapabilityGroupRevoked(bytes32 indexed capability, bytes32 indexed groupHash);
    event CapabilityActorGranted(bytes32 indexed capability, address indexed actor);
    event CapabilityActorRevoked(bytes32 indexed capability, address indexed actor);

    /// @notice Grant `groupHash` the capability `capability`.
    function grant(bytes32 capability, bytes32 groupHash) internal {
        CapabilitiesStorage.Layout storage L = CapabilitiesStorage.getLayout();
        if (!CapabilitiesStorage.capability(L, capability).groups.add(groupHash)) {
            revert CapabilityGroupExists();
        }
        CapabilitiesStorage.incrementGroupRef(L, groupHash, capability);
        // EnumerableSet and capability helpers are internal storage operations, with no mutable external call
        // before this event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit CapabilityGroupGranted(capability, groupHash);
    }

    /// @notice Revoke `groupHash` from capability `capability`.
    function revoke(bytes32 capability, bytes32 groupHash) internal {
        CapabilitiesStorage.Layout storage L = CapabilitiesStorage.getLayout();
        if (!CapabilitiesStorage.capability(L, capability).groups.remove(groupHash)) {
            revert CapabilityGroupMissing();
        }
        CapabilitiesStorage.decrementGroupRef(L, groupHash, capability);
        // EnumerableSet and capability helpers are internal storage operations, with no mutable external call
        // before this event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit CapabilityGroupRevoked(capability, groupHash);
    }

    /// @notice Grant `actor` the capability `capability`.
    function grantActor(bytes32 capability, address actor) internal {
        CapabilitiesStorage.Layout storage L = CapabilitiesStorage.getLayout();
        if (!CapabilitiesStorage.capability(L, capability).actors.add(actor)) {
            revert CapabilityActorExists();
        }
        // EnumerableSet and capability helpers are internal storage operations, with no mutable external call
        // before this event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit CapabilityActorGranted(capability, actor);
    }

    /// @notice Revoke `actor` from capability `capability`.
    function revokeActor(bytes32 capability, address actor) internal {
        CapabilitiesStorage.Layout storage L = CapabilitiesStorage.getLayout();
        if (!CapabilitiesStorage.capability(L, capability).actors.remove(actor)) {
            revert CapabilityActorMissing();
        }
        // EnumerableSet and capability helpers are internal storage operations, with no mutable external call
        // before this event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit CapabilityActorRevoked(capability, actor);
    }

    /// @notice Return every registry group currently mapped to `capability`.
    function capabilityGroups(bytes32 capability) internal view returns (bytes32[] memory groups) {
        CapabilitiesStorage.Layout storage L = CapabilitiesStorage.getLayout();
        EnumerableSet.Bytes32Set storage set = CapabilitiesStorage.capability(L, capability).groups;
        uint256 len = set.length();
        groups = new bytes32[](len);
        for (uint256 i; i < len; ++i) {
            groups[i] = set.at(i);
        }
    }

    /// @notice Return whether `groupHash` is directly assigned to `capability`.
    function capabilityHasGroup(bytes32 capability, bytes32 groupHash) internal view returns (bool) {
        CapabilitiesStorage.Layout storage L = CapabilitiesStorage.getLayout();
        return CapabilitiesStorage.capability(L, capability).groups.contains(groupHash);
    }

    /// @notice Return whether `capability` has any group or direct actor assignment.
    function isConfigured(bytes32 capability) internal view returns (bool) {
        CapabilitiesStorage.Layout storage L = CapabilitiesStorage.getLayout();
        CapabilitiesStorage.Capability storage cap = CapabilitiesStorage.capability(L, capability);
        return cap.groups.length() != 0 || cap.actors.length() != 0;
    }

    /// @notice Return every directly assigned actor currently mapped to `capability`.
    function capabilityActors(bytes32 capability) internal view returns (address[] memory actors) {
        CapabilitiesStorage.Layout storage L = CapabilitiesStorage.getLayout();
        EnumerableSet.AddressSet storage set = CapabilitiesStorage.capability(L, capability).actors;
        uint256 len = set.length();
        actors = new address[](len);
        for (uint256 i; i < len; ++i) {
            actors[i] = set.at(i);
        }
    }

    /// @notice Return whether `actor` currently holds `capability`.
    /// @dev Direct actors must still have deployed code of their own. This prevents an EOA
    ///      from inheriting a system-only capability that was intended for a contract. An EIP-7702
    ///      designator (exactly 23 bytes) is not contract code, so a direct actor needs more code than
    ///      that; system actors are proxies and factories, far larger. The length comparison adds no
    ///      bytecode to the many facets that inline this library.
    ///      The EIP-7702 actor rule for group-held capabilities is applied where the question is asked:
    ///      for callers in `ExecutionContextLib.actorOrSender()`, for third parties in
    ///      `RegistryCapabilitiesFacet.hasCapability`.
    function hasCapability(address actor, bytes32 capability) internal view returns (bool) {
        CapabilitiesStorage.Layout storage L = CapabilitiesStorage.getLayout();
        CapabilitiesStorage.Capability storage cap = CapabilitiesStorage.capability(L, capability);
        if (cap.actors.contains(actor)) {
            return actor.code.length > Delegation7702.DESIGNATOR_LENGTH;
        }
        EnumerableSet.Bytes32Set storage set = cap.groups;
        uint256 len = set.length();
        if (len == 0) return false;
        GroupsStorage.Layout storage gl = GroupsStorage.getLayout();
        for (uint256 i; i < len; ++i) {
            bytes32 groupHash = set.at(i);
            if (GroupsStorage.exists(gl, groupHash) && GroupsStorage.isMember(gl, groupHash, actor)) {
                return true;
            }
        }
        return false;
    }

    /// @notice Return whether `actor` holds a direct system capability assignment.
    /// @dev Group membership is intentionally ignored for protocol actor capabilities.
    function hasDirectActorCapability(address actor, bytes32 capability) internal view returns (bool) {
        CapabilitiesStorage.Layout storage L = CapabilitiesStorage.getLayout();
        CapabilitiesStorage.Capability storage cap = CapabilitiesStorage.capability(L, capability);
        return cap.actors.contains(actor) && actor.code.length > Delegation7702.DESIGNATOR_LENGTH;
    }
}
