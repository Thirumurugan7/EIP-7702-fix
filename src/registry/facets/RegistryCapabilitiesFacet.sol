// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {KeccakHelpers as KH} from "../../registry/Hashing.sol";
import {CapabilitiesStorage, GroupsStorage} from "../../registry/RegistryShared.sol";
import {ExecutionContextLib, TimelockLib, TimelockRequest} from "../../registry/TimelockLib.sol";
import {DiamondAdminStorage} from "../diamond/DiamondAdminStorage.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

library CapabilityErrors {
    error CapabilityIdEmpty();
    error GroupNotFound();
    error ActorZero();
    error ActorCapabilityNotSystem();
    error ActorContractRequired();
    error ActorGrantsLocked();
}

/// @title RegistryCapabilitiesFacet
/// @notice Assigns registry groups to capability ids for access control.
/// @dev Capabilities are the narrower, protocol-specific alternative to broad admin rights. Facets, factory modules,
///      and runtime contracts use these ids to grant powers such as account management, metadata writes, or contract
///      directory updates without handing out full registry ownership.
contract RegistryCapabilitiesFacet is FacetGuard {
    uint256 public constant VERSION = 1;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 private constant ACTOR_LOCK_SCOPE = keccak256("capability.actor.lock");
    bytes32 private constant DIAMOND_SCOPE = keccak256("diamond.cut");

    error OwnerBootstrapAlreadyFinalized();
    error OwnershipHandoverNotCompleted();
    error RoleGovernanceNotEnabled();
    error FinalizationRoleMissing(bytes32 role, address account);

    event OwnerBootstrapFinalized(address indexed operator);

    /// @notice Link a registry group to a capability.
    function grantCapabilityGroup(bytes32 capability, bytes32 groupHash) external whenNotPausedD nonReentrantD {
        _requireCapabilityAdmin();
        if (capability == bytes32(0)) revert CapabilityErrors.CapabilityIdEmpty();
        if (!GroupsStorage.exists(GroupsStorage.getLayout(), groupHash)) revert CapabilityErrors.GroupNotFound();
        bytes32 scope = _capabilityScope(capability, groupHash, true);
        (bool executing, bytes32 actionId) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryCapability(), scope: scope, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.grantCapabilityGroup.selector, capability, groupHash)
        );
        if (!executing) {
            GroupsStorage.registerPendingMembership(GroupsStorage.getLayout(), actionId, groupHash);
            return;
        }
        // Policy programs run before payload replay; verify the reviewed members again at the grant boundary.
        if (ExecutionContextLib.isActive()) {
            GroupsStorage.requirePendingMemberships(GroupsStorage.getLayout(), ExecutionContextLib.currentActionId());
        }
        CapabilitiesLib.grant(capability, groupHash);
    }

    /// @notice Remove a registry group from a capability assignment.
    function revokeCapabilityGroup(bytes32 capability, bytes32 groupHash) external whenNotPausedD nonReentrantD {
        _requireCapabilityAdmin();
        if (capability == bytes32(0)) revert CapabilityErrors.CapabilityIdEmpty();
        bytes32 scope = _capabilityScope(capability, groupHash, false);
        (bool executing, bytes32 actionId) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryCapability(), scope: scope, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.revokeCapabilityGroup.selector, capability, groupHash)
        );
        if (!executing) {
            GroupsStorage.registerPendingAction(GroupsStorage.getLayout(), actionId, groupHash);
            return;
        }
        CapabilitiesLib.revoke(capability, groupHash);
    }

    /// @notice Link an actor address directly to a capability.
    /// @dev System-only: restricted to capabilities used by protocol-owned helper contracts.
    ///      WebAuthn AuthAccounts should receive registry powers through user/group capability grants instead.
    function grantCapabilityActor(bytes32 capability, address actor) external whenNotPausedD nonReentrantD {
        _requireCapabilityAdmin();
        if (capability == bytes32(0)) revert CapabilityErrors.CapabilityIdEmpty();
        _requireSystemCapability(capability);
        if (CapabilitiesStorage.getLayout().actorGrantsLocked) revert CapabilityErrors.ActorGrantsLocked();
        if (actor == address(0)) revert CapabilityErrors.ActorZero();
        if (actor.code.length == 0 && !_allowUndeployedSystemActor(capability)) {
            revert CapabilityErrors.ActorContractRequired();
        }
        bytes32 scope = _capabilityActorScope(capability, actor, true);
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryCapability(), scope: scope, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.grantCapabilityActor.selector, capability, actor)
        );
        if (!executing) {
            return;
        }
        CapabilitiesLib.grantActor(capability, actor);
    }

    /// @notice Remove an actor address from a capability assignment.
    function revokeCapabilityActor(bytes32 capability, address actor) external whenNotPausedD nonReentrantD {
        _requireCapabilityAdmin();
        if (capability == bytes32(0)) revert CapabilityErrors.CapabilityIdEmpty();
        _requireSystemCapability(capability);
        if (CapabilitiesStorage.getLayout().actorGrantsLocked) revert CapabilityErrors.ActorGrantsLocked();
        if (actor == address(0)) revert CapabilityErrors.ActorZero();
        bytes32 scope = _capabilityActorScope(capability, actor, false);
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryCapability(), scope: scope, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.revokeCapabilityActor.selector, capability, actor)
        );
        if (!executing) {
            return;
        }
        CapabilitiesLib.revokeActor(capability, actor);
    }

    /// @notice Permanently lock capability actor grants/revokes.
    /// @dev Factory stage 1 uses this after pre-authorizing the predicted system actors.
    function lockCapabilityActors() external whenNotPausedD nonReentrantD {
        _requireCapabilityAdmin();
        CapabilitiesStorage.Layout storage cl = CapabilitiesStorage.getLayout();
        if (cl.actorGrantsLocked) revert CapabilityErrors.ActorGrantsLocked();
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryCapability(),
                scope: ACTOR_LOCK_SCOPE,
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            abi.encodeWithSelector(this.lockCapabilityActors.selector)
        );
        if (!executing) {
            return;
        }
        cl.actorGrantsLocked = true;
    }

    /// @notice Return the group identifiers mapped to a capability.
    function getCapabilityGroups(bytes32 capability) external view returns (bytes32[] memory) {
        return CapabilitiesLib.capabilityGroups(capability);
    }

    /// @notice Return the direct actor assignments for a capability.
    function getCapabilityActors(bytes32 capability) external view returns (address[] memory) {
        return CapabilitiesLib.capabilityActors(capability);
    }

    /// @notice Check if an account currently holds a capability (direct actor or group membership).
    function hasCapability(bytes32 capability, address actor) external view returns (bool) {
        return CapabilitiesLib.hasCapability(actor, capability);
    }

    /// @notice Permanently remove `owner()` as an implicit timelock governor.
    /// @dev The caller must already hold the explicit governor capability, which
    ///      prevents finalization from leaving the Registry without a governor.
    function finalizeOwnerBootstrap() external nonReentrantD {
        DiamondAdminStorage.Layout storage admin = DiamondAdminStorage.state();
        if (admin.ownerBootstrapFinalized) revert OwnerBootstrapAlreadyFinalized();
        if (!admin.roleGovernanceEnabled) revert RoleGovernanceNotEnabled();
        if (!admin.ownershipHandoverCompleted) revert OwnershipHandoverNotCompleted();
        address actor = _msgSenderD();
        address currentOwner = _ownerD();
        // The handover flag proves historical alignment. Revalidate the two
        // live roles before permanently removing owner-derived recovery so a
        // post-handover renounce cannot produce false production readiness.
        if (!IAccessControl(address(this)).hasRole(ADMIN_ROLE, currentOwner)) {
            revert FinalizationRoleMissing(ADMIN_ROLE, currentOwner);
        }
        if (!IAccessControl(address(this)).hasRole(UPGRADER_ROLE, currentOwner)) {
            revert FinalizationRoleMissing(UPGRADER_ROLE, currentOwner);
        }
        if (!CapabilitiesLib.hasCapability(actor, CapabilityIds.TIMELOCK_GOVERNOR)) {
            revert AccessControlUnauthorizedAccount(actor, CapabilityIds.TIMELOCK_GOVERNOR);
        }
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryDiamond(),
                scope: DIAMOND_SCOPE,
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            abi.encodeWithSelector(this.finalizeOwnerBootstrap.selector)
        );
        if (!executing) return;
        if (!CapabilitiesLib.hasCapability(actor, CapabilityIds.TIMELOCK_GOVERNOR)) {
            revert AccessControlUnauthorizedAccount(actor, CapabilityIds.TIMELOCK_GOVERNOR);
        }
        admin.ownerBootstrapFinalized = true;
        // Governance changes hold nonReentrantD; role helpers only read Registry storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit OwnerBootstrapFinalized(actor);
    }

    function ownershipHandoverCompleted() external view returns (bool) {
        return DiamondAdminStorage.state().ownershipHandoverCompleted;
    }

    function ownerBootstrapFinalized() external view returns (bool) {
        return DiamondAdminStorage.state().ownerBootstrapFinalized;
    }

    function _capabilityScope(bytes32 capability, bytes32 groupHash, bool grantOp) private pure returns (bytes32) {
        return KH.capabilityScope(capability, groupHash, grantOp);
    }

    function _capabilityActorScope(bytes32 capability, address actor, bool grantOp) private pure returns (bytes32) {
        return KH.capabilityActorScope(capability, actor, grantOp);
    }

    function _requireSystemCapability(bytes32 capability) private pure {
        if (capability == CapabilityIds.ACCOUNT_MANAGER || capability == CapabilityIds.POLICY_STATE_RUNNER) {
            return;
        }
        revert CapabilityErrors.ActorCapabilityNotSystem();
    }

    function _allowUndeployedSystemActor(bytes32 capability) private pure returns (bool) {
        return capability == CapabilityIds.ACCOUNT_MANAGER || capability == CapabilityIds.POLICY_STATE_RUNNER;
    }

    function _requireCapabilityAdmin() private view {
        address actor = _msgSenderD();
        if (IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor)) {
            return;
        }
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.CAPABILITY_ADMIN)) {
            return;
        }
        revert AccessControlUnauthorizedAccount(actor, ADMIN_ROLE);
    }
}
