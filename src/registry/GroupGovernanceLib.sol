// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {CapabilitiesLib, CapabilityIds} from "./Capabilities.sol";
import {KeccakHelpers as KH} from "./Hashing.sol";
import {CapabilitiesStorage, GroupsStorage, PoliciesStorage} from "./RegistryShared.sol";
import {ExecutionContextLib, TimelockLib, TimelockRequest} from "./TimelockLib.sol";

/// @notice Membership changes carry every capability grant/revoke and policy-edit requirement they affect.
/// @dev Ordinary user/group authorization remains at the entrypoint. These additional checks prevent directory
///      authority from assigning capabilities or rewriting approval groups through live membership changes.
library GroupGovernanceLib {
    bytes32 private constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint256 private constant MAX_REQUIREMENTS = 129;

    struct References {
        bytes32[] capabilities;
        bytes32[] policies;
    }

    function enforceOrQueue(
        bytes32 category,
        bytes32 scope,
        bytes32[] memory groupIds,
        bool adding,
        bytes memory payload
    ) internal returns (bool executing) {
        References[] memory refs = new References[](groupIds.length);
        uint256 capacity = 1 + groupIds.length;
        address actor = ExecutionContextLib.actorOrSender();
        bool admin = IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor);
        bool blockGuardianCancellation = false;
        bool requiresCapabilityAuthority = false;
        bool requiresPolicyAuthority = false;
        for (uint256 i; i < groupIds.length; ++i) {
            refs[i].capabilities = CapabilitiesStorage.groupCapabilities(CapabilitiesStorage.getLayout(), groupIds[i]);
            refs[i].policies = PoliciesStorage.groupPolicies(PoliciesStorage.getLayout(), groupIds[i]);
            if (refs[i].capabilities.length != 0) requiresCapabilityAuthority = true;
            if (refs[i].policies.length != 0) requiresPolicyAuthority = true;
            capacity += refs[i].capabilities.length + refs[i].policies.length;
        }
        // Admission bounds the sum of memberships and their references for each user.
        assert(capacity <= MAX_REQUIREMENTS);
        // These authorities are global to the actor. Check each once after collecting every
        // affected reference, rather than rescanning capability grants for every group.
        _requireAuthority(actor, admin, requiresCapabilityAuthority, requiresPolicyAuthority);

        TimelockRequest[] memory requests = new TimelockRequest[](capacity);
        uint256 count = _append(requests, 0, category, scope);
        for (uint256 i; i < groupIds.length; ++i) {
            // Reverse memberships and each capability index are sets. Only the original group
            // request can repeat; capability scopes include their group and cannot overlap.
            if (category != TimelockLib.categoryGroup() || scope != groupIds[i]) {
                count = _append(requests, count, TimelockLib.categoryGroup(), groupIds[i]);
            }
            for (uint256 j; j < refs[i].capabilities.length; ++j) {
                bytes32 capability = refs[i].capabilities[j];
                count = _append(
                    requests,
                    count,
                    TimelockLib.categoryCapability(),
                    KH.capabilityScope(capability, groupIds[i], adding)
                );
                if (!adding && capability == CapabilityIds.CANCEL_TIMELOCK) blockGuardianCancellation = true;
            }
            for (uint256 j; j < refs[i].policies.length; ++j) {
                count = _appendPolicy(requests, count, refs[i].policies[j]);
            }
        }
        // _append writes at most capacity records; shrink only the logical length to the populated prefix.
        assembly ("memory-safe") {
            mstore(requests, count)
        }
        bytes32 commitment = keccak256(abi.encode(groupIds, requests));
        bytes32 actionId;
        (executing, actionId) =
            TimelockLib.enforceOrQueueBundle(requests, payload, commitment, blockGuardianCancellation);
        if (!executing) {
            GroupsStorage.registerCompactPendingAction(GroupsStorage.getLayout(), actionId, groupIds);
        }
    }

    function _requireAuthority(address actor, bool admin, bool capabilityRequired, bool policyRequired) private view {
        if (admin) return;
        if (capabilityRequired && !CapabilitiesLib.hasCapability(actor, CapabilityIds.CAPABILITY_ADMIN)) {
            revert IAccessControl.AccessControlUnauthorizedAccount(actor, CapabilityIds.CAPABILITY_ADMIN);
        }
        if (
            policyRequired && !CapabilitiesLib.hasCapability(actor, CapabilityIds.DIRECTORY_MANAGER)
                && !CapabilitiesLib.hasCapability(actor, CapabilityIds.POLICY_AUTHOR)
        ) {
            revert IAccessControl.AccessControlUnauthorizedAccount(actor, CapabilityIds.POLICY_AUTHOR);
        }
    }

    function _append(TimelockRequest[] memory requests, uint256 count, bytes32 category, bytes32 scope)
        private
        pure
        returns (uint256)
    {
        requests[count] =
            TimelockRequest({category: category, scope: scope, policyId: bytes32(0), delay: 0, gracePeriod: 0});
        return count + 1;
    }

    /// @dev One policy can reference several affected groups. Require its category/scope only once.
    function _appendPolicy(TimelockRequest[] memory requests, uint256 count, bytes32 policyId)
        private
        pure
        returns (uint256)
    {
        bytes32 category = TimelockLib.categoryPolicy();
        for (uint256 i; i < count; ++i) {
            if (requests[i].category == category && requests[i].scope == policyId) return count;
        }
        return _append(requests, count, category, policyId);
    }
}
