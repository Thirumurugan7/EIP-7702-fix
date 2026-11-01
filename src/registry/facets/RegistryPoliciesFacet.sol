// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {MiniScriptBytecode} from "../../MiniScriptBytecode.sol";
import {PagedIndex} from "../../PagedIndex.sol";
import {GroupCriteria, Policy} from "../../RegistryTypes.sol";
import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {GroupsStorage, PoliciesStorage, PolicyStateStorage} from "../../registry/RegistryShared.sol";
import {ExecutionContextLib, TimelockLib, TimelockRequest} from "../../registry/TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/**
 * @title RegistryPoliciesFacet
 * @notice CRUD for policy criteria and optional policy programs.
 * @dev Group ids must already exist. Membership is intentionally owned by
 *      RegistryUsersFacet so POLICY_AUTHOR cannot grant itself capabilities.
 *      Policies are consumed by two subsystems:
 *      1. `Interact` operation approval and direct-execution checks.
 *      2. Registry timelock approvals for queued governance actions.
 */
contract RegistryPoliciesFacet is FacetGuard {
    using PagedIndex for PagedIndex.Index;

    uint256 public constant VERSION = 1;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint256 internal constant MAX_POLICY_PROGRAM_BYTES = 8192;
    uint8 internal constant TRANSFER_NATIVE_OPCODE = 0x34;

    error PolicyExists();
    error GroupNotFound();
    error GroupDuplicate();
    error PolicyNotFound();
    error PolicyInUseByConfig(bytes32 policyId);
    error PolicyInUseByPendingAction(bytes32 policyId, bytes32 actionId);
    error PolicyProgramInvalid();

    /// @notice Emitted when a new policy id is created.
    event PolicyCreated(bytes32 indexed policyId);
    /// @notice Emitted whenever the policy's ordered group thresholds change.
    event PolicyCriteriaUpdated(bytes32 indexed policyId, bytes32 criteriaHash);
    /// @notice Emitted when a policy is deleted after all references have been cleared.
    event PolicyDeleted(bytes32 indexed policyId);
    /// @notice Emitted when the optional policy program is written or cleared.
    event PolicyProgramUpdated(bytes32 indexed policyId, bytes32 programHash, uint64 version, uint32 maxSteps);

    /// @notice Create a new policy with group thresholds.
    function createPolicy(bytes32 policyId, bytes32[] calldata groupIds, uint256[] calldata thresholds)
        external
        whenNotPausedD
        nonReentrantD
    {
        _requirePolicyWriteRole();
        require(policyId != bytes32(0), "policyId=0");
        require(groupIds.length == thresholds.length && groupIds.length > 0, "len mismatch");
        PoliciesStorage.Layout storage pl = PoliciesStorage.getLayout();
        if (PoliciesStorage.exists(pl, policyId)) revert PolicyExists();
        (bool executing, bytes32 actionId) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryPolicy(), scope: policyId, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.createPolicy.selector, policyId, groupIds, thresholds)
        );
        if (!executing) {
            _registerPendingGroups(actionId, groupIds);
            return;
        }
        Policy storage p = pl.policies[policyId];
        p.id = policyId;
        _writePolicyCriteria(pl, p, groupIds, thresholds);
        pl.policyIds.insert(policyId);
        // Policy entrypoints hold nonReentrantD; criteria, program, and index helpers mutate only local storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit PolicyCreated(policyId);
        // Policy entrypoints hold nonReentrantD; criteria, program, and index helpers mutate only local storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit PolicyCriteriaUpdated(policyId, keccak256(abi.encode(groupIds, thresholds)));
    }

    /// @notice Create or update policy criteria.
    /// @dev Creates the policy if it does not exist.
    function setPolicy(bytes32 policyId, bytes32[] calldata groupIds, uint256[] calldata thresholds)
        external
        whenNotPausedD
        nonReentrantD
    {
        _requirePolicyWriteRole();
        // `bytes32(0)` is the missing-policy sentinel. Empty criteria are also
        // invalid; use an explicit criterion with threshold zero when a policy
        // intentionally requires no approvals.
        require(policyId != bytes32(0), "policyId=0");
        require(groupIds.length == thresholds.length && groupIds.length > 0, "len mismatch");
        PoliciesStorage.Layout storage pl = PoliciesStorage.getLayout();
        (bool executing, bytes32 actionId) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryPolicy(), scope: policyId, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setPolicy.selector, policyId, groupIds, thresholds)
        );
        if (!executing) {
            _registerPendingGroups(actionId, groupIds);
            return;
        }
        Policy storage p = pl.policies[policyId];
        bool existed = p.id != bytes32(0);
        if (!existed) {
            pl.policyIds.insert(policyId);
            p.id = policyId;
            // Policy entrypoints hold nonReentrantD; criteria, program, and index helpers mutate only local
            // storage.
            // forge-lint: disable-next-line(reentrancy-events)
            emit PolicyCreated(policyId);
        }
        _writePolicyCriteria(pl, p, groupIds, thresholds);
        // Policy entrypoints hold nonReentrantD; criteria, program, and index helpers mutate only local storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit PolicyCriteriaUpdated(policyId, keccak256(abi.encode(groupIds, thresholds)));
        if (existed) {
            _touchPolicyIndex(pl, policyId);
        }
    }

    /// @notice Attach or update a policy program.
    /// @dev Program length and maxSteps are bounded; see MAX_POLICY_PROGRAM_BYTES.
    function setPolicyProgram(bytes32 policyId, bytes calldata program, uint32 maxSteps)
        external
        whenNotPausedD
        nonReentrantD
    {
        _requirePolicyWriteRole();
        _validatePolicyProgram(program, maxSteps);
        PoliciesStorage.Layout storage pl = PoliciesStorage.getLayout();
        if (!PoliciesStorage.exists(pl, policyId)) revert PolicyNotFound();
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryPolicy(), scope: policyId, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setPolicyProgram.selector, policyId, program, maxSteps)
        );
        if (!executing) {
            return;
        }
        _writePolicyProgram(pl.policies[policyId], program, maxSteps);
        _touchPolicyIndex(pl, policyId);
    }

    /// @notice Clear the policy program and increment its version.
    function clearPolicyProgram(bytes32 policyId) external whenNotPausedD nonReentrantD {
        _requirePolicyWriteRole();
        PoliciesStorage.Layout storage pl = PoliciesStorage.getLayout();
        if (!PoliciesStorage.exists(pl, policyId)) revert PolicyNotFound();
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryPolicy(), scope: policyId, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.clearPolicyProgram.selector, policyId)
        );
        if (!executing) {
            return;
        }
        Policy storage p = pl.policies[policyId];
        delete p.program;
        p.programHash = bytes32(0);
        p.programMaxSteps = 0;
        unchecked {
            p.programVersion = p.programVersion + 1;
            if (p.programVersion == 0) {
                p.programVersion = 1;
            }
        }
        // Policy entrypoints hold nonReentrantD; criteria, program, and index helpers mutate only local storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit PolicyProgramUpdated(policyId, bytes32(0), p.programVersion, 0);
        _touchPolicyIndex(pl, policyId);
    }

    /// @notice Delete a policy once it is no longer referenced by timelock config or pending actions.
    function deletePolicy(bytes32 policyId) external whenNotPausedD nonReentrantD {
        _requirePolicyWriteRole();
        PoliciesStorage.Layout storage pl = PoliciesStorage.getLayout();
        if (!PoliciesStorage.exists(pl, policyId)) revert PolicyNotFound();
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryPolicy(), scope: policyId, policyId: bytes32(0), delay: 0, gracePeriod: 0
            }),
            abi.encodeWithSelector(this.deletePolicy.selector, policyId)
        );
        if (!executing) {
            return;
        }

        if (!PoliciesStorage.exists(pl, policyId)) revert PolicyNotFound();
        if (TimelockLib.policyConfigRefCount(policyId) != 0) {
            revert PolicyInUseByConfig(policyId);
        }

        if (TimelockLib.pendingPolicyRefCount(policyId) != 0) {
            revert PolicyInUseByPendingAction(policyId, TimelockLib.pendingActionByPolicy(policyId));
        }

        PolicyStateStorage.bumpPolicyEpoch(policyId);
        _clearPolicyCriteriaRefs(pl, pl.policies[policyId]);
        pl.policyIds.removeValue(policyId);
        delete pl.policies[policyId];
        // Policy entrypoints hold nonReentrantD; criteria, program, and index helpers mutate only local storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit PolicyDeleted(policyId);
    }

    // Index views
    function getPolicyCount() external view returns (uint256) {
        return PoliciesStorage.getLayout().policyIds.length();
    }

    function getPolicyKeyAt(uint256 index) external view returns (bytes32) {
        return PoliciesStorage.getLayout().policyIds.valueAt(index);
    }

    function getPolicyKeysPage(uint256 start, uint256 count) external view returns (bytes32[] memory) {
        return PoliciesStorage.getLayout().policyIds.page(start, count);
    }

    function getPolicyIndexNextId() external view returns (uint256) {
        return PoliciesStorage.getLayout().policyIds.nextId();
    }

    function getPolicyIndexCurrentEpoch() external view returns (uint64) {
        return PoliciesStorage.getLayout().policyIds.currentEpoch;
    }

    function getPolicyIndexAlivePage(uint256 pageIndex) external view returns (uint256) {
        return PoliciesStorage.getLayout().policyIds.alivePage(pageIndex);
    }

    function getPolicyIndexValues(uint256[] calldata ids) external view returns (bytes32[] memory) {
        return PoliciesStorage.getLayout().policyIds.getValues(ids);
    }

    function getPolicyIndexEpochPageCount(uint64 epoch) external view returns (uint256) {
        return PoliciesStorage.getLayout().policyIds.epochPageCount(epoch);
    }

    function getPolicyIndexEpochPageAt(uint64 epoch, uint256 i) external view returns (uint128) {
        return PoliciesStorage.getLayout().policyIds.epochPageAt(epoch, i);
    }

    function getPolicyIndexJournal(uint64 epoch, uint128 pageIndex)
        external
        view
        returns (uint256 updates, uint256 deletes)
    {
        return PoliciesStorage.getLayout().policyIds.journal(epoch, pageIndex);
    }

    function policyExists(bytes32 policyId) external view returns (bool) {
        return PoliciesStorage.exists(PoliciesStorage.getLayout(), policyId);
    }

    function getPolicyCriteria(bytes32 policyId)
        external
        view
        returns (bytes32[] memory groupHashes, uint256[] memory thresholds)
    {
        PoliciesStorage.Layout storage pl = PoliciesStorage.getLayout();
        Policy storage p = pl.policies[policyId];
        if (p.id == bytes32(0)) revert PolicyNotFound();
        uint256 n = p.criteria.length;
        groupHashes = new bytes32[](n);
        thresholds = new uint256[](n);
        for (uint256 i = 0; i < n;) {
            groupHashes[i] = p.criteria[i].groupHash;
            thresholds[i] = p.criteria[i].threshold;
            unchecked {
                ++i;
            }
        }
    }

    function getPolicyProgram(bytes32 policyId)
        external
        view
        returns (bytes memory program, uint32 maxSteps, bytes32 programHash, uint64 version)
    {
        PoliciesStorage.Layout storage pl = PoliciesStorage.getLayout();
        Policy storage p = pl.policies[policyId];
        if (p.id == bytes32(0)) revert PolicyNotFound();
        return (p.program, p.programMaxSteps, p.programHash, p.programVersion);
    }

    function getPolicy(bytes32 policyId)
        external
        view
        returns (
            bytes32[] memory groupHashes,
            uint256[] memory thresholds,
            bytes memory program,
            uint32 maxSteps,
            bytes32 programHash,
            uint64 version
        )
    {
        PoliciesStorage.Layout storage pl = PoliciesStorage.getLayout();
        Policy storage p = pl.policies[policyId];
        if (p.id == bytes32(0)) revert PolicyNotFound();
        uint256 n = p.criteria.length;
        groupHashes = new bytes32[](n);
        thresholds = new uint256[](n);
        for (uint256 i = 0; i < n;) {
            groupHashes[i] = p.criteria[i].groupHash;
            thresholds[i] = p.criteria[i].threshold;
            unchecked {
                ++i;
            }
        }
        return (groupHashes, thresholds, p.program, p.programMaxSteps, p.programHash, p.programVersion);
    }

    function _requirePolicyWriteRole() private view {
        address actor = _msgSenderD();
        if (_canManagePolicies(actor)) {
            return;
        }
        revert AccessControlUnauthorizedAccount(actor, ADMIN_ROLE);
    }

    function _canManagePolicies(address actor) private view returns (bool) {
        if (IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor)) return true;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.DIRECTORY_MANAGER)) return true;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.POLICY_AUTHOR)) return true;
        return false;
    }

    function _writePolicyCriteria(
        PoliciesStorage.Layout storage policies,
        Policy storage policy_,
        bytes32[] calldata groupIds,
        uint256[] calldata thresholds
    ) private {
        // A policy program may call out before replay. The assigned groups must still match the reviewed sets.
        if (ExecutionContextLib.isActive()) {
            GroupsStorage.requirePendingMemberships(GroupsStorage.getLayout(), ExecutionContextLib.currentActionId());
        }
        _clearPolicyCriteriaRefs(policies, policy_);
        GroupsStorage.Layout storage gl = GroupsStorage.getLayout();
        for (uint256 i = 0; i < groupIds.length;) {
            // Policy criteria must all reference distinct existing groups; skipping one would weaken the policy.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (!GroupsStorage.exists(gl, groupIds[i])) revert GroupNotFound();
            for (uint256 j = 0; j < i;) {
                // Policy criteria must all reference distinct existing groups; skipping one would weaken the
                // policy.
                // forge-lint: disable-next-line(require-revert-in-loop)
                if (groupIds[j] == groupIds[i]) revert GroupDuplicate();
                unchecked {
                    ++j;
                }
            }
            policy_.criteria.push(GroupCriteria({groupHash: groupIds[i], threshold: thresholds[i]}));
            PoliciesStorage.incrementGroupRef(policies, groupIds[i], policy_.id);
            unchecked {
                ++i;
            }
        }
    }

    function _clearPolicyCriteriaRefs(PoliciesStorage.Layout storage policies, Policy storage policy_) private {
        uint256 criteriaLength = policy_.criteria.length;
        for (uint256 i = 0; i < criteriaLength;) {
            PoliciesStorage.decrementGroupRef(policies, policy_.criteria[i].groupHash, policy_.id);
            unchecked {
                ++i;
            }
        }
        delete policy_.criteria;
    }

    function _writePolicyProgram(Policy storage policy_, bytes calldata program, uint32 maxSteps) private {
        policy_.program = program;
        policy_.programHash = keccak256(program);
        policy_.programMaxSteps = maxSteps;
        unchecked {
            policy_.programVersion = policy_.programVersion + 1;
            if (policy_.programVersion == 0) {
                policy_.programVersion = 1;
            }
        }
        // Policy entrypoints hold nonReentrantD; criteria, program, and index helpers mutate only local storage.
        // forge-lint: disable-next-line(reentrancy-events)
        emit PolicyProgramUpdated(policy_.id, policy_.programHash, policy_.programVersion, maxSteps);
    }

    function _touchPolicyIndex(PoliciesStorage.Layout storage policies, bytes32 policyId) private {
        (uint256 id, bool exists_) = policies.policyIds.idOf(policyId);
        if (exists_) {
            policies.policyIds.update(id, policyId);
        }
    }

    function _validatePolicyProgram(bytes calldata program, uint32 maxSteps) private pure {
        if (program.length == 0 || maxSteps == 0) revert PolicyProgramInvalid();
        if (program.length > MAX_POLICY_PROGRAM_BYTES) revert PolicyProgramInvalid();
        // Payable WRITE opcodes may evaluate to zero. The engine enforces the
        // zero policy budget at dispatch, including raw bytecode and CALLI.
        // Unregistered dynamic native recipients are not a policy capability.
        if (MiniScriptBytecode.containsOpcode(program, TRANSFER_NATIVE_OPCODE)) revert PolicyProgramInvalid();
    }

    function _registerPendingGroups(bytes32 actionId, bytes32[] calldata groupIds) private {
        GroupsStorage.Layout storage groups = GroupsStorage.getLayout();
        for (uint256 i; i < groupIds.length; ++i) {
            // Only existing groups can be reviewed; accepting a later-created group would leave no reviewed members.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (!GroupsStorage.exists(groups, groupIds[i])) revert GroupNotFound();
            GroupsStorage.registerPendingMembership(groups, actionId, groupIds[i]);
        }
    }
}
