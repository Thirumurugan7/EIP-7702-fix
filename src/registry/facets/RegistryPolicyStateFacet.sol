// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {PoliciesStorage, PolicyStateStorage} from "../../registry/RegistryShared.sol";
import {TimelockLib, TimelockRequest} from "../../registry/TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/// @title RegistryPolicyStateFacet
/// @notice Policy-owned typed values and atomic scoped meters for runtime policy programs.
/// @dev This is separate from descriptive registry metadata. Runtime writes are allowed either to registry
///      administrators or to the active MiniScript runner for the exact policy currently opened by Interact.
contract RegistryPolicyStateFacet is FacetGuard {
    uint256 public constant VERSION = 1;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    error PolicyStateUnauthorized(address actor, bytes32 policyId);
    error PolicyStatePolicyNotFound(bytes32 policyId);
    error PolicyStateExecutionActive(bytes32 policyId, address executor, address runner);
    error PolicyStateExecutionInactive();
    error PolicyStateRunnerZero();
    error PolicyStateExecutorMismatch(address expected, address actual);
    error PolicyStateWindowZero();
    error PolicyStateQueuedEpochMissing(bytes32 actionId);
    error PolicyStateEpochMismatch(bytes32 policyId, bytes32 actionId, uint256 expected, uint256 actual);
    error PolicyStateLimitExceeded(
        bytes32 policyId, bytes32 meterId, uint256 bucket, uint256 spent, uint256 amount, uint256 limit
    );

    event PolicyStateExecutionStarted(bytes32 indexed policyId, address indexed executor, address indexed runner);
    event PolicyStateExecutionEnded(bytes32 indexed policyId, address indexed executor, address indexed runner);
    event PolicyUintSet(
        bytes32 indexed policyId,
        bytes32 indexed namespace,
        bytes32 indexed subject,
        bytes32 key,
        uint256 value,
        address operator
    );
    event PolicyMeterConsumed(
        bytes32 indexed policyId,
        bytes32 indexed meterId,
        bytes32 indexed scope,
        uint64 windowSeconds,
        uint256 bucket,
        uint256 amount,
        uint256 spent,
        uint256 limit,
        address operator
    );

    /// @notice Open a policy-state execution context for one policy program run.
    /// @param policyId Policy whose state may be mutated by `runner`.
    /// @param runner MiniScript instance expected to call runtime policy-state functions.
    function beginPolicyStateExecution(bytes32 policyId, address runner) external whenNotPausedD nonReentrantD {
        _requirePolicyStateExecutor();
        _requirePolicyExists(policyId);
        if (runner == address(0)) revert PolicyStateRunnerZero();

        PolicyStateStorage.Layout storage l = PolicyStateStorage.getLayout();
        if (l.activeRunner != address(0)) {
            revert PolicyStateExecutionActive(l.activePolicyId, l.activeExecutor, l.activeRunner);
        }

        l.activePolicyId = policyId;
        l.activeExecutor = msg.sender;
        l.activeRunner = runner;
        // Policy-state entrypoints hold nonReentrantD and perform only local context, meter, and value writes
        // before this event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit PolicyStateExecutionStarted(policyId, msg.sender, runner);
    }

    /// @notice Close the active policy-state execution context.
    function endPolicyStateExecution() external whenNotPausedD nonReentrantD {
        PolicyStateStorage.Layout storage l = PolicyStateStorage.getLayout();
        address executor = l.activeExecutor;
        address runner = l.activeRunner;
        bytes32 policyId = l.activePolicyId;
        if (runner == address(0)) revert PolicyStateExecutionInactive();
        if (msg.sender != executor) revert PolicyStateExecutorMismatch(executor, msg.sender);

        delete l.activePolicyId;
        delete l.activeExecutor;
        delete l.activeRunner;
        // Policy-state entrypoints hold nonReentrantD and perform only local context, meter, and value writes
        // before this event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit PolicyStateExecutionEnded(policyId, executor, runner);
    }

    /// @notice Return the active policy-state execution context.
    function currentPolicyStateExecution() external view returns (bytes32 policyId, address executor, address runner) {
        PolicyStateStorage.Layout storage l = PolicyStateStorage.getLayout();
        return (l.activePolicyId, l.activeExecutor, l.activeRunner);
    }

    /// @notice Set one policy-owned uint value.
    function setPolicyUint(bytes32 policyId, bytes32 namespace, bytes32 subject, bytes32 key, uint256 value)
        external
        whenNotPausedD
        nonReentrantD
    {
        _requirePolicyExists(policyId);
        if (!_isActivePolicyRunner(policyId)) {
            _requirePolicyStateAdmin(policyId);
            uint256 expectedEpoch = PolicyStateStorage.policyEpoch(policyId);
            (bool executing, bytes32 actionId) = TimelockLib.enforceOrQueue(
                TimelockRequest({
                    category: TimelockLib.categoryPolicy(),
                    scope: policyId,
                    policyId: bytes32(0),
                    delay: 0,
                    gracePeriod: 0
                }),
                abi.encodeWithSelector(this.setPolicyUint.selector, policyId, namespace, subject, key, value)
            );
            if (!executing) {
                PolicyStateStorage.getLayout().queuedUintWriteEpochs[actionId] =
                    PolicyStateStorage.UintRecord({value: expectedEpoch, exists: true});
                return;
            }
            if (actionId != bytes32(0)) {
                _consumeQueuedUintWriteEpoch(policyId, actionId);
            }
        }
        _writePolicyUint(policyId, namespace, subject, key, value);
    }

    function _writePolicyUint(bytes32 policyId, bytes32 namespace, bytes32 subject, bytes32 key, uint256 value)
        private
    {
        bytes32 storageKey = PolicyStateStorage.uintKey(policyId, namespace, subject, key);
        PolicyStateStorage.Layout storage l = PolicyStateStorage.getLayout();
        l.uints[storageKey] = PolicyStateStorage.UintRecord({value: value, exists: true});
        // Policy-state entrypoints hold nonReentrantD and perform only local context, meter, and value writes
        // before this event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit PolicyUintSet(policyId, namespace, subject, key, value, _msgSenderD());
    }

    function _consumeQueuedUintWriteEpoch(bytes32 policyId, bytes32 actionId) private {
        PolicyStateStorage.Layout storage l = PolicyStateStorage.getLayout();
        PolicyStateStorage.UintRecord storage record = l.queuedUintWriteEpochs[actionId];
        if (!record.exists) revert PolicyStateQueuedEpochMissing(actionId);
        uint256 expectedEpoch = record.value;
        uint256 actualEpoch = PolicyStateStorage.policyEpoch(policyId);
        if (actualEpoch != expectedEpoch) {
            revert PolicyStateEpochMismatch(policyId, actionId, expectedEpoch, actualEpoch);
        }
        delete l.queuedUintWriteEpochs[actionId];
    }

    /// @notice Read one policy-owned uint value.
    function getPolicyUint(bytes32 policyId, bytes32 namespace, bytes32 subject, bytes32 key)
        external
        view
        returns (uint256 value, bool found)
    {
        PolicyStateStorage.UintRecord storage record =
            PolicyStateStorage.getLayout().uints[PolicyStateStorage.uintKey(policyId, namespace, subject, key)];
        return (record.value, record.exists);
    }

    /// @notice Atomically consume a scoped policy meter for the current fixed window.
    /// @dev Dimensions are caller-defined words such as vault, asset, initiator, destination, DApp, or kind.
    function consumePolicyMeter(
        bytes32 policyId,
        bytes32 meterId,
        uint64 windowSeconds,
        uint256 amount,
        uint256 limit,
        bytes32 d0,
        bytes32 d1,
        bytes32 d2,
        bytes32 d3
    ) external whenNotPausedD nonReentrantD returns (bool) {
        _requirePolicyStateRuntimeWrite(policyId);
        if (windowSeconds == 0) revert PolicyStateWindowZero();

        bytes32 scope = PolicyStateStorage.meterScope(policyId, meterId, d0, d1, d2, d3);
        uint256 bucket = block.timestamp / uint256(windowSeconds);
        bytes32 bucketKey = PolicyStateStorage.meterBucketKey(scope, windowSeconds, bucket);
        PolicyStateStorage.Layout storage l = PolicyStateStorage.getLayout();
        uint256 spent = l.meters[bucketKey];
        uint256 next = spent + amount;
        if (next > limit) {
            revert PolicyStateLimitExceeded(policyId, meterId, bucket, spent, amount, limit);
        }
        l.meters[bucketKey] = next;
        // Policy-state entrypoints hold nonReentrantD and perform only local context, meter, and value writes
        // before this event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit PolicyMeterConsumed(policyId, meterId, scope, windowSeconds, bucket, amount, next, limit, _msgSenderD());
        return true;
    }

    /// @notice Read a scoped policy meter for the current fixed window.
    function getPolicyMeter(
        bytes32 policyId,
        bytes32 meterId,
        uint64 windowSeconds,
        bytes32 d0,
        bytes32 d1,
        bytes32 d2,
        bytes32 d3
    ) external view returns (uint256 spent, uint256 bucket, bytes32 scope) {
        if (windowSeconds == 0) revert PolicyStateWindowZero();
        scope = PolicyStateStorage.meterScope(policyId, meterId, d0, d1, d2, d3);
        bucket = block.timestamp / uint256(windowSeconds);
        spent = PolicyStateStorage.getLayout().meters[PolicyStateStorage.meterBucketKey(scope, windowSeconds, bucket)];
    }

    /// @notice Read a scoped policy meter for an explicit bucket.
    function getPolicyMeterBucket(
        bytes32 policyId,
        bytes32 meterId,
        uint64 windowSeconds,
        uint256 bucket,
        bytes32 d0,
        bytes32 d1,
        bytes32 d2,
        bytes32 d3
    ) external view returns (uint256 spent, bytes32 scope) {
        if (windowSeconds == 0) revert PolicyStateWindowZero();
        scope = PolicyStateStorage.meterScope(policyId, meterId, d0, d1, d2, d3);
        spent = PolicyStateStorage.getLayout().meters[PolicyStateStorage.meterBucketKey(scope, windowSeconds, bucket)];
    }

    function _requirePolicyStateRuntimeWrite(bytes32 policyId) private view {
        _requirePolicyExists(policyId);
        if (_isActivePolicyRunner(policyId)) {
            return;
        }
        address actor = _msgSenderD();
        revert PolicyStateUnauthorized(actor, policyId);
    }

    function _requirePolicyStateAdmin(bytes32 policyId) private view {
        address actor = _msgSenderD();
        if (_canAdminPolicyState(actor)) {
            return;
        }
        revert PolicyStateUnauthorized(actor, policyId);
    }

    function _isActivePolicyRunner(bytes32 policyId) private view returns (bool) {
        PolicyStateStorage.Layout storage l = PolicyStateStorage.getLayout();
        return l.activePolicyId == policyId && l.activeRunner == msg.sender;
    }

    function _requirePolicyStateExecutor() private view {
        address actor = _msgSenderD();
        if (CapabilitiesLib.hasDirectActorCapability(actor, CapabilityIds.POLICY_STATE_RUNNER)) {
            return;
        }
        revert PolicyStateUnauthorized(actor, bytes32(0));
    }

    function _requirePolicyExists(bytes32 policyId) private view {
        if (!PoliciesStorage.exists(PoliciesStorage.getLayout(), policyId)) {
            revert PolicyStatePolicyNotFound(policyId);
        }
    }

    function _canAdminPolicyState(address actor) private view returns (bool) {
        if (IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor)) return true;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.POLICY_AUTHOR)) return true;
        return false;
    }
}
