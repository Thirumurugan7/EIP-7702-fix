// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "../../Delegation7702.sol";
import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

import {ProtocolCodehashes} from "../../ProtocolCodehashes.sol";
import {Policy} from "../../RegistryTypes.sol";
import {ITimelockPolicyProgramRunner} from "../../TimelockPolicyProgramRunner.sol";
import {
    ExecutionCatalogStorage,
    GroupsStorage,
    PoliciesStorage,
    PolicyStateStorage
} from "../../registry/RegistryShared.sol";
import {TimelockEngineCompatibility} from "../../registry/TimelockEngineCompatibility.sol";
import {
    ExecutionContextLib,
    TimelockActionStatus,
    TimelockConfigStorage,
    TimelockLib,
    TimelockStorage
} from "../../registry/TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";

/// @title RegistryTimelockExecutionModule
/// @notice Fixed delegatecall implementation for approving, terminating, and executing queued Registry actions.
/// @dev `RegistryTimelockFacet` preserves the public ABI and forwards lifecycle mutations here. The second
///      delegatecall still executes with the Registry diamond as `address(this)`, so all timelock, policy-state,
///      execution-context, and reentrancy storage remains in the original diamond storage domain.
contract RegistryTimelockExecutionModule is FacetGuard {
    bytes32 private constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes4 private constant GRANT_ROLE_SELECTOR = bytes4(keccak256("grantRole(bytes32,address)"));
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes4 private constant REVOKE_ROLE_SELECTOR = bytes4(keccak256("revokeRole(bytes32,address)"));
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant REVOKE_CAPABILITY_GROUP_SELECTOR =
        bytes4(keccak256("revokeCapabilityGroup(bytes32,bytes32)"));
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant REVOKE_CAPABILITY_ACTOR_SELECTOR =
        bytes4(keccak256("revokeCapabilityActor(bytes32,address)"));
    // forge-lint: disable-end(unsafe-typecast)
    bytes4 private constant RUNNER_REGISTRY_SELECTOR = 0x7b103999;
    bytes4 private constant RUNNER_AUTHORIZED_CALLER_SELECTOR = 0x97dc97cb;
    bytes4 private constant RUNNER_ENGINE_SELECTOR = 0xc9d4623f;
    uint256 private constant TIMELOCK_POLICY_STAGE_EXECUTE = 2;
    uint256 private constant TIMELOCK_POLICY_ARG_COUNT = 20;
    uint32 private constant TIMELOCK_POLICY_PROGRAM_STEP_CAP = 100_000;

    error TimelockActionNotReady(bytes32 actionId, TimelockActionStatus status);
    error TimelockActionExpired(bytes32 actionId);
    error TimelockActionUnauthorized(bytes32 actionId, address caller);
    error TimelockActionNotExpired(bytes32 actionId, uint64 expiresAt);
    error TimelockApprovalsStale(bytes32 actionId, bytes32 policyId);
    error TimelockPayloadMissing(bytes32 actionId);
    error TimelockActionUnknown(bytes32 actionId);
    error TimelockExecutionFailed();
    error TimelockExecutionSkipped();
    error TimelockPolicyRunnerMissing(bytes32 policyId);
    error TimelockPolicyRunnerInvalid(address runner);
    error TimelockPolicyStateActive(bytes32 policyId, address executor, address runner);
    error TimelockPolicyProgramStepsMissing(bytes32 policyId);

    event TimelockPolicyProgramExecuted(
        bytes32 indexed actionId, bytes32 indexed policyId, address indexed runner, uint256 stackTop
    );

    function approveAction(bytes32 actionId) external whenNotPausedD nonReentrantD returns (bool readyNow) {
        TimelockStorage.Action memory action = TimelockLib.action(actionId);
        if (action.status == TimelockActionStatus.None) revert TimelockActionUnknown(actionId);
        if (action.status != TimelockActionStatus.Queued && action.status != TimelockActionStatus.Ready) {
            revert TimelockActionNotReady(actionId, action.status);
        }
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > action.expiresAt) {
            TimelockLib.markExpired(actionId);
            return false;
        }
        readyNow = TimelockLib.performApproval(actionId, _msgSenderD());
    }

    /// @notice Cancel a queued role or registry action.
    /// @dev The original actor, an ADMIN_ROLE holder, or a CANCEL_TIMELOCK holder may cancel. A cancellation-only
    ///      holder cannot cancel an action that revokes CANCEL_TIMELOCK itself, so governance always retains a path
    ///      to remove a compromised guardian. For role-admin actions, a peer holding the matching GRANT_ADMIN or
    ///      REVOKE_ADMIN capability may also cancel the queued grant or revoke. Cancellation remains available while
    ///      paused because it cannot execute or alter the queued payload.
    /// @param actionId Identifier of the queued action to cancel.
    function cancelAction(bytes32 actionId) external nonReentrantD {
        actionId = TimelockLib.bundleRoot(actionId);
        TimelockStorage.Action memory action = TimelockLib.action(actionId);
        TimelockActionStatus status = action.status;
        if (status != TimelockActionStatus.Queued && status != TimelockActionStatus.Ready) {
            revert TimelockActionNotReady(actionId, status);
        }
        address actor = _msgSenderD();
        if (!_canCancelAction(action, actor)) {
            revert TimelockActionUnauthorized(actionId, actor);
        }
        TimelockLib.markCancelled(actionId, actor);
    }

    /// @notice Persist expiry and remove an elapsed action from pending indexes.
    /// @dev Cleanup is permissionless and remains available while the Registry is
    ///      paused because it cannot execute or alter the queued payload.
    function expireAction(bytes32 actionId) external nonReentrantD {
        TimelockStorage.Action memory action = TimelockLib.action(actionId);
        TimelockActionStatus status = action.status;
        if (status != TimelockActionStatus.Queued && status != TimelockActionStatus.Ready) {
            revert TimelockActionNotReady(actionId, status);
        }
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp <= action.expiresAt) {
            revert TimelockActionNotExpired(actionId, action.expiresAt);
        }
        TimelockLib.markExpired(actionId);
    }

    function executeAction(bytes32 actionId) external whenNotPausedD returns (bytes memory returnData) {
        (bool executed, bytes memory data) = _executeAction(actionId, true);
        if (!executed) revert TimelockExecutionSkipped();
        return data;
    }

    function executeActions(bytes32[] calldata actionIds) external whenNotPausedD returns (bytes[] memory returnData) {
        uint256 len = actionIds.length;
        returnData = new bytes[](len);
        for (uint256 i; i < len; ++i) {
            (, bytes memory data) = _executeAction(actionIds[i], false);
            returnData[i] = data;
        }
    }

    /// @dev General actions remain actor/admin cancellable; role-admin actions also allow matching capability peers.
    ///      CANCEL_TIMELOCK cannot protect its own assignment from revocation.
    function _canCancelAction(TimelockStorage.Action memory action, address actor) private view returns (bool) {
        if (!TimelockLib.isActionSemanticsCurrent(action.id)) return true;
        if (!GroupsStorage.pendingMembershipsCurrent(GroupsStorage.getLayout(), action.id)) return true;
        if (actor == action.actor || IAccessControl(address(this)).hasRole(ADMIN_ROLE, actor)) {
            return true;
        }
        if (
            CapabilitiesLib.hasCapability(actor, CapabilityIds.CANCEL_TIMELOCK)
                && !TimelockStorage.state().guardianCancellationBlocked[action.id]
                && !_revokesCancelTimelockCapability(action)
        ) return true;
        bytes32 capability = _roleAdminCancelCapability(action);
        return capability != bytes32(0) && CapabilitiesLib.hasCapability(actor, capability);
    }

    function _revokesCancelTimelockCapability(TimelockStorage.Action memory action) private view returns (bool) {
        if (action.category != TimelockLib.categoryCapability()) return false;
        bytes memory actionPayload = TimelockLib.payload(action.id);
        bytes4 selector = _payloadSelector(actionPayload);
        if (selector != REVOKE_CAPABILITY_GROUP_SELECTOR && selector != REVOKE_CAPABILITY_ACTOR_SELECTOR) {
            return false;
        }
        return _payloadWord(actionPayload, 0) == CapabilityIds.CANCEL_TIMELOCK;
    }

    /// @dev Inspect the queued role-admin payload to require GRANT_ADMIN for grants and REVOKE_ADMIN for revokes.
    function _roleAdminCancelCapability(TimelockStorage.Action memory action) private view returns (bytes32) {
        if (action.category != TimelockLib.categoryRoleAdmin()) {
            return bytes32(0);
        }
        bytes4 selector = _payloadSelector(TimelockLib.payload(action.id));
        if (selector == GRANT_ROLE_SELECTOR) {
            return CapabilityIds.GRANT_ADMIN;
        }
        if (selector == REVOKE_ROLE_SELECTOR) {
            return CapabilityIds.REVOKE_ADMIN;
        }
        return bytes32(0);
    }

    function _checkReady(bytes32 actionId, bool strict) private returns (bool) {
        TimelockStorage.Action memory action = TimelockLib.action(actionId);
        TimelockActionStatus status = action.status;
        if (status == TimelockActionStatus.None) {
            // Batch calls pass strict=false and skip this failure; the revert is reachable only through
            // single-action execution.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (strict) revert TimelockActionUnknown(actionId);
            return false;
        }
        // Batch execution is deliberately skip-oriented, but skipping must not
        // mutate unknown or terminal IDs. A default Action has expiresAt == 0;
        // treating it as expired would let callers pre-squat deterministic
        // future action IDs by writing Expired before they are queued.
        if (status != TimelockActionStatus.Queued && status != TimelockActionStatus.Ready) {
            // Batch calls pass strict=false and skip this failure; the revert is reachable only through
            // single-action execution.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (strict) revert TimelockActionNotReady(actionId, status);
            return false;
        }
        if (!TimelockLib.isActionSemanticsCurrent(actionId)) {
            if (strict) TimelockLib.requireActionSemanticsCurrent(actionId);
            return false;
        }
        if (!TimelockLib.actionMembershipsCurrent(actionId)) {
            if (strict) TimelockLib.requireActionMembershipsCurrent(actionId);
            return false;
        }
        // Live policy edits can make recorded approvals sufficient without a
        // new signer transaction (including an explicit zero-threshold policy).
        // Refresh readiness at execution time so such actions do not remain
        // permanently Queued under the documented live-policy model.
        if (
            // forge-lint: disable-next-line(block-timestamp)
            status == TimelockActionStatus.Queued && block.timestamp >= action.eta
                && TimelockLib.approvalsMeetCurrentPolicy(actionId, action.policyId)
        ) {
            TimelockLib.markReady(actionId);
            status = TimelockActionStatus.Ready;
        }
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > action.expiresAt) {
            // Batch calls pass strict=false and skip this failure; the revert is reachable only through
            // single-action execution.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (strict) revert TimelockActionExpired(actionId);
            TimelockLib.markExpired(actionId);
            return false;
        }
        // forge-lint: disable-next-line(block-timestamp)
        if (status != TimelockActionStatus.Ready || block.timestamp < action.eta) {
            // Batch calls pass strict=false and skip this failure; the revert is reachable only through
            // single-action execution.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (strict) revert TimelockActionNotReady(actionId, status);
            return false;
        }
        if (!TimelockLib.approvalsMeetCurrentPolicy(actionId, action.policyId)) {
            // Batch calls pass strict=false and skip this failure; the revert is reachable only through
            // single-action execution.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (strict) revert TimelockApprovalsStale(actionId, action.policyId);
            return false;
        }

        return true;
    }

    function _executeAction(bytes32 actionId, bool strict) private returns (bool executed, bytes memory returnData) {
        actionId = TimelockLib.bundleRoot(actionId);
        bytes32[] memory ids = TimelockLib.bundleActions(actionId);
        for (uint256 i; i < ids.length; ++i) {
            if (!_checkReady(ids[i], strict)) return (false, "");
        }
        TimelockStorage.Action memory action = TimelockLib.action(actionId);
        bytes memory payload = TimelockLib.payload(actionId);
        // Execution failures must roll back committed effects; batch skipping is limited to unavailable actions
        // before execution.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (payload.length == 0) revert TimelockPayloadMissing(actionId);

        TimelockLib.markBundleExecuting(ids);
        // Acquire the raw action context before policy evaluation so nested
        // ready-action execution cannot enter another context. The external
        // policy runner does not inherit the logical actor: context visibility
        // remains restricted to Registry self-calls.
        ExecutionContextLib.enter(actionId, action.actor, action.category, action.scope);
        ExecutionCatalogStorage.bumpSemantics();
        // Each policy executes in its own category/scope, immediately before the one mutation.
        // Any failure rolls back all policy state, statuses, and the payload atomically.
        for (uint256 i; i < ids.length; ++i) {
            (bool policyOk, bytes memory policyData) =
                _runTimelockPolicyProgram(TimelockLib.action(ids[i]), payload, _msgSenderD());
            if (!policyOk) {
                if (policyData.length != 0) {
                    assembly {
                        // Execution failures must roll back committed effects; batch skipping is limited to unavailable
                        // actions before execution.
                        // forge-lint: disable-next-line(require-revert-in-loop)
                        revert(add(policyData, 0x20), mload(policyData))
                    }
                }
                // Execution failures must roll back committed effects; batch skipping is limited to unavailable actions
                // before execution.
                // forge-lint: disable-next-line(require-revert-in-loop)
                revert TimelockExecutionFailed();
            }
        }
        // Caller-selected action IDs are independently checked; execution holds a single action context and any
        // started failure rolls back.
        // forge-lint: disable-next-line(calls-loop)
        (bool ok, bytes memory data) = address(this).call(payload);
        ExecutionContextLib.exit();

        if (!ok) {
            if (data.length != 0) {
                assembly {
                    // Execution failures must roll back committed effects; batch skipping is limited to unavailable
                    // actions before execution.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert(add(data, 0x20), mload(data))
                }
            }
            // Execution failures must roll back committed effects; batch skipping is limited to unavailable actions
            // before execution.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert TimelockExecutionFailed();
        }

        TimelockLib.markBundleExecuted(ids, _msgSenderD());
        return (true, data);
    }

    function _runTimelockPolicyProgram(TimelockStorage.Action memory action, bytes memory payload, address operator)
        private
        returns (bool ok, bytes memory ret)
    {
        if (action.policyId == bytes32(0)) {
            return (true, "");
        }

        Policy storage policy = PoliciesStorage.getLayout().policies[action.policyId];
        if (policy.program.length == 0) {
            return (true, "");
        }
        // Execution failures must roll back committed effects; batch skipping is limited to unavailable actions
        // before execution.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (policy.programMaxSteps == 0) revert TimelockPolicyProgramStepsMissing(action.policyId);

        address runner = TimelockConfigStorage.state().policyProgramRunner;
        // Execution failures must roll back committed effects; batch skipping is limited to unavailable actions
        // before execution.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (runner == address(0)) revert TimelockPolicyRunnerMissing(action.policyId);
        _validateTimelockPolicyRunner(runner);

        uint32 steps = policy.programMaxSteps;
        if (steps > TIMELOCK_POLICY_PROGRAM_STEP_CAP) {
            steps = TIMELOCK_POLICY_PROGRAM_STEP_CAP;
        }

        uint256[] memory args = _timelockPolicyArgs(action, payload, operator);
        _openPolicyStateContext(action.policyId, runner);
        // Caller-selected action IDs are independently checked; execution holds a single action context and any
        // started failure rolls back.
        // forge-lint: disable-start(calls-loop)
        (ok, ret) = runner.call(
            abi.encodeWithSelector(ITimelockPolicyProgramRunner.runPolicyProgram.selector, policy.program, args, steps)
        );
        // forge-lint: disable-end(calls-loop)
        _closePolicyStateContext();
        if (ok) {
            uint256 stackTop = abi.decode(ret, (uint256));
            // The exclusive execution context stays active across the canonical runner call and this completion
            // event.
            // forge-lint: disable-next-line(reentrancy-events)
            emit TimelockPolicyProgramExecuted(action.id, action.policyId, runner, stackTop);
        }
    }

    /// @dev Configuration and execution both authenticate the canonical runner and its
    ///      complete current or explicitly supported predecessor engine deployment.
    function _validateTimelockPolicyRunner(address runner) private view {
        if (!Delegation7702.hasContractCode(runner) || !ProtocolCodehashes.isAcceptedTimelockPolicyRunnerCodehash(runner.codehash)) {
            // Execution failures must roll back committed effects; batch skipping is limited to unavailable actions
            // before execution.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert TimelockPolicyRunnerInvalid(runner);
        }
        if (_runnerViewAddress(runner, RUNNER_REGISTRY_SELECTOR) != address(this)) {
            // Execution failures must roll back committed effects; batch skipping is limited to unavailable actions
            // before execution.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert TimelockPolicyRunnerInvalid(runner);
        }
        if (_runnerViewAddress(runner, RUNNER_AUTHORIZED_CALLER_SELECTOR) != address(this)) {
            // Execution failures must roll back committed effects; batch skipping is limited to unavailable actions
            // before execution.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert TimelockPolicyRunnerInvalid(runner);
        }

        address engine = _runnerViewAddress(runner, RUNNER_ENGINE_SELECTOR);
        if (!TimelockEngineCompatibility.isAcceptedDeployment(engine)) {
            // Execution failures must roll back committed effects; batch skipping is limited to unavailable actions
            // before execution.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert TimelockPolicyRunnerInvalid(runner);
        }
    }

    function _runnerViewAddress(address runner, bytes4 selector) private view returns (address value) {
        // Caller-selected action IDs are independently checked; execution holds a single action context and any
        // started failure rolls back.
        // forge-lint: disable-next-line(calls-loop)
        (bool ok, bytes memory data) = runner.staticcall(abi.encodeWithSelector(selector));
        // Execution failures must roll back committed effects; batch skipping is limited to unavailable actions
        // before execution.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (!ok || data.length != 32) revert TimelockPolicyRunnerInvalid(runner);
        assembly ("memory-safe") {
            value := mload(add(data, 0x20))
        }
    }

    function _timelockPolicyArgs(TimelockStorage.Action memory action, bytes memory payload, address operator)
        private
        view
        returns (uint256[] memory args)
    {
        args = new uint256[](TIMELOCK_POLICY_ARG_COUNT);
        args[0] = TIMELOCK_POLICY_STAGE_EXECUTE;
        args[1] = uint256(action.policyId);
        args[2] = uint256(action.id);
        args[3] = uint256(action.category);
        args[4] = uint256(action.scope);
        args[5] = uint256(uint160(action.actor));
        args[6] = uint256(uint160(operator));
        args[7] = uint256(action.payloadHash);
        args[8] = uint32(_payloadSelector(payload));
        args[9] = action.scheduledAt;
        args[10] = action.delay;
        args[11] = action.eta;
        args[12] = action.expiresAt;
        args[13] = block.timestamp;
        args[14] = block.chainid;
        args[15] = uint256(_payloadWord(payload, 0));
        args[16] = uint256(_payloadWord(payload, 1));
        args[17] = uint256(_payloadWord(payload, 2));
        args[18] = uint256(_payloadWord(payload, 3));
        args[19] = uint256(_payloadWord(payload, 4));
    }

    function _openPolicyStateContext(bytes32 policyId, address runner) private {
        PolicyStateStorage.Layout storage l = PolicyStateStorage.getLayout();
        if (l.activeRunner != address(0)) {
            // Execution failures must roll back committed effects; batch skipping is limited to unavailable actions
            // before execution.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert TimelockPolicyStateActive(l.activePolicyId, l.activeExecutor, l.activeRunner);
        }
        l.activePolicyId = policyId;
        l.activeExecutor = address(this);
        l.activeRunner = runner;
    }

    function _closePolicyStateContext() private {
        PolicyStateStorage.Layout storage l = PolicyStateStorage.getLayout();
        delete l.activePolicyId;
        delete l.activeExecutor;
        delete l.activeRunner;
    }

    function _payloadSelector(bytes memory payload) private pure returns (bytes4 selector) {
        if (payload.length < 4) return bytes4(0);
        assembly ("memory-safe") {
            selector := mload(add(payload, 0x20))
        }
    }

    function _payloadWord(bytes memory payload, uint256 wordIndex) private pure returns (bytes32 word) {
        uint256 offset = 4 + (wordIndex + 1) * 32;
        if (payload.length < offset) return bytes32(0);
        assembly ("memory-safe") {
            word := mload(add(add(payload, 0x24), mul(wordIndex, 0x20)))
        }
    }
}
