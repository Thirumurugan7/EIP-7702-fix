// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {ProtocolCodehashes} from "../../ProtocolCodehashes.sol";
import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {ExecutionCatalogStorage, IndexingStorage, PoliciesStorage} from "../../registry/RegistryShared.sol";
import {TimelockEngineCompatibility} from "../../registry/TimelockEngineCompatibility.sol";
import {
    TimelockActionApprovalState,
    TimelockActionStatus,
    TimelockConfigStorage,
    TimelockLib,
    TimelockRequest,
    TimelockStorage
} from "../../registry/TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";
import {RegistryTimelockExecutionModule} from "./RegistryTimelockExecutionModule.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/// @title TimelockActionView
/// @notice External view over an enqueued timelock action.
struct TimelockActionView {
    bytes32 id;
    bytes32 category;
    bytes32 scope;
    address actor;
    bytes32 payloadHash;
    bytes32 policyId;
    uint64 scheduledAt;
    uint64 delay;
    uint64 eta;
    uint64 expiresAt;
    TimelockActionStatus status;
    bool executable;
}

/// @title TimelockActionSummary
/// @notice Compact summary returned by pagination helpers over queued/executed actions.
struct TimelockActionSummary {
    bytes32 id;
    bytes32 category;
    bytes32 scope;
    address actor;
    uint64 scheduledAt;
    uint64 delay;
    uint64 eta;
    uint64 expiresAt;
    TimelockActionStatus status;
    bytes32 policyId;
    bytes32 payloadHash;
}

/// @title TimelockCategoryConfigInput
/// @notice Input payload for configuring a timelock category.
struct TimelockCategoryConfigInput {
    uint64 minDelay;
    uint64 maxDelay;
    uint64 defaultDelay;
    uint64 gracePeriod;
    bytes32 defaultPolicyId;
}

/// @title TimelockScopeOverrideInput
/// @notice Scope-level override configuration fields.
struct TimelockScopeOverrideInput {
    bool setDelay;
    uint64 delay;
    bool setPolicy;
    bytes32 policyId;
    bool setGrace;
    uint64 gracePeriod;
}

/// @title RegistryTimelockFacet
/// @notice Timelock queue, approvals, and configuration for registry actions.
/// @dev Protocol categories have code-defined bootstrap defaults. Unknown categories
///      fail closed until governance configures them. Built-in categories use zero-delay
///      defaults, so tenants must configure category defaults or scope overrides before
///      production use.
///      Every mutating facet can route through this one:
///      1. The facet calls `TimelockLib.enforceOrQueue`.
///      2. If delay is required, a queued action appears here and approvals accumulate under the configured policy.
///      3. Once ready, governance executes the queued payload through the registry dispatcher.
///
///      Queued actions intentionally pin the payload, actor, category, scope, delay, and policy id, but not a
///      snapshot of the policy criteria or policy program. Timelock approvals and execution-time policy programs use
///      the live policy record so governance can tighten, relax, replace, or clear policies while an action is
///      pending. Approver membership and stored-actor authority are revalidated. Operators that need immutable rules
///      should queue under versioned policy ids.
contract RegistryTimelockFacet is FacetGuard {
    uint256 public constant VERSION = 1;
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 private constant POLICY_RUNNER_SCOPE = keccak256("timelock.policy.runner");
    bytes4 private constant RUNNER_REGISTRY_SELECTOR = 0x7b103999;
    bytes4 private constant RUNNER_AUTHORIZED_CALLER_SELECTOR = 0x97dc97cb;
    bytes4 private constant RUNNER_ENGINE_SELECTOR = 0xc9d4623f;
    /// @notice Fixed delegatecall implementation for queued-action execution.
    RegistryTimelockExecutionModule public immutable EXECUTION_MODULE;

    constructor() {
        EXECUTION_MODULE = new RegistryTimelockExecutionModule();
    }

    error TimelockActionNotReady(bytes32 actionId, TimelockActionStatus status);
    error TimelockActionExpired(bytes32 actionId);
    error TimelockActionNotExpired(bytes32 actionId, uint64 expiresAt);
    error TimelockActionUnauthorized(bytes32 actionId, address caller);
    error TimelockApprovalsStale(bytes32 actionId, bytes32 policyId);
    error TimelockConfigInvalid(bytes32 category);
    error TimelockPayloadMissing(bytes32 actionId);
    error TimelockActionUnknown(bytes32 actionId);
    error TimelockExecutionModuleInvalid(address module, bytes32 codehash);
    error TimelockExecutionFailed();
    error TimelockExecutionSkipped();
    error IndexingAlreadyEnabled();
    error TimelockPolicyRunnerMissing(bytes32 policyId);
    error TimelockPolicyRunnerInvalid(address runner);
    error TimelockPolicyStateActive(bytes32 policyId, address executor, address runner);
    error TimelockPolicyProgramStepsMissing(bytes32 policyId);
    // Preserve the Registry-facing ABI for errors bubbled from the fixed lifecycle module.
    error GroupMembershipChanged(bytes32 groupId, uint64 reviewedRevision, uint64 currentRevision);
    error NoSuchId();
    error TimelockActionSemanticsStale(bytes32 actionId, uint64 queuedGeneration, uint64 currentGeneration);
    error TimelockAlreadyApproved(bytes32 actionId, address approver);
    error TimelockNotEligible(bytes32 actionId, address approver);
    error TimelockWrongStatus(bytes32 actionId, TimelockActionStatus want, TimelockActionStatus got);

    /// @notice Emitted when a category's default delay/grace/policy bounds are updated.
    event TimelockCategoryConfigured(
        bytes32 indexed category,
        uint64 minDelay,
        uint64 maxDelay,
        uint64 defaultDelay,
        uint64 gracePeriod,
        bytes32 defaultPolicyId
    );
    /// @notice Emitted when a scope-specific timelock override is created or updated.
    event TimelockScopeOverrideSet(
        bytes32 indexed category,
        bytes32 indexed scope,
        bool delaySet,
        uint64 delay,
        bool policySet,
        bytes32 policyId,
        bool graceSet,
        uint64 gracePeriod
    );
    /// @notice Emitted when a scope-specific override is removed.
    event TimelockScopeOverrideCleared(bytes32 indexed category, bytes32 indexed scope);
    /// @notice Emitted when timelock indexing is enabled for queue/execution history reads.
    event IndexingEnabled(uint64 startBlock);
    /// @notice Emitted when the MiniScript runner used for timelock policy programs changes.
    event TimelockPolicyProgramRunnerSet(address indexed runner, address indexed operator);
    /// @notice Emitted after a timelock policy program accepts an action.
    event TimelockPolicyProgramExecuted(
        bytes32 indexed actionId, bytes32 indexed policyId, address indexed runner, uint256 stackTop
    );
    /// @notice Emitted from the Registry when the delegated execution module completes an action.
    /// @dev Declared here to preserve the Registry-facing facet ABI; the event is emitted by
    ///      {TimelockLib.markBundleExecuted} while the fixed execution module runs through delegatecall.
    event ActionExecuted(bytes32 indexed actionId, address indexed executor);
    event ActionReady(bytes32 indexed actionId);
    event ActionCancelled(bytes32 indexed actionId, address indexed by);
    event ActionExpired(bytes32 indexed actionId);
    event ActionApproved(
        bytes32 indexed actionId, address indexed approver, bytes32 indexed groupHash, uint256 newCount
    );

    /// @notice Configure a timelock category.
    /// @dev Callable by the bootstrap owner or TIMELOCK_GOVERNOR capability holders. Every update, including
    ///      a delay increase, follows the current configuration timelock so availability changes require review.
    /// @param category The keccak256 category identifier.
    /// @param cfg Serialized category configuration describing delay bounds, defaults and policy.
    function setCategoryConfig(bytes32 category, TimelockCategoryConfigInput calldata cfg) external {
        _requireTimelockGovernor();
        TimelockConfigStorage.Layout storage configLayout = TimelockConfigStorage.state();
        bytes32 scopeKey = _categoryScopeKey(category);
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryTimelock(),
                scope: scopeKey,
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setCategoryConfig.selector, category, cfg)
        );
        if (!executing) {
            return;
        }

        if (cfg.minDelay > cfg.maxDelay) revert TimelockConfigInvalid(category);
        if (cfg.defaultDelay < cfg.minDelay || cfg.defaultDelay > cfg.maxDelay) revert TimelockConfigInvalid(category);
        if (cfg.gracePeriod > TimelockLib.maxGracePeriod()) revert TimelockConfigInvalid(category);
        _requireExistingPolicy(cfg.defaultPolicyId);

        TimelockConfigStorage.CategoryConfig storage dest = configLayout.categories[category];
        TimelockLib.replaceConfigPolicyRef(dest.defaultPolicyId, cfg.defaultPolicyId);
        dest.minDelay = cfg.minDelay;
        dest.maxDelay = cfg.maxDelay;
        dest.defaultDelay = cfg.defaultDelay;
        dest.gracePeriod = cfg.gracePeriod;
        dest.defaultPolicyId = cfg.defaultPolicyId;
        dest.exists = true;

        // Configuration helpers mutate local storage; runner validation is STATICCALL-only before the write and
        // event.
        // forge-lint: disable-start(reentrancy-events)
        emit TimelockCategoryConfigured(
            category, cfg.minDelay, cfg.maxDelay, cfg.defaultDelay, cfg.gracePeriod, cfg.defaultPolicyId
        );
        // forge-lint: disable-end(reentrancy-events)
    }

    /// @notice Configure or update a scope-specific override for a category.
    /// @dev Callable by the registry owner or TIMELOCK_GOVERNOR capability holders. Override writes are governed by
    ///      the timelock configuration category, so they may queue under the current config.
    /// @param category Category identifier that the override belongs to.
    /// @param scope Scope identifier (bytes32) subject to the override.
    /// @param input Flags + values describing whether to override delay, grace or policy.
    function setScopeOverride(bytes32 category, bytes32 scope, TimelockScopeOverrideInput calldata input) external {
        _requireTimelockGovernor();
        bytes32 scopeKey = _overrideScopeKey(category, scope);
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryTimelock(),
                scope: scopeKey,
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setScopeOverride.selector, category, scope, input)
        );
        if (!executing) {
            return;
        }

        TimelockConfigStorage.Layout storage configLayout = TimelockConfigStorage.state();
        TimelockConfigStorage.CategoryConfig memory cat = TimelockLib.categoryConfig(category);
        if (!cat.exists) revert TimelockConfigInvalid(category);

        TimelockConfigStorage.ScopeOverride storage ov = configLayout.overrides[category][scope];
        if (input.setDelay) {
            if (input.delay < cat.minDelay || input.delay > cat.maxDelay) {
                revert TimelockLib.TimelockDelayOutOfBounds(input.delay, cat.minDelay, cat.maxDelay);
            }
            ov.delay = input.delay;
            ov.delaySet = true;
        }
        if (input.setPolicy) {
            _requireExistingPolicy(input.policyId);
            TimelockLib.replaceConfigPolicyRef(ov.policySet ? ov.policyId : bytes32(0), input.policyId);
            ov.policyId = input.policyId;
            ov.policySet = true;
        }
        if (input.setGrace) {
            if (input.gracePeriod > TimelockLib.maxGracePeriod()) revert TimelockConfigInvalid(category);
            ov.gracePeriod = input.gracePeriod;
            ov.graceSet = true;
        }

        // Configuration helpers mutate local storage; runner validation is STATICCALL-only before the write and
        // event.
        // forge-lint: disable-start(reentrancy-events)
        emit TimelockScopeOverrideSet(
            category, scope, ov.delaySet, ov.delay, ov.policySet, ov.policyId, ov.graceSet, ov.gracePeriod
        );
        // forge-lint: disable-end(reentrancy-events)
    }

    /// @notice Clear the override assigned for a category/scope pair.
    /// @dev Callable by the registry owner or TIMELOCK_GOVERNOR capability holders. Clearing an override is governed
    ///      by the timelock configuration category, so it may queue under the current config.
    /// @param category Category identifier.
    /// @param scope Scope identifier whose override should be deleted.
    function clearScopeOverride(bytes32 category, bytes32 scope) external {
        _requireTimelockGovernor();
        bytes32 scopeKey = _overrideScopeKey(category, scope);
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryTimelock(),
                scope: scopeKey,
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            abi.encodeWithSelector(this.clearScopeOverride.selector, category, scope)
        );
        if (!executing) {
            return;
        }

        TimelockConfigStorage.Layout storage configLayout = TimelockConfigStorage.state();
        TimelockConfigStorage.ScopeOverride storage ov = configLayout.overrides[category][scope];
        if (ov.policySet) {
            TimelockLib.removeConfigPolicyRef(ov.policyId);
        }
        delete configLayout.overrides[category][scope];
        // Configuration helpers mutate local storage; runner validation is STATICCALL-only before the write and
        // event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit TimelockScopeOverrideCleared(category, scope);
    }

    /// @notice Fetch the current category configuration.
    /// @param category Category identifier to inspect.
    /// @return out Stored configuration or the code-defined built-in default.
    function getCategoryConfig(bytes32 category) external view returns (TimelockCategoryConfigInput memory out) {
        TimelockConfigStorage.CategoryConfig memory cat = TimelockLib.categoryConfig(category);
        if (!cat.exists) revert TimelockConfigInvalid(category);
        out.minDelay = cat.minDelay;
        out.maxDelay = cat.maxDelay;
        out.defaultDelay = cat.defaultDelay;
        out.gracePeriod = cat.gracePeriod;
        out.defaultPolicyId = cat.defaultPolicyId;
    }

    /// @notice Returns true for a built-in category or an explicitly stored custom category.
    /// @param category Category identifier to check.
    function hasCategoryConfig(bytes32 category) external view returns (bool) {
        return TimelockLib.hasCategoryConfig(category);
    }

    /// @notice Fetch the scope override (if any) for a category/scope key.
    /// @param category Category identifier.
    /// @param scope Scope identifier.
    /// @return out Serialized override fields. When `exists` is false the contents should be ignored.
    /// @return exists True when an override has been written for the provided pair.
    function getScopeOverride(bytes32 category, bytes32 scope)
        external
        view
        returns (TimelockScopeOverrideInput memory out, bool exists)
    {
        TimelockConfigStorage.Layout storage configLayout = TimelockConfigStorage.state();
        TimelockConfigStorage.ScopeOverride storage ov = configLayout.overrides[category][scope];
        if (ov.delaySet || ov.policySet || ov.graceSet) {
            exists = true;
            out.setDelay = ov.delaySet;
            out.delay = ov.delay;
            out.setPolicy = ov.policySet;
            out.policyId = ov.policyId;
            out.setGrace = ov.graceSet;
            out.gracePeriod = ov.gracePeriod;
        }
    }

    /// @notice Return a view of a queued action.
    function getAction(bytes32 actionId) external view returns (TimelockActionView memory view_) {
        TimelockStorage.Action memory action = TimelockLib.action(actionId);
        if (action.status == TimelockActionStatus.None) {
            revert TimelockActionUnknown(actionId);
        }
        view_.id = action.id;
        view_.category = action.category;
        view_.scope = action.scope;
        view_.actor = action.actor;
        view_.payloadHash = action.payloadHash;
        view_.policyId = action.policyId;
        view_.scheduledAt = action.scheduledAt;
        view_.delay = action.delay;
        view_.eta = action.eta;
        view_.expiresAt = action.expiresAt;
        view_.status = action.status;
        view_.executable = TimelockLib.isExecutable(actionId);
    }

    /// @notice Return live approval progress and eligibility for a prospective approver.
    /// @dev The result uses the action's current policy criteria and current group membership. Passing address zero
    ///      returns policy progress without attributing eligibility to an account.
    function getActionApprovalState(bytes32 actionId, address approver)
        external
        view
        returns (TimelockActionApprovalState memory)
    {
        if (TimelockLib.action(actionId).status == TimelockActionStatus.None) {
            revert TimelockActionUnknown(actionId);
        }
        return TimelockLib.actionApprovalState(actionId, approver);
    }

    /// @notice Returns a compact summary for a timelock action.
    function getActionSummary(bytes32 actionId) public view returns (TimelockActionSummary memory summary) {
        TimelockStorage.Action memory action = TimelockLib.action(actionId);
        if (action.status == TimelockActionStatus.None) {
            revert TimelockActionUnknown(actionId);
        }
        return _buildSummary(action);
    }

    /// @notice Return all required reviews for the one atomic mutation, starting with its replay action.
    /// @dev Approve each record's policy separately. Executing or cancelling any record addresses the whole bundle.
    function getActionBundle(bytes32 actionId) external view returns (bytes32[] memory) {
        if (TimelockLib.action(actionId).status == TimelockActionStatus.None) revert TimelockActionUnknown(actionId);
        return TimelockLib.bundleActions(actionId);
    }

    /// @notice Return the queued and current runtime-semantics generations for an action.
    /// @dev A stale action cannot receive approvals or execute, but anyone may cancel it.
    function getActionSemantics(bytes32 actionId)
        external
        view
        returns (uint64 queuedGeneration, uint64 currentGeneration, bool current)
    {
        TimelockStorage.Action memory action = TimelockLib.action(actionId);
        if (action.status == TimelockActionStatus.None) revert TimelockActionUnknown(actionId);
        queuedGeneration = action.semanticsGeneration;
        currentGeneration = TimelockLib.actionSemanticsGeneration();
        current = queuedGeneration == currentGeneration;
    }

    /// @notice Return the generation assigned to newly queued Registry actions.
    function actionSemanticsGeneration() external view returns (uint64) {
        return TimelockLib.actionSemanticsGeneration();
    }

    /// @notice Enable optional indexing helpers for timelock payload retention.
    /// @dev One-way switch intended to be set at deployment by the owner or a TIMELOCK_GOVERNOR capability holder.
    function enableIndexing() external {
        _requireTimelockGovernor();
        IndexingStorage.Layout storage cfg = IndexingStorage.state();
        if (cfg.enabled) {
            revert IndexingAlreadyEnabled();
        }
        cfg.enabled = true;
        cfg.startBlock = SafeCast.toUint64(block.number);
        // Configuration helpers mutate local storage; runner validation is STATICCALL-only before the write and
        // event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit IndexingEnabled(cfg.startBlock);
    }

    /// @notice Returns whether timelock indexing and payload retention are enabled.
    function indexingEnabled() external view returns (bool) {
        return IndexingStorage.state().enabled;
    }

    /// @notice Returns the block where timelock indexing was enabled, or zero when disabled.
    function indexingStartBlock() external view returns (uint64) {
        return IndexingStorage.state().startBlock;
    }

    /// @notice Configure the MiniScript instance used to run timelock policy programs.
    /// @dev The runner must be the protocol's non-upgradeable TimelockPolicyProgramRunner runtime, bound to this
    ///      registry as both `registry()` and `authorizedCaller()`, with a current or explicitly supported
    ///      predecessor engine and its matching children at `engine()`. Setting zero disables the runner,
    ///      but executing an action whose policy has a program will then revert.
    function setTimelockPolicyRunner(address runner) external {
        _requireTimelockGovernor();
        (bool executing,) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryTimelock(),
                scope: POLICY_RUNNER_SCOPE,
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            abi.encodeWithSelector(this.setTimelockPolicyRunner.selector, runner)
        );
        if (!executing) {
            return;
        }
        _validateTimelockPolicyRunner(runner);
        TimelockConfigStorage.Layout storage config = TimelockConfigStorage.state();
        if (config.policyProgramRunner != runner) {
            config.policyProgramRunner = runner;
            ExecutionCatalogStorage.bumpRuntime();
            TimelockLib.bumpActionSemanticsGeneration();
        }
        // Configuration helpers mutate local storage; runner validation is STATICCALL-only before the write and
        // event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit TimelockPolicyProgramRunnerSet(runner, _msgSenderD());
    }

    /// @notice Return the configured MiniScript runner used for timelock policy programs.
    function getTimelockPolicyRunner() external view returns (address) {
        return TimelockConfigStorage.state().policyProgramRunner;
    }

    /// @notice Return one ABI payload word from a queued action, excluding the 4-byte selector.
    /// @dev Returns zero when the action or requested payload word is missing.
    function getActionPayloadWord(bytes32 actionId, uint256 wordIndex) external view returns (bytes32) {
        TimelockStorage.Action memory action = TimelockLib.action(actionId);
        if (action.status == TimelockActionStatus.None) {
            revert TimelockActionUnknown(actionId);
        }
        return _payloadWord(TimelockLib.payload(actionId), wordIndex);
    }

    /// @notice Return a page of pending action identifiers.
    /// @param start Index of the first id to return.
    /// @param count Maximum number of identifiers to return.
    function getPendingActionIds(uint256 start, uint256 count) external view returns (bytes32[] memory) {
        return TimelockLib.pendingIdsPage(start, count);
    }

    /// @notice Return number of pending actions.
    function getPendingActionCount() external view returns (uint256) {
        return TimelockLib.pendingCount();
    }

    /// @notice Return summaries for a page of pending actions.
    function getPendingActionSummaries(uint256 start, uint256 count)
        external
        view
        returns (TimelockActionSummary[] memory summaries)
    {
        bytes32[] memory ids = TimelockLib.pendingIdsPage(start, count);
        summaries = new TimelockActionSummary[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            TimelockStorage.Action memory action = TimelockLib.action(ids[i]);
            // An indexed action must exist; returning a partial page would hide an index/state mismatch.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (action.status == TimelockActionStatus.None) revert TimelockActionUnknown(ids[i]);
            summaries[i] = _buildSummary(action);
        }
    }

    /// @notice Return a page of executed action identifiers.
    /// @param start Index of the first id to return.
    /// @param count Maximum number of identifiers to return.
    function getExecutedActionIds(uint256 start, uint256 count) external view returns (bytes32[] memory) {
        return TimelockLib.executedIdsPage(start, count);
    }

    /// @notice Return number of executed actions.
    function getExecutedActionCount() external view returns (uint256) {
        return TimelockLib.executedCount();
    }

    /// @notice Return summaries for a page of executed actions.
    function getExecutedActionSummaries(uint256 start, uint256 count)
        external
        view
        returns (TimelockActionSummary[] memory summaries)
    {
        bytes32[] memory ids = TimelockLib.executedIdsPage(start, count);
        summaries = new TimelockActionSummary[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            TimelockStorage.Action memory action = TimelockLib.action(ids[i]);
            // An indexed action must exist; returning a partial page would hide an index/state mismatch.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (action.status == TimelockActionStatus.None) revert TimelockActionUnknown(ids[i]);
            summaries[i] = _buildSummary(action);
        }
    }

    /// @notice Approve an action according to its attached policy.
    /// @param actionId Identifier of the queued action.
    /// @return readyNow True when thresholds are satisfied by this approval and the action flipped to Ready.
    function approveAction(bytes32 actionId) external returns (bool readyNow) {
        return abi.decode(
            _delegateExecution(abi.encodeCall(RegistryTimelockExecutionModule.approveAction, (actionId))), (bool)
        );
    }

    /// @notice Cancel every review in a bundle under the original cancellation authority.
    function cancelAction(bytes32 actionId) external {
        _delegateExecution(abi.encodeCall(RegistryTimelockExecutionModule.cancelAction, (actionId)));
    }

    /// @notice Permissionlessly expire an elapsed bundle, including while paused.
    function expireAction(bytes32 actionId) external {
        _delegateExecution(abi.encodeCall(RegistryTimelockExecutionModule.expireAction, (actionId)));
    }

    /// @notice Execute a ready timelock action once the delay has elapsed and approvals satisfied.
    /// @dev Execution uses the live program for the queued action's policy id. This is intentional: governance can
    ///      update policy programs while actions are pending, and execution will evaluate the current policy.
    /// @param actionId Identifier of the ready action to execute.
    /// @return returnData ABI encoded data returned by the executed internal call.
    function executeAction(bytes32 actionId) external returns (bytes memory returnData) {
        bytes memory callData = abi.encodeCall(RegistryTimelockExecutionModule.executeAction, (actionId));
        return abi.decode(_delegateExecution(callData), (bytes));
    }

    /// @notice Execute multiple ready timelock actions in a single transaction.
    /// @dev Each action uses the live program for its queued policy id at the time that action is executed.
    /// @param actionIds Identifiers of the ready actions to execute.
    /// @return returnData ABI encoded data returned per executed action.
    function executeActions(bytes32[] calldata actionIds) external returns (bytes[] memory returnData) {
        bytes memory callData = abi.encodeCall(RegistryTimelockExecutionModule.executeActions, (actionIds));
        return abi.decode(_delegateExecution(callData), (bytes[]));
    }

    function _delegateExecution(bytes memory callData) private returns (bytes memory ret) {
        address module = address(EXECUTION_MODULE);
        bytes32 codehash = module.codehash;
        if (!ProtocolCodehashes.isAcceptedRegistryTimelockExecutionModuleCodehash(codehash)) {
            revert TimelockExecutionModuleInvalid(module, codehash);
        }
        // The target is the immutable execution module and its canonical runtime hash was checked immediately above.
        // forge-lint: disable-next-line(controlled-delegatecall)
        (bool success, bytes memory data) = module.delegatecall(callData);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(data, 0x20), mload(data))
            }
        }
        return data;
    }

    function _payloadWord(bytes memory payload, uint256 wordIndex) private pure returns (bytes32 word) {
        uint256 offset = 4 + (wordIndex + 1) * 32;
        if (payload.length < offset) {
            return bytes32(0);
        }
        assembly ("memory-safe") {
            word := mload(add(add(payload, 0x24), mul(wordIndex, 0x20)))
        }
    }

    function _validateTimelockPolicyRunner(address runner) private view {
        if (runner == address(0)) {
            return;
        }
        if (runner.code.length == 0) revert TimelockPolicyRunnerInvalid(runner);
        if (!_isTrustedTimelockPolicyRunnerHash(runner.codehash)) {
            revert TimelockPolicyRunnerInvalid(runner);
        }
        if (_runnerViewAddress(runner, RUNNER_REGISTRY_SELECTOR) != address(this)) {
            revert TimelockPolicyRunnerInvalid(runner);
        }
        if (_runnerViewAddress(runner, RUNNER_AUTHORIZED_CALLER_SELECTOR) != address(this)) {
            revert TimelockPolicyRunnerInvalid(runner);
        }
        if (!TimelockEngineCompatibility.isAcceptedDeployment(_runnerViewAddress(runner, RUNNER_ENGINE_SELECTOR))) {
            revert TimelockPolicyRunnerInvalid(runner);
        }
    }

    function _isTrustedTimelockPolicyRunnerHash(bytes32 codeHash) private pure returns (bool) {
        return ProtocolCodehashes.isAcceptedTimelockPolicyRunnerCodehash(codeHash);
    }

    function _runnerViewAddress(address runner, bytes4 selector) private view returns (address value) {
        (bool ok, bytes memory data) = runner.staticcall(abi.encodeWithSelector(selector));
        if (!ok || data.length != 32) revert TimelockPolicyRunnerInvalid(runner);
        assembly ("memory-safe") {
            value := mload(add(data, 0x20))
        }
    }

    function _buildSummary(TimelockStorage.Action memory action)
        private
        pure
        returns (TimelockActionSummary memory summary)
    {
        summary.id = action.id;
        summary.category = action.category;
        summary.scope = action.scope;
        summary.actor = action.actor;
        summary.scheduledAt = action.scheduledAt;
        summary.delay = action.delay;
        summary.eta = action.eta;
        summary.expiresAt = action.expiresAt;
        summary.status = action.status;
        summary.policyId = action.policyId;
        summary.payloadHash = action.payloadHash;
    }

    function _categoryScopeKey(bytes32 category) private pure returns (bytes32 result) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore8(ptr, 0x01)
            mstore(add(ptr, 0x01), category)
            result := keccak256(ptr, 0x21)
            mstore(0x40, add(ptr, 0x60))
        }
    }

    function _overrideScopeKey(bytes32 category, bytes32 scope) private pure returns (bytes32 result) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore8(ptr, 0x02)
            mstore(add(ptr, 0x01), category)
            mstore(add(ptr, 0x21), scope)
            result := keccak256(ptr, 0x41)
            mstore(0x40, add(ptr, 0x80))
        }
    }

    /// @dev Timelock governance is owner-compatible for bootstrap, then capability-compatible for delegated ops.
    function _requireTimelockGovernor() private view {
        address actor = _msgSenderD();
        if (_isBootstrapOwnerD(actor)) {
            return;
        }
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.TIMELOCK_GOVERNOR)) {
            return;
        }
        revert OwnableUnauthorizedAccount(actor);
    }

    function _requireExistingPolicy(bytes32 policyId) private view {
        if (policyId == bytes32(0)) {
            return;
        }
        if (!PoliciesStorage.exists(PoliciesStorage.getLayout(), policyId)) {
            revert TimelockLib.TimelockPolicyMissing(policyId);
        }
    }
}
