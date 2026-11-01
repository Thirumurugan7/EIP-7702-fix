// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {PagedIndex} from "../PagedIndex.sol";
import {GroupCriteria, Policy} from "../RegistryTypes.sol";
import {GovernanceData} from "./GovernanceData.sol";
import {PendingActionList} from "./PendingActionList.sol";
import {
    ExecutionCatalogStorage,
    GroupsStorage,
    IndexingStorage,
    PoliciesStorage,
    StorageKeys
} from "./RegistryShared.sol";
import {DiamondCutStorage} from "./diamond/DiamondCutStorage.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/// @title TimelockActionStatus
/// @notice Runtime status for tracked timelock actions.
enum TimelockActionStatus {
    None,
    Queued,
    Ready,
    Executing,
    Executed,
    Cancelled,
    Expired
}

/// @title TimelockRequest
/// @notice Structured request parameters used when queueing a timelocked call.
/// @dev Mutating registry facets construct this struct and hand it to `TimelockLib.enforceOrQueue`.
struct TimelockRequest {
    bytes32 category;
    bytes32 scope;
    bytes32 policyId;
    uint64 delay;
    uint64 gracePeriod;
}

/// @title TimelockResolvedConfig
/// @notice Resolved configuration after applying category defaults and overrides.
struct TimelockResolvedConfig {
    uint64 delay;
    uint64 gracePeriod;
    bytes32 policyId;
}

/// @title TimelockApprovalGroupState
/// @notice Live approval progress for one group in a timelock action's current policy.
/// @dev `activeApprovals` is capped at `threshold`; approvals above the threshold do not affect readiness.
struct TimelockApprovalGroupState {
    bytes32 groupHash;
    uint256 threshold;
    uint256 activeApprovals;
    bool satisfied;
    bool approverIsMember;
    bool approverHasApproved;
    bool approverCanContribute;
}

/// @title TimelockActionApprovalState
/// @notice Canonical live policy and approver state for one timelock action.
struct TimelockActionApprovalState {
    bytes32 policyId;
    TimelockActionStatus status;
    bool policyExists;
    bool approvalsSatisfied;
    bool acceptingApprovals;
    bool canApproverApprove;
    bool approverWouldSatisfy;
    TimelockApprovalGroupState[] groups;
}

/// @title ExecutionContextLib
/// @notice Tracks the logical actor and action metadata while a timelocked call is replaying or emulated.
/// @dev Facets use this to behave as though the original actor were calling directly, even though the actual call is
///      being replayed by the timelock executor. Immediate zero-delay paths that require context must enter it
///      explicitly, usually with a zero action id.
library ExecutionContextLib {
    /// @notice Storage layout for the active timelock execution context.
    struct Layout {
        address actor;
        bytes32 actionId;
        bytes32 category;
        bytes32 scope;
        bool active;
    }

    /// @notice Return the namespaced execution-context storage.
    function state() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.EXECUTION_CONTEXT_SLOT;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Returns true when the current call is the Registry's timelock replay.
    /// @dev The raw storage flag remains set across external callbacks made by the
    ///      replayed payload. Restricting visibility to Registry self-calls prevents
    ///      a callback from inheriting the queued actor or bypassing queue checks.
    function isActive() internal view returns (bool) {
        return state().active && msg.sender == address(this);
    }

    /// @notice Resolves the actor for a Registry self-replay, otherwise returns the real caller.
    function actorOrSender() internal view returns (address) {
        Layout storage l = state();
        return l.active && msg.sender == address(this) ? l.actor : msg.sender;
    }

    /// @notice Returns the action id currently bound to the execution context.
    function currentActionId() internal view returns (bytes32) {
        return state().actionId;
    }

    /// @notice Returns the category currently bound to the execution context.
    function currentCategory() internal view returns (bytes32) {
        return state().category;
    }

    /// @notice Returns the scope currently bound to the execution context.
    function currentScope() internal view returns (bytes32) {
        return state().scope;
    }

    /// @notice Enters the execution context for an action, preventing nested re-entry.
    function enter(bytes32 actionId, address actor_, bytes32 category, bytes32 scope) internal {
        Layout storage l = state();
        // Action status, semantics, and single execution context are per-action invariants and must fail closed.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (l.active) revert("TimelockCtx:active");
        l.active = true;
        l.actor = actor_;
        l.actionId = actionId;
        l.category = category;
        l.scope = scope;
    }

    /// @notice Clear the active execution context after a timelocked call finishes.
    function exit() internal {
        Layout storage l = state();
        l.active = false;
        l.actor = address(0);
        l.actionId = bytes32(0);
        l.category = bytes32(0);
        l.scope = bytes32(0);
    }

    /// @notice Ensures the stored execution context matches the expected category + scope pair.
    function ensure(bytes32 category, bytes32 scope) internal view {
        Layout storage l = state();
        if (!isActive()) revert("TimelockCtx:inactive");
        if (l.category != category) revert("TimelockCtx:category");
        if (l.scope != scope) revert("TimelockCtx:scope");
    }
}

/// @title TimelockConfigStorage
/// @notice Namespaced storage for category defaults, scope overrides, and policy reference counts.
/// @dev Categories define the broad rules for a type of action, while overrides let governance tighten or relax those
///      rules for a specific scope such as one contract key or one capability grant.
library TimelockConfigStorage {
    /// @notice Default delay, grace, and policy settings for a whole action category.
    struct CategoryConfig {
        uint64 minDelay;
        uint64 maxDelay;
        uint64 defaultDelay;
        uint64 gracePeriod;
        bytes32 defaultPolicyId;
        bool exists;
    }

    /// @notice User supplied overrides applied per category + scope pair.
    struct ScopeOverride {
        uint64 delay;
        uint64 gracePeriod;
        bytes32 policyId;
        bool delaySet;
        bool graceSet;
        bool policySet;
    }

    /// @notice Full timelock configuration state.
    struct Layout {
        mapping(bytes32 => CategoryConfig) categories;
        mapping(bytes32 => mapping(bytes32 => ScopeOverride)) overrides;
        mapping(bytes32 => uint256) policyRefCount;
        address policyProgramRunner;
    }

    /// @notice Return the namespaced timelock configuration storage.
    function state() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.TIMELOCK_CONFIG_SLOT;
        assembly {
            l.slot := slot
        }
    }
}

/// @title TimelockPayloadStorage
/// @notice Namespaced storage for calldata blobs queued behind the timelock.
/// @dev Payload bytes are stored separately from action metadata so queued action records remain compact.
library TimelockPayloadStorage {
    /// @notice Storage layout for timelock calldata blobs keyed by action id.
    struct Layout {
        mapping(bytes32 => bytes) payloads;
    }

    /// @notice Return the namespaced payload storage.
    function state() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.TIMELOCK_PAYLOAD_SLOT;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Persist calldata for a queued action.
    function store(bytes32 actionId, bytes memory payload) internal {
        state().payloads[actionId] = payload;
    }

    /// @notice Load the queued calldata for `actionId`.
    function load(bytes32 actionId) internal view returns (bytes memory) {
        return state().payloads[actionId];
    }

    /// @notice Delete the stored calldata for `actionId`.
    function clear(bytes32 actionId) internal {
        delete state().payloads[actionId];
    }
}

/// @title TimelockApprovalsStorage
/// @notice Namespaced storage for approval tallies attached to queued actions.
/// @dev Counts are stored per action and per policy group so the timelock can mirror the same threshold model used by
///      runtime operations.
library TimelockApprovalsStorage {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Tracks approvals per action and per policy group.
    struct Layout {
        mapping(bytes32 => mapping(bytes32 => EnumerableSet.AddressSet)) groupApprovers;
    }

    /// @notice Return the namespaced approval-tally storage.
    function state() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.TIMELOCK_APPROVAL_SLOT;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Record an approver in one policy group.
    function addGroupApprover(bytes32 actionId, bytes32 groupHash, address approver)
        internal
        returns (bool added, uint256 newCount)
    {
        Layout storage l = state();
        added = l.groupApprovers[actionId][groupHash].add(approver);
        newCount = l.groupApprovers[actionId][groupHash].length();
    }

    /// @notice Remove approvers that no longer belong to `groupHash`.
    /// @dev Called before replacement approval so the stored set stays bounded across membership churn.
    function compactGroupApprovers(bytes32 actionId, bytes32 groupHash) internal returns (uint256 liveCount) {
        Layout storage l = state();
        EnumerableSet.AddressSet storage approvers = l.groupApprovers[actionId][groupHash];
        GroupsStorage.Layout storage groups = GroupsStorage.getLayout();
        uint256 i = 0;
        while (i < approvers.length()) {
            address approver = approvers.at(i);
            if (!GroupsStorage.isMember(groups, groupHash, approver)) {
                approvers.remove(approver);
            } else {
                unchecked {
                    ++i;
                }
            }
        }
        liveCount = approvers.length();
    }

    /// @dev Stop once `threshold` live approvals are found. This bounds the
    ///      execution-time scan by the approvals actually required by policy.
    function liveGroupCount(bytes32 actionId, bytes32 groupHash, uint256 threshold)
        internal
        view
        returns (uint256 count)
    {
        if (threshold == 0) return 0;
        EnumerableSet.AddressSet storage approvers = state().groupApprovers[actionId][groupHash];
        GroupsStorage.Layout storage groups = GroupsStorage.getLayout();
        for (uint256 i; i < approvers.length(); ++i) {
            if (GroupsStorage.isMember(groups, groupHash, approvers.at(i))) {
                ++count;
                if (count == threshold) return count;
            }
        }
    }

    /// @notice Return the number of approvals recorded for one group within one action.
    function groupCount(bytes32 actionId, bytes32 groupHash) internal view returns (uint256) {
        return state().groupApprovers[actionId][groupHash].length();
    }

    /// @notice Return whether `approver` has a stored approval in one action policy group.
    function hasGroupApproval(bytes32 actionId, bytes32 groupHash, address approver) internal view returns (bool) {
        return state().groupApprovers[actionId][groupHash].contains(approver);
    }
}

/// @title TimelockStorage
/// @notice Namespaced storage for queued and executed timelock actions.
/// @dev The paged indexes expose queue history to UIs and off-chain tooling without requiring log-only reconstruction.
library TimelockStorage {
    using PagedIndex for PagedIndex.Index;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @notice Canonical representation of a queued timelock action.
    struct Action {
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
        /// @notice Runtime-semantics generation under which this action was authorized.
        uint64 semanticsGeneration;
    }

    struct CompactBundle {
        address data;
        uint8 policyPosition;
        // Each child keeps its own readiness bit; approvals remain scoped by full action id.
        uint256 ready;
    }

    /// @notice Full action queue state.
    struct Layout {
        mapping(bytes32 => Action) actions;
        PagedIndex.Index pending;
        PagedIndex.Index executed;
        uint128 nonce;
        mapping(bytes32 => EnumerableSet.Bytes32Set) pendingActionsByPolicy;
        /// @dev Zero storage encodes the initial generation, one.
        uint64 actionSemanticsGeneration;
        // Conjunctive governance keeps each category/scope policy independently
        // reviewable. All records in a bundle execute or terminate together.
        mapping(bytes32 => bytes32) governanceCommitment;
        mapping(bytes32 => bool) guardianCancellationBlocked;
        // Compact bundles keep shared metadata and indexes on their root. Review ids use
        // the root's reserved low 16 bits, and immutable code stores each scope/policy pair.
        mapping(bytes32 => CompactBundle) compactBundleData;
        mapping(bytes32 => PendingActionList.List) compactPendingPolicies;
    }

    /// @notice Return the namespaced core timelock storage.
    function state() internal pure returns (Layout storage l) {
        bytes32 slot = StorageKeys.TIMELOCK_CORE_SLOT;
        assembly {
            l.slot := slot
        }
    }
}

/// @title TimelockLib
/// @notice Shared queueing, approval, and execution helpers used by registry facets.
/// @dev Facets call `enforceOrQueue` before mutating state. If the relevant category/scope currently requires no
///      delay, execution continues immediately. Otherwise an action is queued, approvals accumulate against the
///      configured policy, and a later executor replays the original payload through the dispatcher.
library TimelockLib {
    using PagedIndex for PagedIndex.Index;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    error TimelockGovernanceChanged(bytes32 actionId);
    event ActionBundled(bytes32 indexed rootActionId, bytes32 indexed actionId);
    /// @notice A requirement without an approval policy is committed and timed by the root action.
    event ActionRequirement(bytes32 indexed rootActionId, bytes32 indexed category, bytes32 indexed scope);
    uint256 private constant REVIEW_MASK = type(uint16).max;
    uint256 private constant REVIEW_BYTES = 66;

    /// @notice Category key for organization writes.
    bytes32 internal constant CATEGORY_ORG = keccak256("timelock.category.org");
    /// @notice Category key for user allowlist writes.
    bytes32 internal constant CATEGORY_USER = keccak256("timelock.category.user");
    /// @notice Category key for group membership/configuration writes.
    bytes32 internal constant CATEGORY_GROUP = keccak256("timelock.category.group");
    /// @notice Category key for policy writes.
    bytes32 internal constant CATEGORY_POLICY = keccak256("timelock.category.policy");
    /// @notice Category key for contract directory writes.
    bytes32 internal constant CATEGORY_CONTRACT = keccak256("timelock.category.contract");
    /// @notice Category key for token directory writes.
    bytes32 internal constant CATEGORY_TOKEN = keccak256("timelock.category.token");
    /// @notice Category key for interaction bundle and private-commit writes.
    bytes32 internal constant CATEGORY_INTERACTION = keccak256("timelock.category.interaction");
    /// @notice Category key for contract/token/interaction activation changes.
    bytes32 internal constant CATEGORY_ACTIVATION = keccak256("timelock.category.activation");
    /// @notice Category key for metadata writes.
    bytes32 internal constant CATEGORY_METADATA = keccak256("timelock.category.metadata");
    /// @notice Category key for auth link writes.
    bytes32 internal constant CATEGORY_AUTH = keccak256("timelock.category.auth");
    /// @notice Category key for Safe allowlist writes.
    bytes32 internal constant CATEGORY_SAFE = keccak256("timelock.category.safe");
    /// @notice Category key for account allowlist writes.
    bytes32 internal constant CATEGORY_ACCOUNT = keccak256("timelock.category.account");
    /// @notice Category key for diamond upgrades and facet cuts.
    bytes32 internal constant CATEGORY_DIAMOND = keccak256("timelock.category.diamond");
    /// @notice Category key for governed registry role grants and revokes.
    bytes32 internal constant CATEGORY_ROLE_ADMIN = keccak256("timelock.category.role.admin");
    /// @notice Category key for timelock configuration changes themselves.
    bytes32 internal constant CATEGORY_TIMELOCK = keccak256("timelock.category.config");
    /// @notice Category key for capability grants/revokes.
    bytes32 internal constant CATEGORY_CAPABILITY = keccak256("timelock.category.capability");
    /// @notice Category key for source-registry allowlist changes.
    bytes32 internal constant CATEGORY_SYNC_SOURCE = keccak256("timelock.category.sync.source");
    /// @notice Category key for contract imports from approved source registries.
    bytes32 internal constant CATEGORY_SYNC_CONTRACT = keccak256("timelock.category.sync.contract");
    /// @notice Category key for token imports from approved source registries.
    bytes32 internal constant CATEGORY_SYNC_TOKEN = keccak256("timelock.category.sync.token");

    uint64 internal constant DEFAULT_MAX_DELAY = 30 days;
    uint64 internal constant DEFAULT_GRACE_PERIOD = 30 days;
    uint64 internal constant MAX_GRACE_PERIOD = type(uint24).max;

    error TimelockScopeMismatch(bytes32 expected, bytes32 actual);
    error TimelockCategoryMismatch(bytes32 expected, bytes32 actual);
    error TimelockDelayOutOfBounds(uint64 delay, uint64 minDelay, uint64 maxDelay);
    error TimelockDelayBelowRequiredMinimum(uint64 delay, uint64 requiredMinimum);
    error TimelockCategoryNotConfigured(bytes32 category);
    error TimelockAlreadyApproved(bytes32 actionId, address approver);
    error TimelockNotEligible(bytes32 actionId, address approver);
    error TimelockPolicyMissing(bytes32 policyId);
    error TimelockWrongStatus(bytes32 actionId, TimelockActionStatus want, TimelockActionStatus got);
    error TimelockExpired(bytes32 actionId);
    error TimelockActionSemanticsStale(bytes32 actionId, uint64 queuedGeneration, uint64 currentGeneration);

    event ActionQueued(
        bytes32 indexed actionId,
        bytes32 indexed category,
        bytes32 indexed scope,
        address actor,
        uint64 eta,
        uint64 expiresAt,
        bytes32 payloadHash,
        bytes32 policyId
    );
    event ActionReady(bytes32 indexed actionId);
    event ActionCancelled(bytes32 indexed actionId, address indexed by);
    event ActionExecuted(bytes32 indexed actionId, address indexed executor);
    event ActionExpired(bytes32 indexed actionId);
    event ActionSemanticsGenerationAdvanced(uint64 previousGeneration, uint64 newGeneration);
    event ActionApproved(
        bytes32 indexed actionId, address indexed approver, bytes32 indexed groupHash, uint256 newCount
    );

    function categoryOrg() internal pure returns (bytes32) {
        return CATEGORY_ORG;
    }

    function categoryUser() internal pure returns (bytes32) {
        return CATEGORY_USER;
    }

    function categoryGroup() internal pure returns (bytes32) {
        return CATEGORY_GROUP;
    }

    function categoryPolicy() internal pure returns (bytes32) {
        return CATEGORY_POLICY;
    }

    function categoryContract() internal pure returns (bytes32) {
        return CATEGORY_CONTRACT;
    }

    function categoryToken() internal pure returns (bytes32) {
        return CATEGORY_TOKEN;
    }

    function categoryInteraction() internal pure returns (bytes32) {
        return CATEGORY_INTERACTION;
    }

    function categoryActivation() internal pure returns (bytes32) {
        return CATEGORY_ACTIVATION;
    }

    function categoryMetadata() internal pure returns (bytes32) {
        return CATEGORY_METADATA;
    }

    function categoryAuth() internal pure returns (bytes32) {
        return CATEGORY_AUTH;
    }

    function categorySafe() internal pure returns (bytes32) {
        return CATEGORY_SAFE;
    }

    function categoryAccount() internal pure returns (bytes32) {
        return CATEGORY_ACCOUNT;
    }

    function categoryDiamond() internal pure returns (bytes32) {
        return CATEGORY_DIAMOND;
    }

    function categoryRoleAdmin() internal pure returns (bytes32) {
        return CATEGORY_ROLE_ADMIN;
    }

    function categoryTimelock() internal pure returns (bytes32) {
        return CATEGORY_TIMELOCK;
    }

    function categoryCapability() internal pure returns (bytes32) {
        return CATEGORY_CAPABILITY;
    }

    function categorySyncSource() internal pure returns (bytes32) {
        return CATEGORY_SYNC_SOURCE;
    }

    function categorySyncContract() internal pure returns (bytes32) {
        return CATEGORY_SYNC_CONTRACT;
    }

    function categorySyncToken() internal pure returns (bytes32) {
        return CATEGORY_SYNC_TOKEN;
    }

    /// @notice Return whether `category` is part of the protocol-defined surface.
    /// @dev Built-in bootstrap defaults are code-defined instead of materialized
    ///      as 20 storage records. This keeps Registry deployment below public
    ///      chain gas caps while unknown categories still fail closed.
    function isProtocolCategory(bytes32 category) internal pure returns (bool) {
        return category == CATEGORY_ORG || category == CATEGORY_USER || category == CATEGORY_GROUP
            || category == CATEGORY_POLICY || category == CATEGORY_CONTRACT || category == CATEGORY_TOKEN
            || category == CATEGORY_INTERACTION || category == CATEGORY_ACTIVATION || category == CATEGORY_METADATA
            || category == CATEGORY_AUTH || category == CATEGORY_SAFE || category == CATEGORY_ACCOUNT
            || category == CATEGORY_DIAMOND || category == CATEGORY_ROLE_ADMIN || category == CATEGORY_TIMELOCK
            || category == CATEGORY_CAPABILITY || category == CATEGORY_SYNC_SOURCE || category == CATEGORY_SYNC_CONTRACT
            || category == CATEGORY_SYNC_TOKEN;
    }

    /// @notice Resolve a stored category or the code-defined built-in default.
    /// @dev The returned `exists` flag is false only for unknown, unconfigured
    ///      categories. Once governance stores a built-in override, storage wins.
    function categoryConfig(bytes32 category)
        internal
        view
        returns (TimelockConfigStorage.CategoryConfig memory config)
    {
        TimelockConfigStorage.CategoryConfig storage stored = TimelockConfigStorage.state().categories[category];
        if (stored.exists) return stored;
        if (!isProtocolCategory(category)) return config;
        config.maxDelay = DEFAULT_MAX_DELAY;
        config.gracePeriod = DEFAULT_GRACE_PERIOD;
        config.exists = true;
    }

    function hasCategoryConfig(bytes32 category) internal view returns (bool) {
        return categoryConfig(category).exists;
    }

    function maxGracePeriod() internal pure returns (uint64) {
        return MAX_GRACE_PERIOD;
    }

    /// @notice Returns the number of timelock config entries currently referencing a policy.
    function policyConfigRefCount(bytes32 policyId) internal view returns (uint256 count) {
        count = TimelockConfigStorage.state().policyRefCount[policyId];
    }

    /// @notice Replaces one policy reference in timelock config bookkeeping.
    function replaceConfigPolicyRef(bytes32 oldPolicyId, bytes32 newPolicyId) internal {
        if (oldPolicyId == newPolicyId) {
            return;
        }
        TimelockConfigStorage.Layout storage cfg = TimelockConfigStorage.state();
        if (oldPolicyId != bytes32(0)) {
            cfg.policyRefCount[oldPolicyId] -= 1;
        }
        if (newPolicyId != bytes32(0)) {
            cfg.policyRefCount[newPolicyId] += 1;
        }
    }

    /// @notice Removes one policy reference from timelock config bookkeeping.
    function removeConfigPolicyRef(bytes32 policyId) internal {
        if (policyId == bytes32(0)) {
            return;
        }
        TimelockConfigStorage.state().policyRefCount[policyId] -= 1;
    }

    /// @notice Return the number of pending actions using `policyId`, excluding
    ///         the action currently replaying through the timelock context.
    function pendingPolicyRefCount(bytes32 policyId) internal view returns (uint256 count) {
        if (policyId == bytes32(0)) return 0;
        TimelockStorage.Layout storage store = TimelockStorage.state();
        count = store.pendingActionsByPolicy[policyId].length()
            + PendingActionList.count(store.compactPendingPolicies[policyId]);
        if (count != 0 && ExecutionContextLib.isActive()) {
            bytes32 currentActionId = ExecutionContextLib.currentActionId();
            if (
                store.pendingActionsByPolicy[policyId].contains(currentActionId)
                    || PendingActionList.contains(store.compactPendingPolicies[policyId], currentActionId)
            ) {
                --count;
            }
        }
    }

    /// @notice Return one pending action using `policyId`, excluding the action
    ///         currently replaying through the timelock context.
    function pendingActionByPolicy(bytes32 policyId) internal view returns (bytes32 actionId) {
        if (policyId == bytes32(0)) return bytes32(0);
        TimelockStorage.Layout storage store = TimelockStorage.state();
        EnumerableSet.Bytes32Set storage actions = store.pendingActionsByPolicy[policyId];
        bytes32 currentActionId = ExecutionContextLib.isActive() ? ExecutionContextLib.currentActionId() : bytes32(0);
        for (uint256 i; i < actions.length(); ++i) {
            actionId = actions.at(i);
            if (actionId != currentActionId) return actionId;
        }
        return PendingActionList.firstExcept(store.compactPendingPolicies[policyId], currentActionId);
    }

    /// @notice Return the generation used to bind queued actions to active runtime semantics.
    /// @dev Derive the initial generation from zero storage without a redundant initialization write.
    function actionSemanticsGeneration() internal view returns (uint64 generation) {
        generation = TimelockStorage.state().actionSemanticsGeneration;
        if (generation == 0) return 1;
    }

    /// @notice Invalidate every queued action authorized under earlier runtime semantics.
    /// @dev Invoke only after transition postconditions pass. The action performing
    ///      the transition may finish, while sibling actions become stale immediately.
    function bumpActionSemanticsGeneration() internal returns (uint64 nextGeneration) {
        TimelockStorage.Layout storage store = TimelockStorage.state();
        uint64 previousGeneration = actionSemanticsGeneration();
        nextGeneration = previousGeneration + 1;
        store.actionSemanticsGeneration = nextGeneration;
        // Action/index helpers mutate local storage and emit together; execution callbacks finish before these
        // final-state writes.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ActionSemanticsGenerationAdvanced(previousGeneration, nextGeneration);
    }

    /// @notice Return whether an action was queued under current runtime semantics.
    function isActionSemanticsCurrent(bytes32 actionId) internal view returns (bool) {
        TimelockStorage.Action storage a = _sharedAction(actionId);
        return a.status != TimelockActionStatus.None && a.semanticsGeneration == actionSemanticsGeneration();
    }

    /// @notice Revert unless an action was authorized under current runtime semantics.
    function requireActionSemanticsCurrent(bytes32 actionId) internal view {
        TimelockStorage.Action storage a = _sharedAction(actionId);
        uint64 currentGeneration = actionSemanticsGeneration();
        if (a.semanticsGeneration != currentGeneration) {
            // Action status, semantics, and single execution context are per-action invariants and must fail
            // closed.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert TimelockActionSemanticsStale(actionId, a.semanticsGeneration, currentGeneration);
        }
    }

    /// @notice Resolves the effective delay / grace / policy by applying category defaults + scope overrides.
    /// @dev Protocol categories have code-defined bootstrap defaults. Any unknown
    ///      category fails closed until governance intentionally configures it.
    function _resolveConfig(TimelockRequest memory req, uint64 requiredMinimum)
        private
        view
        returns (TimelockResolvedConfig memory resolved)
    {
        TimelockConfigStorage.Layout storage cfg = TimelockConfigStorage.state();
        TimelockConfigStorage.CategoryConfig memory cat = categoryConfig(req.category);
        if (!cat.exists) {
            // Every bundled request must have explicit or protocol-defined governance; none may be skipped.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert TimelockCategoryNotConfigured(req.category);
        }

        uint64 delay = req.delay != 0 ? req.delay : cat.defaultDelay;
        bytes32 policyId = req.policyId != bytes32(0) ? req.policyId : cat.defaultPolicyId;
        uint64 grace = req.gracePeriod != 0 ? req.gracePeriod : cat.gracePeriod;

        TimelockConfigStorage.ScopeOverride storage ov = cfg.overrides[req.category][req.scope];
        if (ov.delaySet) {
            delay = ov.delay;
        }
        if (ov.policySet) {
            policyId = ov.policyId;
        }
        if (ov.graceSet) {
            grace = ov.gracePeriod;
        }

        if (grace == 0) {
            grace = DEFAULT_GRACE_PERIOD;
        }

        // Preserve the resolved tenant delay before applying the protocol floor.
        // The resulting delay must still satisfy the category's bounds.
        if (delay < requiredMinimum) delay = requiredMinimum;
        if (delay < cat.minDelay || delay > cat.maxDelay) {
            // Resolve each requirement within its own bounds before combining; invalid requirements reject all.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert TimelockDelayOutOfBounds(delay, cat.minDelay, cat.maxDelay);
        }

        resolved.delay = delay;
        resolved.gracePeriod = grace;
        resolved.policyId = policyId;
    }

    /// @notice Applies timelock enforcement for a call, queueing it when a delay or policy is required.
    /// @dev Unknown categories fail closed. Immediate execution does not enter
    ///      `ExecutionContextLib`; callers that require context must wrap their
    ///      immediate execution path themselves.
    /// @param req Timelock metadata describing the category/scope/delay overrides.
    /// @param callDataBlob Encoded calldata that will be dispatched once the action executes.
    /// @return executing True when the call may execute immediately.
    /// @return queuedActionId The action id assigned when the call is queued (zero when executing immediately).
    function enforceOrQueue(TimelockRequest memory req, bytes memory callDataBlob)
        internal
        returns (bool executing, bytes32 queuedActionId)
    {
        return _enforceOrQueue(req, callDataBlob, 0);
    }

    /// @notice Enforce a protocol-level minimum that category overrides cannot weaken.
    /// @dev Used for constitutional changes whose delay is part of the contract's
    ///      security model. Longer tenant delays are preserved.
    function enforceOrQueueWithMinimum(TimelockRequest memory req, bytes memory callDataBlob, uint64 requiredMinimum)
        internal
        returns (bool executing, bytes32 queuedActionId)
    {
        return _enforceOrQueue(req, callDataBlob, requiredMinimum);
    }

    function _enforceOrQueue(TimelockRequest memory req, bytes memory callDataBlob, uint64 requiredMinimum)
        private
        returns (bool executing, bytes32 queuedActionId)
    {
        if (ExecutionContextLib.isActive()) {
            if (ExecutionContextLib.currentCategory() != req.category) {
                revert TimelockCategoryMismatch(ExecutionContextLib.currentCategory(), req.category);
            }
            if (ExecutionContextLib.currentScope() != req.scope) {
                revert TimelockScopeMismatch(ExecutionContextLib.currentScope(), req.scope);
            }
            uint64 queuedDelay = TimelockStorage.state().actions[ExecutionContextLib.currentActionId()].delay;
            if (queuedDelay < requiredMinimum) {
                revert TimelockDelayBelowRequiredMinimum(queuedDelay, requiredMinimum);
            }
            return (true, ExecutionContextLib.currentActionId());
        }

        TimelockResolvedConfig memory resolved = _resolveConfig(req, requiredMinimum);
        if (resolved.delay == 0 && resolved.policyId == bytes32(0)) {
            // Every immediate Registry mutation advances the transaction-local
            // guard before control returns to the calling facet. A failed or
            // no-op mutation rolls this write back with the surrounding call.
            ExecutionCatalogStorage.bumpSemantics();
            return (true, bytes32(0));
        }
        return (false, _queue(req, resolved, callDataBlob, false));
    }

    /// @notice Require every affected category/scope, preserving independent approval policies and programs.
    /// @dev Each request is resolved against its own bounds and overrides before combining the longest delay
    ///      and shortest grace window. The first record supplies the sole replay context and payload dispatch.
    ///      The commitment binds the affected authorities; changing them while queued requires renewed review.
    function enforceOrQueueBundle(
        TimelockRequest[] memory requests,
        bytes memory callDataBlob,
        bytes32 commitment,
        bool blockGuardianCancellation
    ) internal returns (bool executing, bytes32 rootActionId) {
        TimelockStorage.Layout storage store = TimelockStorage.state();
        if (ExecutionContextLib.isActive()) {
            (executing, rootActionId) = enforceOrQueue(requests[0], callDataBlob);
            if (store.governanceCommitment[rootActionId] != commitment) {
                revert TimelockGovernanceChanged(rootActionId);
            }
            return (executing, rootActionId);
        }

        TimelockResolvedConfig[] memory resolved = new TimelockResolvedConfig[](requests.length);
        uint64 delay = 0;
        uint64 grace = type(uint64).max;
        bool needsQueue = false;
        uint256 actionCount = 1;
        for (uint256 i; i < requests.length; ++i) {
            resolved[i] = _resolveConfig(requests[i], 0);
            if (resolved[i].delay > delay) delay = resolved[i].delay;
            if (resolved[i].gracePeriod < grace) grace = resolved[i].gracePeriod;
            if (resolved[i].delay != 0 || resolved[i].policyId != bytes32(0)) needsQueue = true;
            if (i != 0 && resolved[i].policyId != bytes32(0)) ++actionCount;
        }
        if (!needsQueue) {
            ExecutionCatalogStorage.bumpSemantics();
            return (true, bytes32(0));
        }

        resolved[0].delay = delay;
        resolved[0].gracePeriod = grace;
        rootActionId = _queue(requests[0], resolved[0], callDataBlob, true);
        bytes memory reviews = new bytes((actionCount - 1) * REVIEW_BYTES);
        uint8[] memory positions = new uint8[](requests.length);
        uint256 reviewIndex = 0;
        for (uint256 i; i < requests.length; ++i) {
            // Every scope still contributes its bounds, delay, grace, and replay commitment.
            // Only a nonzero policy needs independent approval state and a policy-program context.
            if (i != 0 && resolved[i].policyId == bytes32(0)) {
                // Resolution and queueing use local storage and STATICCALL-only authority checks.
                // forge-lint: disable-next-line(reentrancy-events)
                emit ActionRequirement(rootActionId, requests[i].category, requests[i].scope);
                continue;
            }
            bytes32 actionId = rootActionId;
            bytes32 policyId = resolved[i].policyId;
            if (policyId != bytes32(0)) {
                positions[i] = _registerBundlePolicy(store, rootActionId, resolved, positions, i);
            }
            if (i != 0) {
                _writeReview(reviews, reviewIndex, requests[i].category, requests[i].scope, policyId, positions[i]);
                actionId = bytes32(uint256(rootActionId) | ++reviewIndex);
                TimelockStorage.Action storage root = store.actions[rootActionId];
                // Queue construction only queries authority with STATICCALL and updates local storage.
                // forge-lint: disable-start(reentrancy-events)
                emit ActionQueued(
                    actionId,
                    requests[i].category,
                    requests[i].scope,
                    root.actor,
                    root.eta,
                    root.expiresAt,
                    root.payloadHash,
                    policyId
                );
                // forge-lint: disable-end(reentrancy-events)
            }
            // Resolution and queueing touch local storage; any preceding authority call is STATICCALL-only.
            // forge-lint: disable-next-line(reentrancy-events)
            emit ActionBundled(rootActionId, actionId);
        }
        // Address one is a sentinel for a compact bundle with no independent policy reviews.
        store.compactBundleData[rootActionId] = TimelockStorage.CompactBundle({
            data: reviews.length == 0 ? address(1) : address(new GovernanceData(reviews)),
            policyPosition: positions[0],
            ready: 0
        });
        store.governanceCommitment[rootActionId] = commitment;
        store.guardianCancellationBlocked[rootActionId] = blockGuardianCancellation;
    }

    function _registerBundlePolicy(
        TimelockStorage.Layout storage store,
        bytes32 root,
        TimelockResolvedConfig[] memory resolved,
        uint8[] memory positions,
        uint256 index
    ) private returns (uint8) {
        bytes32 policyId = resolved[index].policyId;
        for (uint256 i; i < index; ++i) {
            if (resolved[i].policyId == policyId) return positions[i];
        }
        return PendingActionList.add(store.compactPendingPolicies[policyId], root);
    }

    /// @notice Return the one action whose payload is dispatched for this governance bundle.
    function bundleRoot(bytes32 actionId) internal view returns (bytes32) {
        bytes32 compactRoot = bytes32(uint256(actionId) & ~REVIEW_MASK);
        address pointer = TimelockStorage.state().compactBundleData[compactRoot].data;
        if (pointer != address(0) && (uint256(actionId) & REVIEW_MASK) <= _reviewCount(pointer)) return compactRoot;
        return actionId;
    }

    /// @notice Return every independently reviewed record, or just the unbundled action.
    function bundleActions(bytes32 actionId) internal view returns (bytes32[] memory ids) {
        bytes32 root = bundleRoot(actionId);
        address pointer = TimelockStorage.state().compactBundleData[root].data;
        if (pointer != address(0)) {
            ids = new bytes32[](_reviewCount(pointer) + 1);
            for (uint256 i; i < ids.length; ++i) {
                ids[i] = bytes32(uint256(root) | i);
            }
            return ids;
        }
        ids = new bytes32[](1);
        ids[0] = root;
    }

    function _queue(
        TimelockRequest memory req,
        TimelockResolvedConfig memory resolved,
        bytes memory callDataBlob,
        bool compactBundle
    ) private returns (bytes32 queuedActionId) {
        TimelockStorage.Layout storage store = TimelockStorage.state();
        address actor = ExecutionContextLib.actorOrSender();

        bytes32 payloadHash;
        assembly ("memory-safe") {
            payloadHash := keccak256(add(callDataBlob, 0x20), mload(callDataBlob))
        }
        uint128 nonce = store.nonce;
        store.nonce = nonce + 1;

        bytes32 category = req.category;
        bytes32 scopeValue = req.scope;
        uint256 nonceWord = uint256(nonce);
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, actor)
            mstore(add(ptr, 0x20), category)
            mstore(add(ptr, 0x40), scopeValue)
            mstore(add(ptr, 0x60), payloadHash)
            mstore(add(ptr, 0x80), nonceWord)
            queuedActionId := keccak256(ptr, 0xa0)
            mstore(0x40, add(ptr, 0xa0))
        }
        if (compactBundle) queuedActionId = bytes32(uint256(queuedActionId) & ~REVIEW_MASK);
        TimelockStorage.Action storage a = store.actions[queuedActionId];
        if (a.status != TimelockActionStatus.None) {
            // Action ids bind actor, payload, scope, and monotonic nonce; overwriting any record is forbidden.
            revert("Timelock:action-exists");
        }

        uint64 scheduledAt = SafeCast.toUint64(block.timestamp);
        uint64 eta = _saturatingAdd(scheduledAt, resolved.delay);
        uint64 expiresAt = resolved.gracePeriod == 0 ? type(uint64).max : _saturatingAdd(eta, resolved.gracePeriod);

        a.id = queuedActionId;
        a.category = req.category;
        a.scope = req.scope;
        a.actor = actor;
        a.payloadHash = payloadHash;
        a.policyId = resolved.policyId;
        a.scheduledAt = scheduledAt;
        a.delay = resolved.delay;
        a.eta = eta;
        a.expiresAt = expiresAt;
        a.status = TimelockActionStatus.Queued;
        a.semanticsGeneration = actionSemanticsGeneration();

        TimelockPayloadStorage.store(queuedActionId, callDataBlob);
        store.pending.insert(queuedActionId);
        if (!compactBundle && resolved.policyId != bytes32(0)) {
            bool added = store.pendingActionsByPolicy[resolved.policyId].add(queuedActionId);
            assert(added);
        }

        // Action/index helpers mutate local storage and emit together; execution callbacks finish before these
        // final-state writes.
        // forge-lint: disable-start(reentrancy-events)
        emit ActionQueued(
            queuedActionId, req.category, req.scope, actor, eta, expiresAt, payloadHash, resolved.policyId
        );
        // forge-lint: disable-end(reentrancy-events)
    }

    /// @dev Timelock timestamps use uint64 storage. Saturation preserves a
    ///      configured long delay instead of making an otherwise valid queue revert.
    function _saturatingAdd(uint64 left, uint64 right) private pure returns (uint64) {
        unchecked {
            uint64 sum = left + right;
            return sum < left ? type(uint64).max : sum;
        }
    }

    function _reviewCount(address pointer) private view returns (uint256) {
        return pointer == address(1) ? 0 : (pointer.code.length - 1) / REVIEW_BYTES;
    }

    function _writeReview(
        bytes memory data,
        uint256 index,
        bytes32 category,
        bytes32 scope,
        bytes32 policyId,
        uint8 position
    ) private pure {
        uint256 kind = category == CATEGORY_GROUP ? 0 : category == CATEGORY_CAPABILITY ? 1 : 2;
        assert(category == CATEGORY_GROUP || category == CATEGORY_CAPABILITY || category == CATEGORY_POLICY);
        uint256 offset = index * REVIEW_BYTES;
        assembly ("memory-safe") {
            let ptr := add(add(data, 32), offset)
            mstore8(ptr, kind)
            mstore(add(ptr, 1), scope)
            mstore(add(ptr, 33), policyId)
            mstore8(add(ptr, 65), position)
        }
    }

    function _reviewPolicyPosition(address pointer, uint256 index)
        private
        view
        returns (bytes32 policyId, uint8 position)
    {
        uint256 offset = 1 + index * REVIEW_BYTES + 33;
        assembly ("memory-safe") {
            extcodecopy(pointer, 0, offset, 33)
            policyId := mload(0)
            position := byte(0, mload(32))
        }
    }

    /// @dev Shared lifecycle metadata needs no allocation or decoding of a review's scope.
    function _sharedAction(bytes32 actionId) private view returns (TimelockStorage.Action storage) {
        return TimelockStorage.state().actions[bundleRoot(actionId)];
    }

    /// @dev Child reviews share the root's dependency registration, including membership snapshots.
    function actionMembershipsCurrent(bytes32 actionId) internal view returns (bool) {
        return GroupsStorage.pendingMembershipsCurrent(GroupsStorage.getLayout(), _sharedAction(actionId).id);
    }

    function requireActionMembershipsCurrent(bytes32 actionId) internal view {
        GroupsStorage.requirePendingMemberships(GroupsStorage.getLayout(), _sharedAction(actionId).id);
    }

    /// @notice Read a standalone/root action or reconstruct an independent review from its shared root.
    function action(bytes32 actionId) internal view returns (TimelockStorage.Action memory a) {
        TimelockStorage.Layout storage store = TimelockStorage.state();
        bytes32 rootId = bundleRoot(actionId);
        if (rootId == actionId) return store.actions[actionId];
        address pointer = store.compactBundleData[rootId].data;
        a = store.actions[rootId];
        a.id = actionId;
        uint256 offset = 1 + ((uint256(actionId) & REVIEW_MASK) - 1) * REVIEW_BYTES;
        bytes memory data = new bytes(REVIEW_BYTES);
        uint256 kind;
        bytes32 scope;
        bytes32 policyId;
        assembly ("memory-safe") {
            let ptr := add(data, 32)
            extcodecopy(pointer, ptr, offset, 65)
            kind := byte(0, mload(ptr))
            scope := mload(add(ptr, 1))
            policyId := mload(add(ptr, 33))
        }
        a.category = kind == 0 ? CATEGORY_GROUP : kind == 1 ? CATEGORY_CAPABILITY : CATEGORY_POLICY;
        a.scope = scope;
        a.policyId = policyId;
        if (a.status == TimelockActionStatus.Queued || a.status == TimelockActionStatus.Ready) {
            uint256 bit = 1 << (uint256(actionId) & REVIEW_MASK);
            a.status = store.compactBundleData[rootId].ready & bit == 0
                ? TimelockActionStatus.Queued
                : TimelockActionStatus.Ready;
        }
    }

    /// @notice Marks a queued action as ready for execution after approvals/delay satisfied.
    function markReady(bytes32 actionId) internal {
        requireActionSemanticsCurrent(actionId);
        TimelockStorage.Action memory a = action(actionId);
        if (a.status != TimelockActionStatus.Queued && a.status != TimelockActionStatus.Ready) {
            // Action status, semantics, and single execution context are per-action invariants and must fail
            // closed.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert TimelockWrongStatus(actionId, TimelockActionStatus.Queued, a.status);
        }
        bytes32 root = bundleRoot(actionId);
        if (root != actionId) {
            TimelockStorage.state().compactBundleData[root].ready |= 1 << (uint256(actionId) & REVIEW_MASK);
        } else {
            TimelockStorage.state().actions[actionId].status = TimelockActionStatus.Ready;
        }
        // Action/index helpers mutate local storage and emit together; execution callbacks finish before these
        // final-state writes.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ActionReady(actionId);
    }

    /// @notice Lock every record returned by bundleActions through the root's shared status.
    function markBundleExecuting(bytes32[] memory ids) internal {
        TimelockStorage.state().actions[ids[0]].status = TimelockActionStatus.Executing;
    }

    /// @notice Cancels an action and removes pending indexes/payloads.
    /// @dev Authorization is performed by the calling facet. Payload bytes are retained only when indexing is enabled.
    function markCancelled(bytes32 actionId, address operator) internal {
        bytes32[] memory ids = bundleActions(actionId);
        _markCancelled(ids[0], operator);
        for (uint256 i = 1; i < ids.length; ++i) {
            // Root cleanup updates only local storage and reads immutable data, with no callbacks.
            // forge-lint: disable-next-line(reentrancy-events)
            emit ActionCancelled(ids[i], operator);
        }
    }

    function _markCancelled(bytes32 actionId, address operator) private {
        TimelockStorage.Layout storage store = TimelockStorage.state();
        TimelockStorage.Action storage a = store.actions[actionId];
        TimelockActionStatus status = a.status;
        if (
            status != TimelockActionStatus.Queued && status != TimelockActionStatus.Ready
                && status != TimelockActionStatus.Executing
        ) {
            revert TimelockWrongStatus(actionId, TimelockActionStatus.Queued, status);
        }
        a.status = TimelockActionStatus.Cancelled;
        store.pending.removeValue(actionId);
        _clearPendingReferences(store, a, actionId);
        if (!IndexingStorage.state().enabled) {
            TimelockPayloadStorage.clear(actionId);
        }
        // Action/index helpers mutate local storage and emit together; execution callbacks finish before these
        // final-state writes.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ActionCancelled(actionId, operator);
    }

    /// @notice Marks an action as expired once its grace period elapses.
    function markExpired(bytes32 actionId) internal {
        bytes32[] memory ids = bundleActions(actionId);
        _markExpired(ids[0]);
        for (uint256 i = 1; i < ids.length; ++i) {
            // Root cleanup updates only local storage and reads immutable data, with no callbacks.
            // forge-lint: disable-next-line(reentrancy-events)
            emit ActionExpired(ids[i]);
        }
    }

    function _markExpired(bytes32 actionId) private {
        TimelockStorage.Layout storage store = TimelockStorage.state();
        TimelockStorage.Action storage a = store.actions[actionId];
        TimelockActionStatus status = a.status;
        if (status != TimelockActionStatus.Queued && status != TimelockActionStatus.Ready) {
            // Action status, semantics, and single execution context are per-action invariants and must fail
            // closed.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert TimelockWrongStatus(actionId, TimelockActionStatus.Queued, status);
        }
        a.status = TimelockActionStatus.Expired;
        store.pending.removeValue(actionId);
        _clearPendingReferences(store, a, actionId);
        if (!IndexingStorage.state().enabled) {
            TimelockPayloadStorage.clear(actionId);
        }
        // Action/index helpers mutate local storage and emit together; execution callbacks finish before these
        // final-state writes.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ActionExpired(actionId);
    }

    /// @notice Finalize the records returned by bundleActions, indexing the shared root once.
    function markBundleExecuted(bytes32[] memory ids, address executor) internal {
        TimelockStorage.Layout storage store = TimelockStorage.state();
        _markExecuted(store, ids[0], executor);
        for (uint256 i = 1; i < ids.length; ++i) {
            // Root cleanup touches only local storage and immutable data, with no callbacks.
            // forge-lint: disable-next-line(reentrancy-events)
            emit ActionExecuted(ids[i], executor);
        }
    }

    function _markExecuted(TimelockStorage.Layout storage store, bytes32 actionId, address executor) private {
        TimelockStorage.Action storage a = store.actions[actionId];
        a.status = TimelockActionStatus.Executed;
        store.pending.removeValue(actionId);
        _clearPendingReferences(store, a, actionId);
        store.executed.insert(actionId);
        if (!IndexingStorage.state().enabled) {
            TimelockPayloadStorage.clear(actionId);
        }
        // Action/index helpers mutate local storage and emit together; execution callbacks finish before these
        // final-state writes.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ActionExecuted(actionId, executor);
    }

    function _clearPendingReferences(
        TimelockStorage.Layout storage store,
        TimelockStorage.Action storage action_,
        bytes32 actionId
    ) private {
        TimelockStorage.CompactBundle storage bundle = store.compactBundleData[actionId];
        address pointer = bundle.data;
        if (pointer != address(0)) {
            if (action_.policyId != bytes32(0)) {
                PendingActionList.remove(
                    store.compactPendingPolicies[action_.policyId], bundle.policyPosition, actionId
                );
            }
            uint256 count = _reviewCount(pointer);
            for (uint256 i; i < count; ++i) {
                (bytes32 policyId, uint8 position) = _reviewPolicyPosition(pointer, i);
                // Multiple independently approved scopes can use the same policy. Its one
                // root reference is removed once, while every scope retains its own approvals.
                PendingActionList.remove(store.compactPendingPolicies[policyId], position, actionId);
            }
        } else if (action_.policyId != bytes32(0)) {
            bool removed = store.pendingActionsByPolicy[action_.policyId].remove(actionId);
            assert(removed);
        }
        GroupsStorage.clearPendingAction(GroupsStorage.getLayout(), actionId);
        if (action_.category == CATEGORY_DIAMOND) {
            delete DiamondCutStorage.getLayout().queuedCodeCommitment[actionId];
        }
    }

    /// @notice Records a policy approval for an action and optionally auto-readies it.
    /// @return thresholdsMet True when all policy thresholds are satisfied after this approval.
    function performApproval(bytes32 actionId, address approver) internal returns (bool thresholdsMet) {
        requireActionSemanticsCurrent(actionId);
        requireActionMembershipsCurrent(actionId);
        TimelockStorage.Action memory a = action(actionId);
        if (a.policyId == bytes32(0)) {
            revert("Timelock:policy-none");
        }
        if (
            a.status != TimelockActionStatus.Queued
                && (a.status != TimelockActionStatus.Ready || approvalsMeetCurrentPolicy(actionId, a.policyId))
        ) {
            revert TimelockWrongStatus(actionId, TimelockActionStatus.Queued, a.status);
        }

        PoliciesStorage.Layout storage pl = PoliciesStorage.getLayout();
        Policy storage policy = pl.policies[a.policyId];
        if (policy.id == bytes32(0)) {
            revert TimelockPolicyMissing(a.policyId);
        }

        GroupsStorage.Layout storage gl = GroupsStorage.getLayout();
        bool eligible = false;
        bool recorded = false;
        for (uint256 i = 0; i < policy.criteria.length; ++i) {
            GroupCriteria storage crit = policy.criteria[i];
            if (GroupsStorage.exists(gl, crit.groupHash) && GroupsStorage.isMember(gl, crit.groupHash, approver)) {
                eligible = true;
                // Once a group meets its current threshold, additional members
                // cannot inflate its enumerable approval set while another
                // policy group remains pending. Replacement approvals remain
                // possible after membership or threshold changes make it stale.
                uint256 liveCount = TimelockApprovalsStorage.compactGroupApprovers(actionId, crit.groupHash);
                if (liveCount < crit.threshold) {
                    (bool added, uint256 newCount) =
                        TimelockApprovalsStorage.addGroupApprover(actionId, crit.groupHash, approver);
                    if (added) {
                        recorded = true;
                        // Action/index helpers mutate local storage and emit together; execution callbacks finish
                        // before these final-state writes.
                        // forge-lint: disable-next-line(reentrancy-events)
                        emit ActionApproved(actionId, approver, crit.groupHash, newCount);
                    }
                }
            }
        }
        if (!eligible) {
            revert TimelockNotEligible(actionId, approver);
        }
        // An actor may approve again only when a live policy update makes them
        // eligible for a group that did not record their earlier approval.
        if (!recorded) revert TimelockAlreadyApproved(actionId, approver);

        thresholdsMet = approvalsMeetCurrentPolicy(actionId, a.policyId);

        if (thresholdsMet && a.status == TimelockActionStatus.Queued) {
            markReady(actionId);
        }
    }

    /// @notice Return live approval progress and the supplied approver's exact contribution outcome.
    /// @dev Policy criteria, group membership, and runtime semantics are read live, matching approval and execution.
    function actionApprovalState(bytes32 actionId, address approver)
        internal
        view
        returns (TimelockActionApprovalState memory out)
    {
        TimelockStorage.Action memory a = action(actionId);
        out.policyId = a.policyId;
        out.status = a.status;
        if (a.policyId == bytes32(0)) {
            out.approvalsSatisfied = true;
            return out;
        }

        Policy storage policy = PoliciesStorage.getLayout().policies[a.policyId];
        if (policy.id == bytes32(0)) return out;

        out.policyExists = true;
        out.approvalsSatisfied = true;
        bool approverCanContribute = false;
        bool approverWouldSatisfy = true;
        uint256 criteriaLength = policy.criteria.length;
        out.groups = new TimelockApprovalGroupState[](criteriaLength);
        GroupsStorage.Layout storage groups = GroupsStorage.getLayout();

        for (uint256 i; i < criteriaLength; ++i) {
            GroupCriteria storage crit = policy.criteria[i];
            TimelockApprovalGroupState memory groupState = _approvalGroupState(actionId, crit, groups, approver);
            out.groups[i] = groupState;
            if (groupState.satisfied) continue;

            out.approvalsSatisfied = false;
            if (groupState.approverCanContribute) {
                approverCanContribute = true;
            }
            if (!groupState.approverCanContribute || groupState.activeApprovals + 1 < groupState.threshold) {
                approverWouldSatisfy = false;
            }
        }

        bool approvalStatus = a.status == TimelockActionStatus.Queued || a.status == TimelockActionStatus.Ready;
        // Report approval availability using the queued action's chain-time expiry.
        // forge-lint: disable-next-line(block-timestamp)
        out.acceptingApprovals = approvalStatus && isActionSemanticsCurrent(actionId) && block.timestamp <= a.expiresAt
            && !out.approvalsSatisfied && actionMembershipsCurrent(actionId);
        out.canApproverApprove = out.acceptingApprovals && approverCanContribute;
        out.approverWouldSatisfy = out.canApproverApprove && approverWouldSatisfy;
    }

    /// @notice Re-evaluate recorded approvals against current criteria and membership.
    function approvalsMeetCurrentPolicy(bytes32 actionId, bytes32 policyId) internal view returns (bool) {
        if (policyId == bytes32(0)) return true;
        Policy storage policy = PoliciesStorage.getLayout().policies[policyId];
        if (policy.id == bytes32(0)) return false;
        for (uint256 i; i < policy.criteria.length; ++i) {
            GroupCriteria storage crit = policy.criteria[i];
            if (TimelockApprovalsStorage.liveGroupCount(actionId, crit.groupHash, crit.threshold) < crit.threshold) {
                return false;
            }
        }
        return true;
    }

    function _approvalGroupState(
        bytes32 actionId,
        GroupCriteria storage criterion,
        GroupsStorage.Layout storage groups,
        address approver
    ) private view returns (TimelockApprovalGroupState memory out) {
        out.groupHash = criterion.groupHash;
        out.threshold = criterion.threshold;
        out.activeApprovals =
            TimelockApprovalsStorage.liveGroupCount(actionId, criterion.groupHash, criterion.threshold);
        out.satisfied = out.activeApprovals >= criterion.threshold;
        if (approver == address(0)) return out;

        out.approverIsMember = GroupsStorage.exists(groups, criterion.groupHash)
            && GroupsStorage.isMember(groups, criterion.groupHash, approver);
        out.approverHasApproved = TimelockApprovalsStorage.hasGroupApproval(actionId, criterion.groupHash, approver);
        out.approverCanContribute = out.approverIsMember && !out.approverHasApproved && !out.satisfied;
    }

    /// @notice Returns true when the action is ready, delay elapsed, and grace window open.
    function isExecutable(bytes32 actionId) internal view returns (bool) {
        bytes32[] memory ids = bundleActions(actionId);
        for (uint256 i; i < ids.length; ++i) {
            if (!_isExecutable(ids[i])) return false;
        }
        return true;
    }

    function _isExecutable(bytes32 actionId) private view returns (bool) {
        TimelockStorage.Action memory a = action(actionId);
        if (!isActionSemanticsCurrent(actionId)) return false;
        if (!actionMembershipsCurrent(actionId)) return false;
        if (a.status != TimelockActionStatus.Ready && a.status != TimelockActionStatus.Queued) {
            return false;
        }
        // The configured governance delay is intentionally measured in chain time.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp < a.eta) {
            return false;
        }
        // The configured grace window uses chain time; current policy approvals are still required.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > a.expiresAt) {
            return false;
        }
        if (!approvalsMeetCurrentPolicy(actionId, a.policyId)) return false;
        return true;
    }

    /// @notice Returns a page of pending action identifiers for off-chain consumers.
    function pendingIdsPage(uint256 start, uint256 count) internal view returns (bytes32[] memory) {
        return TimelockStorage.state().pending.page(start, count);
    }

    /// @notice Number of actions present in the pending queue.
    function pendingCount() internal view returns (uint256) {
        return TimelockStorage.state().pending.length();
    }

    /// @notice Returns a page of executed action identifiers for off-chain consumers.
    function executedIdsPage(uint256 start, uint256 count) internal view returns (bytes32[] memory) {
        return TimelockStorage.state().executed.page(start, count);
    }

    /// @notice Number of actions that have been executed historically.
    function executedCount() internal view returns (uint256) {
        return TimelockStorage.state().executed.length();
    }

    /// @notice Fetches the calldata payload associated with a queued action.
    function payload(bytes32 actionId) internal view returns (bytes memory) {
        return TimelockPayloadStorage.load(bundleRoot(actionId));
    }
}
