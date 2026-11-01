// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {IAccessRegistry} from "@chainwall/interfaces/IAccessRegistry.sol";

import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {CapabilityIds} from "./registry/Capabilities.sol";

// Security note: `_checkThresholds` intentionally reads current criteria, but it
// revalidates every recorded approver against current group membership. Interact
// separately binds criteria and program metadata into each operation hash, so a
// policy edit invalidates rather than relaxes a pending Interact operation. Any
// future inheritor must provide an equivalent policy-state binding if it stores
// approvals across policy edits.

/**
 * @title AccessControlPolicy
 * @notice Abstract base contract enforcing multi-group approval policies for operations.
 * @dev Policy criteria and group membership are evaluated at approval/execution time.
 *      Execution and cancellation use Registry policy and capabilities.
 *      Changes to policies or group membership can change the approval status of
 *      pending operations.
 *      The standard lifecycle is:
 *      1. Propose an operation by storing a payload hash, deadline, policy id, value, and bound Safe.
 *      2. Collect approvals from registry users who belong to the required groups.
 *      3. Let a derived contract execute once `_checkThresholds` reports success.
 */
abstract contract AccessControlPolicy is ReentrancyGuardUpgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;

    // Events

    /// @notice Emitted when an actor approves an operation.
    event OperationApproved(address indexed approver, uint256 indexed operationId);
    /// @notice Emitted when a derived contract consumes and executes an operation.
    event OperationExecuted(uint256 indexed operationId);
    /// @notice Emitted when a new operation is proposed.
    event OperationProposed(uint256 indexed operationId);
    /// @notice Emitted when a submitter or delegated cancellation operator withdraws an operation.
    event OperationWithdrawn(uint256 indexed operationId, address indexed operator);

    // Structs

    IAccessRegistry internal _registry;

    /// @notice Operation record used by derived contracts such as `Interact`.
    struct Operation {
        bytes32 payloadHash;
        address submitter;
        uint256 deadline;
        bytes32 policyId;
        uint256 nativeValue;
        mapping(bytes32 => EnumerableSet.AddressSet) approvalsByGroup;
        mapping(address => bool) hasApproved;
        address executor;
        address safe;
    }

    /// @notice Storage layout for the operation queue.
    struct Layout {
        uint256 nextOperationId;
        mapping(uint256 => Operation) operations;
    }

    bytes32 internal constant _STORAGE_SLOT = keccak256("okcontract.storage.AccessControlPolicy");

    error AccessControlPolicySafeZero();

    /// @notice Locks the implementation and prepares the upgradeable base.
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes storage shared by AccessControlPolicy inheritors.
    /// @param registry_ Registry contract address providing user/policy lookups.
    function _accessControlPolicyInit(address registry_) internal onlyInitializing {
        _registry = IAccessRegistry(registry_);
    }

    // Modifier to check if user exists or is a guarded safe
    modifier onlyUser() {
        _onlyUser();
        _;
    }

    function _onlyUser() internal view {
        address actor = _policyActor();
        require(_registry.isUser(actor), "AccessControlPolicy: caller is not a user");
    }

    /// @notice Resolve the logical actor for access-control checks.
    /// @dev    Derived contracts can override to support meta-transaction style forwarding.
    function _policyActor() internal view virtual returns (address) {
        return msg.sender;
    }

    /// @notice Creates a new operation with a given payload hash, policy, deadline, and bound Safe.
    /// @param payloadHash Off-chain computed hash for auditing (trusted input).
    /// @param policyId Policy hash defining required group thresholds.
    /// @param deadline UNIX timestamp after which the operation expires.
    /// @param safe Safe address that must execute this operation.
    /// @return operationId Sequential identifier of the created operation.
    function createOperation(bytes32 payloadHash, bytes32 policyId, uint256 deadline, uint256 nativeValue, address safe)
        public
        virtual
        nonReentrant
        onlyUser
        returns (uint256 operationId)
    {
        return _createOperation(payloadHash, policyId, deadline, nativeValue, safe);
    }

    /// @notice Internal helper that stores a new operation without changing the actor model.
    function _createOperation(
        bytes32 payloadHash,
        bytes32 policyId,
        uint256 deadline,
        uint256 nativeValue,
        address safe
    ) internal returns (uint256 operationId) {
        if (safe == address(0)) revert AccessControlPolicySafeZero();
        require(_registry.policyExists(policyId), "AccessControlPolicy: policy does not exist");
        // The authorized submitter chooses an operation expiry measured in chain time.
        // forge-lint: disable-next-line(block-timestamp)
        require(deadline > block.timestamp, "AccessControlPolicy: deadline must be in the future");

        Layout storage store = _storage();
        operationId = ++store.nextOperationId;

        // Inline assignments avoids introducing additional stack variables when viaIR is enabled.
        store.operations[operationId].payloadHash = payloadHash;
        store.operations[operationId].submitter = _policyActor();
        store.operations[operationId].safe = safe;
        store.operations[operationId].deadline = deadline;
        store.operations[operationId].policyId = policyId;
        store.operations[operationId].nativeValue = nativeValue;
        // Operation entrypoints hold nonReentrant through this event; membership and policy lookups are
        // STATICCALLs.
        // forge-lint: disable-next-line(reentrancy-events)
        emit OperationProposed(operationId);
    }

    /// @notice Records the caller's approval and checks if thresholds are met.
    /// @dev Approval status is re-evaluated against current group membership.
    /// @param operationId ID identifying the operation to approve.
    /// @return True if the operation now meets all approval thresholds.
    function approveOperation(uint256 operationId) public virtual nonReentrant onlyUser returns (bool) {
        return _approveOperation(_policyActor(), operationId);
    }

    /// @notice Internal helper for derived contracts that want to approve using the resolved policy actor.
    function _approveOperationInternal(uint256 operationId) internal returns (bool) {
        return _approveOperation(_policyActor(), operationId);
    }

    /// @notice Cancels and deletes an existing operation.
    /// @dev Callable by the operation submitter or an actor holding the Registry's narrow
    ///      `CANCEL_OPERATION` capability. Contract ownership is deliberately not an
    ///      operational authorization path because it bypasses Registry governance.
    /// @param operationId ID identifying the operation to withdraw.
    function withdrawOperation(uint256 operationId) external virtual nonReentrant {
        Layout storage store = _storage();
        require(store.operations[operationId].submitter != address(0), "AccessControlPolicy: operation does not exist");
        Operation storage operation = store.operations[operationId];
        address actor = _policyActor();
        require(
            actor == operation.submitter || _registry.hasCapability(CapabilityIds.CANCEL_OPERATION, actor),
            "AccessControlPolicy: not authorized"
        );
        // Checked, increasing operation IDs are never reused, so residual approval mappings cannot authorize a new operation.
        // forge-lint: disable-next-line(mapping-deletion)
        delete store.operations[operationId];
        // Operation entrypoints hold nonReentrant through this event; membership and policy lookups are
        // STATICCALLs.
        // forge-lint: disable-next-line(reentrancy-events)
        emit OperationWithdrawn(operationId, actor);
    }

    /// @notice Checks whether an existing operation currently meets its approval thresholds.
    /// @dev Evaluated against the current policy criteria and group membership. This view does not check the
    ///      operation deadline; approval and execution enforce expiry separately.
    /// @param operationId ID identifying the operation.
    /// @return True if the operation exists and currently satisfies all approval thresholds.
    function isOperationApproved(uint256 operationId) external view virtual returns (bool) {
        Layout storage store = _storage();
        if (store.operations[operationId].submitter == address(0)) {
            return false;
        }
        return _checkThresholds(store.operations[operationId]);
    }

    /// @notice Checks if an operation has been executed or withdrawn.
    /// @param operationId ID identifying the operation.
    /// @return True if the operation no longer exists.
    function isOperationExecuted(uint256 operationId) public view virtual returns (bool) {
        return _storage().operations[operationId].submitter == address(0);
    }

    /// @notice Gets the number of stored approvals for an operation in a specific group.
    /// @dev Includes historical approvers whose current membership no longer counts.
    /// @param operationId ID identifying the operation.
    /// @param groupHash Hash of the group whose approvals to count.
    /// @return Number of stored approvals collected from the specified group.
    function getOperationApprovalCount(uint256 operationId, bytes32 groupHash) external view virtual returns (uint256) {
        Layout storage store = _storage();
        if (store.operations[operationId].submitter == address(0)) {
            return 0;
        }
        return store.operations[operationId].approvalsByGroup[groupHash].length();
    }

    /// @notice Gets the number of stored approvals that still have current group membership.
    /// @param operationId ID identifying the operation.
    /// @param groupHash Hash of the group whose active approvals to count.
    /// @return Number of approvals currently counting toward the specified group.
    function getOperationActiveApprovalCount(uint256 operationId, bytes32 groupHash)
        external
        view
        virtual
        returns (uint256)
    {
        Layout storage store = _storage();
        if (store.operations[operationId].submitter == address(0)) {
            return 0;
        }
        return _countActiveApprovals(store.operations[operationId].approvalsByGroup[groupHash], groupHash, 0);
    }

    /// @notice Determines if a given user has ever recorded an approval for an operation.
    /// @dev A true result does not prevent the user from approving again to fill another stale group.
    /// @param operationId ID identifying the operation.
    /// @param user Address of the user to check.
    /// @return True if the user has recorded at least one approval for this operation.
    function hasUserApprovedOperation(uint256 operationId, address user) external view virtual returns (bool) {
        require(_registry.isUser(user), "AccessControlPolicy: user does not exist");
        Layout storage store = _storage();
        if (store.operations[operationId].submitter == address(0)) {
            return false;
        }
        return store.operations[operationId].hasApproved[user];
    }

    /// @notice Returns whether a user can currently add an approval to an operation.
    /// @dev Accounts for the deadline, current membership, stale groups, and approvals already
    ///      recorded for the user in each group.
    function canUserApproveOperation(uint256 operationId, address user) external view virtual returns (bool) {
        (bool canApprove,) = _userApprovalOutcome(operationId, user);
        return canApprove;
    }

    /// @notice Returns whether a user's currently recordable approval would satisfy every group.
    function canUserApproveAndSatisfyOperation(uint256 operationId, address user) external view virtual returns (bool) {
        (bool canApprove, bool wouldSatisfy) = _userApprovalOutcome(operationId, user);
        return canApprove && wouldSatisfy;
    }

    /// @notice Return the native value bound to an operation.
    function getOperationNativeValue(uint256 operationId) public view virtual returns (uint256) {
        Operation storage operation = _storage().operations[operationId];
        require(operation.submitter != address(0), "AccessControlPolicy: operation does not exist");
        return operation.nativeValue;
    }

    /// @notice Return the policy currently governing an operation.
    function getOperationPolicyId(uint256 operationId) public view virtual returns (bytes32) {
        Operation storage operation = _storage().operations[operationId];
        require(operation.submitter != address(0), "AccessControlPolicy: operation does not exist");
        return operation.policyId;
    }

    /// @notice Returns the Safe bound to an operation.
    function getOperationSafe(uint256 operationId) public view virtual returns (address) {
        Operation storage operation = _storage().operations[operationId];
        require(operation.submitter != address(0), "AccessControlPolicy: operation does not exist");
        return operation.safe;
    }

    /// @notice Returns the executor bound to an operation, if any.
    /// @dev A zero address means the operation is not executor-bound.
    function getOperationExecutor(uint256 operationId) public view virtual returns (address) {
        Operation storage operation = _storage().operations[operationId];
        require(operation.submitter != address(0), "AccessControlPolicy: operation does not exist");
        return operation.executor;
    }

    /// @notice Checks whether a given user alone can satisfy all thresholds of a policy.
    /// @dev A user can satisfy a policy if, for every group in the policy,
    ///      either the threshold is 0 _or_ the threshold is 1 **and** the user
    ///      belongs to that group. Any threshold greater than 1 makes it
    ///      impossible for a single caller to satisfy.
    /// @param policyId Hash of the policy to evaluate.
    /// @param user     Address of the user to test.
    /// @return True if the user single-handedly meets the policy requirements.
    function canUserSatisfyPolicy(bytes32 policyId, address user) public view virtual returns (bool) {
        return _canUserSatisfyPolicy(policyId, user);
    }

    function _canUserSatisfyPolicy(bytes32 policyId, address user) internal view returns (bool) {
        require(_registry.policyExists(policyId), "AccessControlPolicy: policy does not exist");

        (bytes32[] memory groupHashes, uint256[] memory thresholds) = _registry.getPolicyCriteria(policyId);

        return _meetsPolicyCriteria(user, groupHashes, thresholds);
    }

    /// @dev For criteria already bound during this call's static authorization phase.
    function _canUserSatisfyPolicy(
        bytes32 policyId,
        address user,
        bytes32[] memory groupHashes,
        uint256[] memory thresholds
    ) internal view returns (bool) {
        require(_registry.policyExists(policyId), "AccessControlPolicy: policy does not exist");
        return _meetsPolicyCriteria(user, groupHashes, thresholds);
    }

    function _meetsPolicyCriteria(address user, bytes32[] memory groupHashes, uint256[] memory thresholds)
        private
        view
        returns (bool)
    {
        for (uint256 i = 0; i < groupHashes.length; i++) {
            uint256 threshold = thresholds[i];

            // If more than one approval is needed from this group,
            // a single caller can never satisfy it.
            if (threshold > 1) {
                return false;
            }

            // If exactly one approval is needed, the caller must belong to the group.
            if (threshold == 1) {
                // Each approval needs a current Registry membership STATICCALL; no callee can mutate state during
                // these reads.
                // forge-lint: disable-next-line(calls-loop)
                if (!_registry.isGroupMemberByHash(groupHashes[i], user)) {
                    return false;
                }
            }

            // If threshold == 0, the group imposes no requirement.
        }
        return true;
    }

    function _countActiveApprovals(EnumerableSet.AddressSet storage approvals, bytes32 groupHash, uint256 stopAt)
        private
        view
        returns (uint256 count)
    {
        uint256 len = approvals.length();
        for (uint256 i; i < len; ++i) {
            address approver = approvals.at(i);
            // Each approval needs a current Registry membership STATICCALL; no callee can mutate state during these
            // reads.
            // forge-lint: disable-next-line(calls-loop)
            if (_registry.isGroupMemberByHash(groupHash, approver)) {
                unchecked {
                    ++count;
                }
                if (stopAt != 0 && count == stopAt) {
                    break;
                }
            }
        }
    }

    /// @dev A satisfied group must stop accepting approvals while another group
    ///      remains pending. Otherwise any eligible user can grow the enumerable
    ///      set without bound and eventually make threshold checks run out of gas.
    function _groupThresholdMet(EnumerableSet.AddressSet storage approvals, bytes32 groupHash, uint256 threshold)
        private
        view
        returns (bool)
    {
        if (threshold == 0) return true;
        if (approvals.length() < threshold) return false;
        return _countActiveApprovals(approvals, groupHash, threshold) == threshold;
    }

    /// @dev Remove approvals that no longer carry membership before recording a
    ///      replacement. EnumerableSet removal swaps the last entry into the
    ///      current index, so the loop advances only when an entry is retained.
    ///      This keeps each group set bounded by live approvals despite repeated
    ///      membership churn.
    function _compactGroupApprovals(EnumerableSet.AddressSet storage approvals, bytes32 groupHash) private {
        uint256 i = 0;
        while (i < approvals.length()) {
            address approver = approvals.at(i);
            // Each approval needs a current Registry membership STATICCALL; no callee can mutate state during these
            // reads.
            // forge-lint: disable-next-line(calls-loop)
            if (!_registry.isGroupMemberByHash(groupHash, approver)) {
                approvals.remove(approver);
            } else {
                unchecked {
                    ++i;
                }
            }
        }
    }

    /// @dev Internal helper to verify if an operation meets all group approval thresholds.
    ///      Group membership is rechecked for each recorded approver.
    /// @param operation Operation storage pointer.
    function _checkThresholds(Operation storage operation) internal view returns (bool) {
        (bytes32[] memory groupHashes, uint256[] memory thresholds) = _registry.getPolicyCriteria(operation.policyId);
        for (uint256 i = 0; i < groupHashes.length; i++) {
            uint256 threshold = thresholds[i];
            if (threshold == 0) {
                continue;
            }
            EnumerableSet.AddressSet storage approvals = operation.approvalsByGroup[groupHashes[i]];
            if (!_groupThresholdMet(approvals, groupHashes[i], threshold)) {
                return false;
            }
        }
        return true;
    }

    function _userApprovalOutcome(uint256 operationId, address actor)
        private
        view
        returns (bool canApprove, bool wouldSatisfy)
    {
        if (!_registry.isUser(actor)) return (false, false);

        Operation storage operation = _storage().operations[operationId];
        if (operation.submitter == address(0)) return (false, false);
        // Report the same chain-time expiry enforced by approval and execution.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > operation.deadline) return (false, false);
        if (!_registry.policyExists(operation.policyId)) return (false, false);

        (bytes32[] memory groupHashes, uint256[] memory thresholds) = _registry.getPolicyCriteria(operation.policyId);
        bool requiresGroup = false;
        wouldSatisfy = true;

        for (uint256 i = 0; i < groupHashes.length; i++) {
            uint256 threshold = thresholds[i];
            if (threshold == 0) continue;
            requiresGroup = true;

            EnumerableSet.AddressSet storage approvals = operation.approvalsByGroup[groupHashes[i]];
            uint256 activeApprovals = _countActiveApprovals(approvals, groupHashes[i], threshold);
            if (activeApprovals == threshold) continue;

            // Each approval needs a current Registry membership STATICCALL; no callee can mutate state during these
            // reads.
            // forge-lint: disable-next-line(calls-loop)
            bool canFillGroup = _registry.isGroupMemberByHash(groupHashes[i], actor) && !approvals.contains(actor);
            if (!canFillGroup) {
                wouldSatisfy = false;
                continue;
            }

            canApprove = true;
            if (activeApprovals + 1 < threshold) {
                wouldSatisfy = false;
            }
        }

        if (!requiresGroup) {
            canApprove = !operation.hasApproved[actor];
        }
    }

    /// @notice Modifier that allows execution only after operation is approved and before deadline.
    /// @param operationId ID identifying the operation.
    /// @dev After execution, cleans up and emits {OperationExecuted}.
    modifier requiresApproval(uint256 operationId) {
        _requiresApprovalBefore(operationId);
        _;
        _requiresApprovalAfter(operationId);
    }

    function _requiresApprovalBefore(uint256 operationId) internal view {
        Layout storage store = _storage();
        require(store.operations[operationId].submitter != address(0), "AccessControlPolicy: operation does not exist");
        Operation storage operation = store.operations[operationId];
        // Chain time bounds operation validity; live policy thresholds are checked below.
        // forge-lint: disable-next-line(block-timestamp)
        require(block.timestamp <= operation.deadline, "AccessControlPolicy: operation deadline passed");
        require(_checkThresholds(operation), "AccessControlPolicy: operation not approved by required groups");
    }

    function _requiresApprovalAfter(uint256 operationId) internal {
        // Checked, increasing operation IDs are never reused; clearing the live fields retires this operation.
        // forge-lint: disable-next-line(mapping-deletion)
        delete _storage().operations[operationId];
        // Operation entrypoints hold nonReentrant through this event; membership and policy lookups are
        // STATICCALLs.
        // forge-lint: disable-next-line(reentrancy-events)
        emit OperationExecuted(operationId);
    }

    function _approveOperation(address actor, uint256 operationId) internal returns (bool) {
        Layout storage store = _storage();
        require(store.operations[operationId].submitter != address(0), "AccessControlPolicy: operation does not exist");
        Operation storage operation = store.operations[operationId];
        // Chain time bounds approval validity; current group membership is checked below.
        // forge-lint: disable-next-line(block-timestamp)
        require(block.timestamp <= operation.deadline, "AccessControlPolicy: operation deadline passed");
        (bytes32[] memory groupHashes, uint256[] memory thresholds) = _registry.getPolicyCriteria(operation.policyId);
        bool eligible = false;
        bool requiresGroup = false;
        bool recorded = false;
        bool isApproved = true;
        for (uint256 i = 0; i < groupHashes.length; i++) {
            uint256 threshold = thresholds[i];
            if (threshold == 0) continue;
            requiresGroup = true;
            EnumerableSet.AddressSet storage approvals = operation.approvalsByGroup[groupHashes[i]];
            // Each approval needs a current Registry membership STATICCALL; no callee can mutate state during these
            // reads.
            // forge-lint: disable-next-line(calls-loop)
            if (!_registry.isGroupMemberByHash(groupHashes[i], actor)) {
                if (isApproved && !_groupThresholdMet(approvals, groupHashes[i], threshold)) isApproved = false;
                continue;
            }

            eligible = true;
            _compactGroupApprovals(approvals, groupHashes[i]);
            // Every retained approver was just checked, and the actor is a live
            // member. No mutating external call separates compaction and use.
            if (approvals.length() < threshold && approvals.add(actor)) recorded = true;
            if (approvals.length() < threshold) isApproved = false;
        }
        // A previous approver may refill another eligible group after live
        // membership changes make it stale. Repeat calls that add nothing are
        // still duplicates and cannot grow any approval set.
        require(recorded || !operation.hasApproved[actor], "AccessControlPolicy: user already approved");
        if (requiresGroup && !eligible) {
            return false;
        }
        // Do not consume the actor's one approval or grow storage when all of
        // their eligible groups already have enough live approvals.
        if (requiresGroup && !recorded) {
            return false;
        }
        operation.hasApproved[actor] = true;

        if (isApproved) {
            // Operation entrypoints hold nonReentrant through this event; membership and policy lookups are
            // STATICCALLs.
            // forge-lint: disable-next-line(reentrancy-events)
            emit OperationApproved(actor, operationId);
        }
        return isApproved;
    }

    function _storage() internal pure returns (Layout storage l) {
        bytes32 slot = _STORAGE_SLOT;
        assembly ("memory-safe") {
            l.slot := slot
        }
    }
}
