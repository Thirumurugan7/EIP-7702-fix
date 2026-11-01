// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {IMiniScriptExecutionHost} from "@chainwall/interfaces/IMiniScriptExecutionHost.sol";
import {IOKAccount} from "@chainwall/interfaces/IOKAccount.sol";

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

import {AccessControlPolicy} from "./AppEx.sol";
import {InteractErrors} from "./InteractErrors.sol";
import {InteractionFlags} from "./InteractionFlags.sol";
import {IMiniScript} from "./MiniScript.sol";
import {PagedIndex} from "./PagedIndex.sol";
import {IRegistry} from "./registry/RegistryShared.sol";

/// @notice Semantic context used to simulate the same policy-program path as execution.
/// @param interactionId Interaction whose policy is being evaluated.
/// @param interactionArgs Original arguments supplied to the interaction.
/// @param nativeValue Native value authorized for the interaction.
/// @param operationId Stored operation identifier, or zero for direct execution.
/// @param payloadHash Stable policy-visible payload hash.
/// @param actor Authenticated policy actor.
/// @param vault Safe or account vault on whose behalf execution would occur.
struct PolicySimulationInput {
    bytes32 interactionId;
    uint256[] interactionArgs;
    uint256 nativeValue;
    uint256 operationId;
    bytes32 payloadHash;
    address actor;
    address vault;
}

/// @title InteractStorage
/// @notice Shared storage, events, constants, and hashing helpers for the split Interact implementation.
/// @dev Interact and its delegatecall modules inherit this contract so they share the
///      same storage slots, events, and authorization helpers.
abstract contract InteractStorage is Initializable, ReentrancyGuardUpgradeable, AccessControlPolicy, EIP712Upgradeable {
    using PagedIndex for PagedIndex.Index;

    /// @notice Registry contract holding interaction definitions.
    IRegistry public registry;
    /// @notice MiniScript interpreter contract.
    IMiniScript public miniScript;
    /// @notice Nonce consumed by each directExecute signature per actor to prevent replay.
    mapping(address => uint256) internal _directExecuteNonces;
    /// @notice Whether execution history indexing is enabled for this Interact instance.
    /// @dev When false, execution history must be discovered from logs alone.
    bool public indexingEnabled;
    /// @notice Block number where execution indexing started for this Interact instance.
    /// @dev Zero when indexing was disabled during initialization.
    uint64 public indexingStartBlock;

    /// @notice Indexed execution record stored in the global execution history.
    struct StoredVaultExecutionRecord {
        /// @notice Zero-based global record identifier assigned by the execution index.
        uint256 recordId;
        /// @notice Interaction identifier that was executed.
        bytes32 interactionId;
        /// @notice Safe or account vault that executed the interaction.
        address vault;
        /// @notice Resolved actor that authorized the execution.
        address caller;
        /// @notice Final MiniScript stack top returned by the execution.
        uint256 stackTop;
        /// @notice Block number where the execution was recorded.
        uint64 blockNumber;
    }

    /// @notice Internal execution result used by both Safe-mode and account-mode flows.
    struct ExecutionOutcome {
        /// @notice Final MiniScript stack top returned by the execution.
        uint256 stackTop;
        /// @notice Indexed execution record identifier, or zero when indexing is disabled.
        uint256 recordId;
    }

    /// @notice Shared direct execution context carried between validation and execution.
    struct DirectExecutionContext {
        /// @notice Reserved for the actor that satisfied the policy or signed the direct execution request.
        address actor;
        /// @notice Caller forwarded into MiniScript for auditability and policy programs.
        address caller;
        /// @notice Payload hash bound into policy program execution.
        bytes32 payloadHash;
    }

    uint8 internal constant VAULT_EXECUTION_RECENT_LIMIT = 32;
    PagedIndex.Index internal _vaultExecutionRecordsIndex;
    mapping(uint256 => StoredVaultExecutionRecord) internal _vaultExecutionRecords;
    mapping(address => uint8) internal _vaultExecutionRecentCount;
    mapping(address => uint8) internal _vaultExecutionRecentNext;
    mapping(address => mapping(uint8 => uint256)) internal _vaultExecutionRecentRecordIds;

    /// @notice Emitted after successful vault execution.
    /// @param vault Safe or account vault that executed the interaction.
    /// @param interactionId Interaction identifier that was executed.
    /// @param recordId Zero-based global execution record identifier, or zero when indexing is disabled.
    /// @param caller Resolved actor that authorized the execution.
    /// @param stackTop Final MiniScript stack top returned by the execution.
    event VaultInteractionExecuted(
        address indexed vault, bytes32 indexed interactionId, uint256 indexed recordId, address caller, uint256 stackTop
    );
    /// @notice Emitted when a signed direct execution trailer cannot be validated.
    /// @param actor Actor recovered from the signed payload.
    /// @param forwarder Forwarder bound into the typed data.
    /// @param interactionId Interaction identifier that failed signature validation.
    /// @param policyId Policy identifier bound into the signature.
    /// @param nonce Direct execution nonce that was checked.
    /// @param errorCode MiniScript-friendly signature failure code.
    /// @param errorArg Auxiliary error argument for the signature failure code.
    /// @param recovered Address recovered from the failing signature, when available.
    event DirectExecuteSignatureFailed(
        address indexed actor,
        address indexed forwarder,
        bytes32 indexed interactionId,
        bytes32 policyId,
        uint256 nonce,
        uint8 errorCode,
        bytes32 errorArg,
        address recovered
    );

    bytes32 internal constant DIRECT_EXECUTE_TYPEHASH = keccak256(
        "DirectExecute(address actor,address forwarder,bytes32 policyId,bytes32 interactionId,bytes32 argsHash,bytes32 executionBindingHash,uint256 maxSteps,uint256 nativeValue,uint256 deadline,uint256 chainId,uint256 nonce)"
    );
    bytes32 internal constant DIRECT_EXECUTE_FROM_ACCOUNT_TYPEHASH = keccak256(
        "DirectExecuteFromAccount(address actor,address forwarder,address account,bytes32 policyId,bytes32 interactionId,bytes32 argsHash,bytes32 executionBindingHash,uint256 maxSteps,uint256 nativeValue,uint256 deadline,uint256 chainId,uint256 nonce)"
    );
    bytes32 internal constant EXECUTION_BINDING_TYPEHASH = keccak256(
        "ExecutionBindingV2(bytes32 interactionBindingHash,bytes32 dependencyHash,bytes32 policyBindingHash,uint64 executionRevision)"
    );
    bytes32 internal constant UNPINNED_EXECUTION_BINDING_TYPEHASH = keccak256(
        "UnpinnedExecutionBindingV2(bytes32 interactionId,bytes32 policyBindingHash,uint256 interactionFlags)"
    );
    bytes32 internal constant POLICY_BINDING_TYPEHASH = keccak256(
        "PolicyBindingV2(bytes32 policyId,bytes32 criteriaHash,bytes32 programHash,uint32 programMaxSteps,uint64 programVersion,bytes32 dependencyHash,uint64 executionRevision)"
    );
    bytes32 internal constant EXECUTION_ACTOR_TYPEHASH = keccak256(
        "ExecutionActor(address actor,address forwarder,bytes4 selector,uint256 operationId,uint256 chainId)"
    );
    uint256 internal constant DIRECT_EXECUTE_DEADLINE = 0;
    uint256 internal constant POLICY_PROGRAM_STEP_CAP = 100_000;
    uint256 internal constant POLICY_PROGRAM_BASE_ARGS = 8;

    /// @notice Locks the implementation to force usage through proxies.
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes a tenant Interact proxy with its registry and MiniScript dependencies.
    /// @param registry_ Registry contract for lookups.
    /// @param miniScript_ Tenant MiniScript interpreter.
    /// @param indexingEnabled_ Whether execution history indexing should be enabled for this instance.
    function _initializeInteract(IRegistry registry_, IMiniScript miniScript_, bool indexingEnabled_)
        internal
        onlyInitializing
    {
        require(address(registry_) != address(0), "registry=0x0");
        require(address(miniScript_) != address(0), "miniScript=0x0");
        __ReentrancyGuard_init();
        _accessControlPolicyInit(address(registry_));
        __EIP712_init("Interact", "1");
        registry = registry_;
        miniScript = miniScript_;
        indexingEnabled = indexingEnabled_;
        if (indexingEnabled_) {
            indexingStartBlock = SafeCast.toUint64(block.number);
        }
    }

    /// @notice Guards index-backed read APIs when indexing is disabled.
    modifier whenIndexingEnabled() {
        _whenIndexingEnabled();
        _;
    }

    /// @notice Reverts when indexing-backed state is unavailable for this instance.
    function _whenIndexingEnabled() internal view {
        if (!indexingEnabled) {
            revert InteractErrors.IndexingDisabled();
        }
    }

    /// @notice Returns whether `actor` belongs to any signatory group for `policyId`.
    /// @dev Shared with proposal creation so a signatory proposer can record its approval atomically.
    function _isPolicySignatory(bytes32 policyId, address actor) internal view returns (bool) {
        (bytes32[] memory groupHashes, uint256[] memory thresholds) = _registry.getPolicyCriteria(policyId);
        for (uint256 i; i < groupHashes.length; ++i) {
            // Each criterion needs a current Registry membership STATICCALL; stopping early occurs only after a
            // match.
            // forge-lint: disable-next-line(calls-loop)
            if (thresholds[i] != 0 && _registry.isGroupMemberByHash(groupHashes[i], actor)) {
                return true;
            }
        }
        return false;
    }

    /// @notice Compute the payload hash used in propose/execute flows.
    /// @dev Binds args, exact Registry execution state, deadline, nativeValue,
    ///      policyId, and Safe address in a sender-agnostic way.
    function _hashPayload(
        bytes32 id,
        uint256[] calldata args,
        bytes32 policyId,
        uint256 deadline,
        uint256 nativeValue,
        address safe
    ) internal view returns (bytes32 h) {
        return _hashBoundPayload(id, args, policyId, deadline, nativeValue, safe, _executionBindingHash(id, policyId));
    }

    /// @dev Reuse a binding only within the same uninterrupted read-only phase.
    function _hashBoundPayload(
        bytes32 id,
        uint256[] calldata args,
        bytes32 policyId,
        uint256 deadline,
        uint256 nativeValue,
        address safe,
        bytes32 binding
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(id, args, policyId, deadline, nativeValue, safe, binding));
    }

    /// @dev Stable intent hash exposed to policy programs. It omits the
    ///      execution binding because a program may validate this hash itself;
    ///      including the program hash would create a hash fixed point.
    function _hashPolicyPayload(
        bytes32 id,
        uint256[] calldata args,
        bytes32 policyId,
        uint256 deadline,
        uint256 nativeValue,
        address safe
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(id, args, policyId, deadline, nativeValue, safe));
    }

    /// @notice Compute the payload hash that binds execution to a specific executor.
    /// @dev Use this when only `executor` should be able to execute the stored operation.
    function _hashPayloadWithExecutor(
        bytes32 id,
        uint256[] calldata args,
        bytes32 policyId,
        uint256 deadline,
        uint256 nativeValue,
        address safe,
        address executor
    ) internal view returns (bytes32 h) {
        return _hashBoundPayloadWithExecutor(
            id, args, policyId, deadline, nativeValue, safe, executor, _executionBindingHash(id, policyId)
        );
    }

    function _hashBoundPayloadWithExecutor(
        bytes32 id,
        uint256[] calldata args,
        bytes32 policyId,
        uint256 deadline,
        uint256 nativeValue,
        address safe,
        address executor,
        bytes32 binding
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(id, args, policyId, deadline, nativeValue, safe, executor, binding));
    }

    function _hashPolicyPayloadWithExecutor(
        bytes32 id,
        uint256[] calldata args,
        bytes32 policyId,
        uint256 deadline,
        uint256 nativeValue,
        address safe,
        address executor
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(id, args, policyId, deadline, nativeValue, safe, executor));
    }

    /// @notice Hash the exact executable Registry and policy state authorized by new approvals.
    /// @dev Public scripts bind their reachable CALLI graph and resolved targets
    ///      plus the shared runtime revision. This prevents unrelated catalog
    ///      authors from invalidating every tenant operation. A private commitment
    ///      cannot expose its dependency graph before reveal, so it conservatively
    ///      binds the full catalog revision. `UNPINNED_APPROVALS` opts into following
    ///      live executable state, but never unpins policy criteria or program.
    function _executionBindingHash(bytes32 interactionId, bytes32 policyId) internal view returns (bytes32) {
        (bytes32 binding,,) = _executionBindingHashAndCriteria(interactionId, policyId);
        return binding;
    }

    /// @dev Criteria are returned for a direct signature's subsequent membership
    ///      check. Signature validation is static, so Registry state cannot change
    ///      between binding these criteria and evaluating them.
    function _executionBindingHashAndCriteria(bytes32 interactionId, bytes32 policyId)
        internal
        view
        returns (bytes32 binding, bytes32[] memory groupHashes, uint256[] memory thresholds)
    {
        uint256 flags = registry.getInteractionFlags(interactionId);
        bytes32 policyBindingHash;
        (policyBindingHash, groupHashes, thresholds) = _policyBindingHash(policyId, interactionId);
        if (InteractionFlags.hasUnpinnedApprovals(flags)) {
            return (
                keccak256(abi.encode(UNPINNED_EXECUTION_BINDING_TYPEHASH, interactionId, policyBindingHash, flags)),
                groupHashes,
                thresholds
            );
        }
        bytes32 dependencyHash = miniScript.getExecutionDependencyHash(interactionId);
        uint64 executionRevision = dependencyHash == bytes32(0)
            ? registry.getExecutionCatalogVersion()
            : registry.getExecutionRuntimeVersion();
        binding = keccak256(
            abi.encode(
                EXECUTION_BINDING_TYPEHASH,
                registry.getInteractionBindingHash(interactionId),
                dependencyHash,
                policyBindingHash,
                executionRevision
            )
        );
    }

    /// @dev Criteria, program metadata, linked dependencies, and the selected
    ///      execution revision are all executable policy state.
    /// @param policyId Policy whose executable state is bound.
    /// @param subjectInteractionId Interaction namespace visible to STATICLINK.
    /// @return binding Exact policy approval binding hash.
    /// @return groupHashes Groups included in that binding.
    /// @return thresholds Approval thresholds included in that binding.
    function _policyBindingHash(bytes32 policyId, bytes32 subjectInteractionId)
        private
        view
        returns (bytes32 binding, bytes32[] memory groupHashes, uint256[] memory thresholds)
    {
        (groupHashes, thresholds) = _registry.getPolicyCriteria(policyId);
        (bytes memory program, uint32 maxSteps, bytes32 programHash, uint64 version) =
            _registry.getPolicyProgram(policyId);
        (bytes32 dependencyHash, bool complete) = miniScript.getProgramDependencyHash(program, subjectInteractionId);
        uint64 executionRevision =
            complete ? registry.getExecutionRuntimeVersion() : registry.getExecutionCatalogVersion();
        binding = keccak256(
            abi.encode(
                POLICY_BINDING_TYPEHASH,
                policyId,
                keccak256(abi.encode(groupHashes, thresholds)),
                programHash,
                maxSteps,
                version,
                dependencyHash,
                executionRevision
            )
        );
    }
}
