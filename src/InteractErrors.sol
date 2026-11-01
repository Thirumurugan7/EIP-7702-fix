// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @title InteractErrors
/// @notice Shared custom errors used by the split Interact implementation.
/// @dev The thin `Interact` wrapper re-declares the user-facing errors so selectors remain
///      addressable as `Interact.ErrorName.selector`, while the delegatecall modules use this
///      library to avoid duplicating revert declarations across files.
library InteractErrors {
    /// @notice Thrown when a registry-only entrypoint is called by another account.
    error OnlyRegistry();
    /// @notice Thrown when a call must originate from the Safe execution path.
    error SafeCallerRequired();
    /// @notice Thrown when a requested account vault is not permitted by the registry.
    error AccountNotAllowed();
    /// @notice Thrown when Interact analyzed dependencies under a language runtime incompatible with the account.
    /// @param analysisEngine Engine whose analyzer produced the execution binding.
    /// @param executionEngine Engine the account would use for execution.
    error AccountEngineMismatch(address analysisEngine, address executionEngine);
    /// @notice Thrown when execution indexing reads are requested while indexing is disabled.
    error IndexingDisabled();
    /// @notice Thrown when an interaction is deactivated in the registry.
    /// @param interactionId Interaction identifier rejected by the runtime.
    error InteractionInactive(bytes32 interactionId);
    /// @notice Thrown when private reveal did not make the requested bundle active.
    /// @param interactionId Interaction identifier rejected by the private execution path.
    /// @param expectedBundleHash Hash of the bundle supplied in the reveal payload.
    /// @param activeBundleHash Hash of the bundle currently stored under `interactionId`.
    error PrivateRevealBundleMismatch(bytes32 interactionId, bytes32 expectedBundleHash, bytes32 activeBundleHash);
    /// @notice Thrown when a proposed Safe target does not match a supported Safe or account vault.
    error InvalidSafeTarget();
    /// @notice Thrown when an operation binds execution to the zero executor address.
    error InvalidExecutor();
    /// @notice Thrown when actor authorization requires an explicit signature.
    error SignatureRequired();
    /// @notice Thrown when the provided actor signature cannot be validated.
    error InvalidActorSignature();
    /// @notice Thrown when a direct execution request is submitted after its deadline.
    error DirectExecuteDeadlineExpired();
    /// @notice Thrown when a reusable signed direct execution omits its expiry.
    error DirectExecuteDeadlineRequired();
    /// @notice Thrown when the caller lacks the executor capability required by policy.
    error ExecutorNotAuthorized();
    /// @notice Thrown when an operation is replayed against a different Safe or account vault.
    error OperationSafeMismatch();
    /// @notice Thrown when an operation is replayed by a different bound executor.
    error OperationExecutorMismatch();
    /// @notice Thrown when an operation payload does not match the stored commitment.
    error OperationHashMismatch();
    /// @notice Thrown when an operation is executed with a different native value than committed.
    error OperationNativeMismatch();
    /// @notice Thrown when direct execution sends a different native value than requested.
    error DirectNativeMismatch();
    /// @notice Thrown when the actor cannot satisfy the requested policy alone.
    error PolicyCallerCannotSatisfy();
    /// @notice Thrown until the instance explicitly accepts its initial document digest.
    error TermsNotAccepted(bytes32 documentHash);
    /// @notice Thrown when Registry semantics change after policy evaluation starts.
    /// @dev Reverting the outer execution also rolls back the nested Registry change and all value movement.
    error RegistryExecutionSemanticsChanged(uint64 expectedRevision, uint64 actualRevision);
    /// @notice Revert payload used by policy-program simulation after the program succeeds.
    /// @dev The simulation path always reverts so it cannot persist PolicyState writes in a real transaction.
    /// @param stackTop Final MiniScript stack top returned by the policy program.
    error PolicyProgramSimulationResult(uint256 stackTop);
}
