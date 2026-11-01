// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {InteractErrors} from "./InteractErrors.sol";
import {InteractModuleBase} from "./InteractModuleBase.sol";
import {PolicySimulationInput} from "./InteractStorage.sol";
import {StoredBundleRevealPayload as StoredRevealPayload} from "./RegistryTypes.sol";

/// @title InteractOpsModule
/// @notice Delegatecall implementation for Interact execution entrypoints.
/// @dev `Interact` forwards its public mutating entrypoints to this module to stay below EIP-170 while
///      preserving one proxy address and one storage layout. Direct calls to this module are not part of
///      the supported deployment model.
contract InteractOpsModule is InteractModuleBase {
    error DirectModuleCallUnsupported();

    struct AccountOperationContext {
        address account;
        uint256 nativeValue;
        bytes32 policyId;
    }

    function execute(uint256 operationId, bytes32 id, uint256[] calldata args, uint256 maxSteps)
        external
        payable
        nonReentrant
        onlySafeCaller
        onlyUser
        onlyExecutor
        requiresApproval(operationId)
        returns (uint256 stackTop)
    {
        _requireInteractionActive(id);
        address actor = _authorizedPolicyActor();
        address caller = _executionCaller(actor);
        _requireTermsAccepted();
        (bytes32 policyId, uint64 semanticsRevision) = _authorizeSafeOperation(operationId, id, args, actor);
        return
            _executeSafeAndFinalize(
                policyId, id, args, maxSteps, msg.value, msg.sender, actor, caller, semanticsRevision
            );
    }

    function executePrivate(
        uint256 operationId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        StoredRevealPayload calldata reveal
    )
        external
        payable
        nonReentrant
        onlySafeCaller
        onlyUser
        onlyExecutor
        requiresApproval(operationId)
        returns (uint256 stackTop)
    {
        address actor = _authorizedPolicyActor();
        address caller = _executionCaller(actor);
        _requireTermsAccepted();
        (bytes32 policyId, bytes32 payloadHash) = _validateSafeOperation(operationId, id, args, actor);
        _revealInteraction(id, reveal);
        (, uint64 semanticsRevision) =
            _runPolicyProgram(policyId, id, args, operationId, msg.value, payloadHash, actor, msg.sender);
        return
            _executeSafeAndFinalize(
                policyId, id, args, maxSteps, msg.value, msg.sender, actor, caller, semanticsRevision
            );
    }

    function approveAndExecute(uint256 operationId, bytes32 id, uint256[] calldata args, uint256 maxSteps)
        external
        payable
        nonReentrant
        onlySafeCaller
        onlyUser
        onlyExecutor
        returns (uint256 stackTop)
    {
        _requireInteractionActive(id);
        address actor = _authorizedPolicyActor();
        address caller = _executionCaller(actor);
        _requireTermsAccepted();
        _approveForExecution(actor, operationId);
        (bytes32 policyId, uint64 semanticsRevision) = _authorizeSafeOperation(operationId, id, args, actor);
        stackTop = _executeSafeAndFinalize(
            policyId, id, args, maxSteps, msg.value, msg.sender, actor, caller, semanticsRevision
        );
        _requiresApprovalAfter(operationId);
    }

    function approveAndExecutePrivate(
        uint256 operationId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        StoredRevealPayload calldata reveal
    ) external payable nonReentrant onlySafeCaller onlyUser onlyExecutor returns (uint256 stackTop) {
        address actor = _authorizedPolicyActor();
        address caller = _executionCaller(actor);
        _requireTermsAccepted();
        _approveForExecution(actor, operationId);
        (bytes32 policyId, bytes32 payloadHash) = _validateSafeOperation(operationId, id, args, actor);
        _revealInteraction(id, reveal);
        (, uint64 semanticsRevision) =
            _runPolicyProgram(policyId, id, args, operationId, msg.value, payloadHash, actor, msg.sender);
        stackTop = _executeSafeAndFinalize(
            policyId, id, args, maxSteps, msg.value, msg.sender, actor, caller, semanticsRevision
        );
        _requiresApprovalAfter(operationId);
    }

    function executeFromAccount(uint256 operationId, bytes32 id, uint256[] calldata args, uint256 maxSteps)
        external
        nonReentrant
        onlyUser
        onlyExecutor
        requiresApproval(operationId)
        returns (uint256 stackTop)
    {
        address actor = _authorizedPolicyActor();
        AccountOperationContext memory ctx = _prepareAccountTarget(operationId);
        _requireInteractionActive(id);
        _requireTermsAccepted();
        uint64 semanticsRevision = _authorizeAccountOperation(operationId, id, args, actor, ctx);
        return _executeAccountAndFinalize(
            ctx.policyId, id, args, maxSteps, ctx.nativeValue, ctx.account, actor, semanticsRevision
        );
    }

    function executePrivateFromAccount(
        uint256 operationId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        StoredRevealPayload calldata reveal
    ) external nonReentrant onlyUser onlyExecutor requiresApproval(operationId) returns (uint256 stackTop) {
        address actor = _authorizedPolicyActor();
        AccountOperationContext memory ctx = _prepareAccountTarget(operationId);
        _requireTermsAccepted();
        bytes32 payloadHash = _validateAccountOperation(operationId, id, args, actor, ctx);
        _revealInteraction(id, reveal);
        (, uint64 semanticsRevision) =
            _runPolicyProgram(ctx.policyId, id, args, operationId, ctx.nativeValue, payloadHash, actor, ctx.account);
        return _executeAccountAndFinalize(
            ctx.policyId, id, args, maxSteps, ctx.nativeValue, ctx.account, actor, semanticsRevision
        );
    }

    function approveAndExecuteFromAccount(uint256 operationId, bytes32 id, uint256[] calldata args, uint256 maxSteps)
        external
        nonReentrant
        onlyUser
        onlyExecutor
        returns (uint256 stackTop)
    {
        address actor = _authorizedPolicyActor();
        _requireTermsAccepted();
        _approveForExecution(actor, operationId);
        AccountOperationContext memory ctx = _prepareAccountTarget(operationId);
        _requireInteractionActive(id);
        uint64 semanticsRevision = _authorizeAccountOperation(operationId, id, args, actor, ctx);
        stackTop = _executeAccountAndFinalize(
            ctx.policyId, id, args, maxSteps, ctx.nativeValue, ctx.account, actor, semanticsRevision
        );
        _requiresApprovalAfter(operationId);
    }

    function approveAndExecutePrivateFromAccount(
        uint256 operationId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        StoredRevealPayload calldata reveal
    ) external nonReentrant onlyUser onlyExecutor returns (uint256 stackTop) {
        address actor = _authorizedPolicyActor();
        _requireTermsAccepted();
        _approveForExecution(actor, operationId);
        AccountOperationContext memory ctx = _prepareAccountTarget(operationId);
        bytes32 payloadHash = _validateAccountOperation(operationId, id, args, actor, ctx);
        _revealInteraction(id, reveal);
        (, uint64 semanticsRevision) =
            _runPolicyProgram(ctx.policyId, id, args, operationId, ctx.nativeValue, payloadHash, actor, ctx.account);
        stackTop = _executeAccountAndFinalize(
            ctx.policyId, id, args, maxSteps, ctx.nativeValue, ctx.account, actor, semanticsRevision
        );
        _requiresApprovalAfter(operationId);
    }

    function directExecute(
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 nativeValue,
        uint256 deadline,
        address actor,
        bytes calldata actorSignature
    ) external payable nonReentrant onlySafeCaller onlyUser onlyExecutor returns (uint256 stackTop) {
        _requireInteractionActive(id);
        bytes32 payloadHash =
            _prepareDirectSafe(policyId, id, args, maxSteps, nativeValue, deadline, actor, actorSignature);
        (, uint64 semanticsRevision) =
            _runPolicyProgram(policyId, id, args, 0, msg.value, payloadHash, actor, msg.sender);
        return _executeSafeAndFinalize(
            policyId, id, args, maxSteps, msg.value, msg.sender, actor, _executionCaller(actor), semanticsRevision
        );
    }

    function directExecutePrivate(
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 nativeValue,
        uint256 deadline,
        address actor,
        bytes calldata actorSignature,
        StoredRevealPayload calldata reveal
    ) external payable nonReentrant onlySafeCaller onlyUser onlyExecutor returns (uint256 stackTop) {
        bytes32 payloadHash =
            _prepareDirectSafe(policyId, id, args, maxSteps, nativeValue, deadline, actor, actorSignature);
        _revealInteraction(id, reveal);
        (, uint64 semanticsRevision) =
            _runPolicyProgram(policyId, id, args, 0, msg.value, payloadHash, actor, msg.sender);
        return _executeSafeAndFinalize(
            policyId, id, args, maxSteps, msg.value, msg.sender, actor, _executionCaller(actor), semanticsRevision
        );
    }

    function directExecuteFromAccount(
        address account,
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 maxNativeValue,
        uint256 deadline,
        address actor,
        bytes calldata actorSignature
    ) external nonReentrant onlyUser onlyExecutor returns (uint256 stackTop) {
        _requireInteractionActive(id);
        bytes32 payloadHash = _prepareDirectAccount(
            account, policyId, id, args, maxSteps, maxNativeValue, deadline, actor, actorSignature
        );
        (, uint64 semanticsRevision) =
            _runPolicyProgram(policyId, id, args, 0, maxNativeValue, payloadHash, actor, account);
        return
            _executeAccountAndFinalize(policyId, id, args, maxSteps, maxNativeValue, account, actor, semanticsRevision);
    }

    function directExecutePrivateFromAccount(
        address account,
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 maxNativeValue,
        uint256 deadline,
        address actor,
        bytes calldata actorSignature,
        StoredRevealPayload calldata reveal
    ) external nonReentrant onlyUser onlyExecutor returns (uint256 stackTop) {
        bytes32 payloadHash = _prepareDirectAccount(
            account, policyId, id, args, maxSteps, maxNativeValue, deadline, actor, actorSignature
        );
        _revealInteraction(id, reveal);
        (, uint64 semanticsRevision) =
            _runPolicyProgram(policyId, id, args, 0, maxNativeValue, payloadHash, actor, account);
        return
            _executeAccountAndFinalize(policyId, id, args, maxSteps, maxNativeValue, account, actor, semanticsRevision);
    }

    /// @notice Simulate the configured policy program through the exact execution argument path.
    /// @dev Always reverts with `PolicyProgramSimulationResult` after success so
    ///      MiniScript effects and PolicyState meter writes cannot persist.
    /// @param policyId Policy whose configured MiniScript program is evaluated.
    /// @param input Semantic operation context used to construct policy arguments and subject data.
    function simulatePolicyProgram(bytes32 policyId, PolicySimulationInput calldata input) external {
        (uint256 stackTop,) = _runPolicyProgram(
            policyId,
            input.interactionId,
            input.interactionArgs,
            input.operationId,
            input.nativeValue,
            input.payloadHash,
            input.actor,
            input.vault
        );
        // Success is reported as a revert so MiniScript writes, external call effects, events, balance
        // sweeps, and PolicyState meter writes are rolled back.
        revert InteractErrors.PolicyProgramSimulationResult(stackTop);
    }

    /// @dev A true result already includes existence, deadline and live threshold
    ///      checks. False may mean no new approval was recorded even when the
    ///      operation is executable, so preserve the full fallback check.
    function _approveForExecution(address actor, uint256 operationId) private {
        if (!_approveOperation(actor, operationId)) _requiresApprovalBefore(operationId);
    }

    /// @dev Validate the approval-bound Safe operation without reading interaction content.
    function _validateSafeOperation(uint256 operationId, bytes32 id, uint256[] calldata args, address actor)
        private
        view
        returns (bytes32 policyId, bytes32 payloadHash)
    {
        payloadHash = _validateOperationCalldata(operationId, id, args, msg.value, actor);
        policyId = _storage().operations[operationId].policyId;
    }

    /// @dev Validate and authorize a public Safe operation before execution.
    function _authorizeSafeOperation(uint256 operationId, bytes32 id, uint256[] calldata args, address actor)
        private
        returns (bytes32 policyId, uint64 semanticsRevision)
    {
        bytes32 payloadHash;
        (policyId, payloadHash) = _validateSafeOperation(operationId, id, args, actor);
        (, semanticsRevision) =
            _runPolicyProgram(policyId, id, args, operationId, msg.value, payloadHash, actor, msg.sender);
    }

    function _prepareDirectSafe(
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 nativeValue,
        uint256 deadline,
        address actor,
        bytes calldata actorSignature
    ) private returns (bytes32 payloadHash) {
        DirectExecutionContext memory ctx = _directExecutePrepare(
            policyId, id, args, maxSteps, nativeValue, deadline, actor, actorSignature
        );
        _requireTermsAccepted();
        payloadHash = ctx.payloadHash;
    }

    function _prepareDirectAccount(
        address account,
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 maxNativeValue,
        uint256 deadline,
        address actor,
        bytes calldata actorSignature
    ) private returns (bytes32 payloadHash) {
        DirectExecutionContext memory ctx = _directExecuteAccountPrepare(
            account, policyId, id, args, maxSteps, maxNativeValue, deadline, actor, actorSignature
        );
        _requireTermsAccepted();
        payloadHash = ctx.payloadHash;
    }

    /// @dev Load and validate the operation account without reading interaction content.
    function _prepareAccountTarget(uint256 operationId) private view returns (AccountOperationContext memory ctx) {
        Operation storage op = _storage().operations[operationId];
        ctx.account = op.safe;
        ctx.nativeValue = op.nativeValue;
        ctx.policyId = op.policyId;
        _requireAccountAllowed(ctx.account);
    }

    function _authorizeAccountOperation(
        uint256 operationId,
        bytes32 id,
        uint256[] calldata args,
        address actor,
        AccountOperationContext memory ctx
    ) private returns (uint64 semanticsRevision) {
        bytes32 payloadHash = _validateAccountOperation(operationId, id, args, actor, ctx);
        (, semanticsRevision) =
            _runPolicyProgram(ctx.policyId, id, args, operationId, ctx.nativeValue, payloadHash, actor, ctx.account);
    }

    /// @dev Validate the approval-bound account operation without reading interaction content.
    function _validateAccountOperation(
        uint256 operationId,
        bytes32 id,
        uint256[] calldata args,
        address actor,
        AccountOperationContext memory ctx
    ) private view returns (bytes32 payloadHash) {
        return _validateOperationCalldataForTarget(operationId, id, args, ctx.nativeValue, actor, ctx.account);
    }

    /// @dev These selectors belong to the proxy-facing `Interact` surface. Keeping revert-only overrides here
    ///      prevents inherited standalone management code from bloating the fixed delegatecall module runtime.
    function createOperation(bytes32, bytes32, uint256, uint256, address) public pure override returns (uint256) {
        revert DirectModuleCallUnsupported();
    }

    function approveOperation(uint256) public pure override returns (bool) {
        revert DirectModuleCallUnsupported();
    }

    function withdrawOperation(uint256) external pure override {
        revert DirectModuleCallUnsupported();
    }

    function isOperationApproved(uint256) external pure override returns (bool) {
        revert DirectModuleCallUnsupported();
    }

    function isOperationExecuted(uint256) public pure override returns (bool) {
        revert DirectModuleCallUnsupported();
    }

    function getOperationApprovalCount(uint256, bytes32) external pure override returns (uint256) {
        revert DirectModuleCallUnsupported();
    }

    function getOperationActiveApprovalCount(uint256, bytes32) external pure override returns (uint256) {
        revert DirectModuleCallUnsupported();
    }

    function hasUserApprovedOperation(uint256, address) external pure override returns (bool) {
        revert DirectModuleCallUnsupported();
    }

    function canUserApproveOperation(uint256, address) external pure override returns (bool) {
        revert DirectModuleCallUnsupported();
    }

    function canUserApproveAndSatisfyOperation(uint256, address) external pure override returns (bool) {
        revert DirectModuleCallUnsupported();
    }

    function getOperationNativeValue(uint256) public pure override returns (uint256) {
        revert DirectModuleCallUnsupported();
    }

    function getOperationPolicyId(uint256) public pure override returns (bytes32) {
        revert DirectModuleCallUnsupported();
    }

    function getOperationSafe(uint256) public pure override returns (address) {
        revert DirectModuleCallUnsupported();
    }

    function getOperationExecutor(uint256) public pure override returns (address) {
        revert DirectModuleCallUnsupported();
    }

    function canUserSatisfyPolicy(bytes32, address) public pure override returns (bool) {
        revert DirectModuleCallUnsupported();
    }

    function eip712Domain()
        public
        pure
        override
        returns (bytes1, string memory, string memory, uint256, address, bytes32, uint256[] memory)
    {
        // The canonical EIP-712 surface lives on the proxy-facing Interact wrapper.
        assembly ("memory-safe") {
            revert(0, 0)
        }
    }
}
