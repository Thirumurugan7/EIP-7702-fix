// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {Safe} from "@gnosis.pm/safe-contracts/Safe.sol";
import {Enum} from "@gnosis.pm/safe-contracts/libraries/Enum.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {InteractErrors} from "./InteractErrors.sol";
import {IMiniScriptExecutionHost, IOKAccount, InteractStorage} from "./InteractStorage.sol";
import {InteractionFlags} from "./InteractionFlags.sol";
import {IMiniScript} from "./MiniScript.sol";
import {MiniScriptEngine} from "./MiniScriptEngine.sol";
import {PagedIndex} from "./PagedIndex.sol";
import {ProtocolCodehashes} from "./ProtocolCodehashes.sol";
import {InteractionBundleInput, StoredBundleRevealPayload as StoredRevealPayload} from "./RegistryTypes.sol";
import {SignedActorTrailer} from "./SignedActorTrailer.sol";
import {CapabilityIds} from "./registry/Capabilities.sol";
import {IRegistryTerms, TermsDocument} from "./registry/Terms.sol";

interface IRegistryPolicyStateContext {
    /// @notice Open a policy-state execution context for one authorized runner.
    function beginPolicyStateExecution(bytes32 policyId, address runner) external;
    /// @notice Close the active policy-state execution context.
    function endPolicyStateExecution() external;
}

/// @title InteractModuleBase
/// @notice Shared execution helpers for the split Interact implementation.
/// @dev Concrete delegatecall modules share execution, terms acceptance, signature verification, and operation
///      validation through this base, keeping one storage domain and a compact proxy-facing wrapper.
abstract contract InteractModuleBase is InteractStorage {
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes4 private constant _EXECUTE_SELECTOR = bytes4(keccak256("execute(uint256,bytes32,uint256[],uint256)"));
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _EXECUTE_PRIVATE_SELECTOR = bytes4(
        keccak256(
            "executePrivate(uint256,bytes32,uint256[],uint256,((bytes32,bytes,uint256,(bytes32,bytes)[]),bytes32[],bytes32,bytes))"
        )
    );
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _APPROVE_AND_EXECUTE_SELECTOR =
        bytes4(keccak256("approveAndExecute(uint256,bytes32,uint256[],uint256)"));
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _APPROVE_AND_EXECUTE_PRIVATE_SELECTOR = bytes4(
        keccak256(
            "approveAndExecutePrivate(uint256,bytes32,uint256[],uint256,((bytes32,bytes,uint256,(bytes32,bytes)[]),bytes32[],bytes32,bytes))"
        )
    );
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _EXECUTE_FROM_ACCOUNT_SELECTOR =
        bytes4(keccak256("executeFromAccount(uint256,bytes32,uint256[],uint256)"));
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _EXECUTE_PRIVATE_FROM_ACCOUNT_SELECTOR = bytes4(
        keccak256(
            "executePrivateFromAccount(uint256,bytes32,uint256[],uint256,((bytes32,bytes,uint256,(bytes32,bytes)[]),bytes32[],bytes32,bytes))"
        )
    );
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _APPROVE_AND_EXECUTE_FROM_ACCOUNT_SELECTOR =
        bytes4(keccak256("approveAndExecuteFromAccount(uint256,bytes32,uint256[],uint256)"));
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _APPROVE_AND_EXECUTE_PRIVATE_FROM_ACCOUNT_SELECTOR = bytes4(
        keccak256(
            "approveAndExecutePrivateFromAccount(uint256,bytes32,uint256[],uint256,((bytes32,bytes,uint256,(bytes32,bytes)[]),bytes32[],bytes32,bytes))"
        )
    );
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _DIRECT_EXECUTE_SELECTOR =
        bytes4(keccak256("directExecute(bytes32,bytes32,uint256[],uint256,uint256,uint256,address,bytes)"));
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _DIRECT_EXECUTE_PRIVATE_SELECTOR = bytes4(
        keccak256(
            "directExecutePrivate(bytes32,bytes32,uint256[],uint256,uint256,uint256,address,bytes,((bytes32,bytes,uint256,(bytes32,bytes)[]),bytes32[],bytes32,bytes))"
        )
    );
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _DIRECT_EXECUTE_FROM_ACCOUNT_SELECTOR = bytes4(
        keccak256("directExecuteFromAccount(address,bytes32,bytes32,uint256[],uint256,uint256,uint256,address,bytes)")
    );
    // forge-lint: disable-end(unsafe-typecast)
    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-start(unsafe-typecast)
    bytes4 private constant _DIRECT_EXECUTE_PRIVATE_FROM_ACCOUNT_SELECTOR = bytes4(
        keccak256(
            "directExecutePrivateFromAccount(address,bytes32,bytes32,uint256[],uint256,uint256,uint256,address,bytes,((bytes32,bytes,uint256,(bytes32,bytes)[]),bytes32[],bytes32,bytes))"
        )
    );
    // forge-lint: disable-end(unsafe-typecast)

    /// @notice Restricts execution to actors with the interaction executor capability.
    modifier onlyExecutor() {
        _requireExecutorRole(_policyActor());
        _;
    }

    /// @notice Restricts execution to Safe/module call paths.
    modifier onlySafeCaller() {
        _requireSafeCaller();
        _;
    }

    /// @notice Reverts when the interaction is deactivated.
    function _requireInteractionActive(bytes32 id) internal view {
        _requireInteractionActive(id, registry.getInteractionFlags(id));
    }

    function _requireInteractionActive(bytes32 id, uint256 flags) internal pure {
        if (InteractionFlags.isInactive(flags)) {
            revert InteractErrors.InteractionInactive(id);
        }
    }

    /// @notice Execute the MiniScript defined under `id` from the calling Safe.
    /// @dev Reverts if the interaction does not exist.
    /// @param id Interaction identifier.
    /// @param args Initial stack arguments forwarded to MiniScript.
    /// @param maxSteps Upper bound for interpreter iterations.
    /// @param nativeValue ETH value authorized for the Safe-hosted run.
    /// @param actor Resolved actor authorizing the execution for audit/indexing purposes.
    /// @param caller Safe that hosts the MiniScript engine execution.
    /// @return outcome Stack/result metadata captured from the successful execution.
    function _executeUnsafe(
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 nativeValue,
        address actor,
        address caller
    ) internal returns (ExecutionOutcome memory outcome) {
        bytes memory script = registry.getInteractionScript(id);

        require(script.length != 0, "interaction:not-found");

        IMiniScript.SubjectContext memory subject = IMiniScript.SubjectContext({
            version: 2,
            interactionId: id,
            nativeValue: nativeValue,
            actor: actor,
            vault: caller,
            policyId: policyId,
            interactionArgs: args
        });
        address engine = IMiniScriptExecutionHost(address(miniScript)).engine();
        bytes memory data = abi.encodeWithSelector(
            MiniScriptEngine.runSubject.selector,
            script,
            args,
            maxSteps,
            address(registry),
            subject,
            nativeValue,
            engine
        );

        // The outer Safe call transfers the authorized native value into Interact.
        // Return it before entering the engine so the full budget is available in
        // the Safe execution host.
        if (nativeValue != 0) {
            // Guarded Safe execution returns only the committed nativeValue to its authenticated Safe host before
            // running the script.
            // forge-lint: disable-next-line(arbitrary-send-eth)
            (bool funded,) = payable(caller).call{value: nativeValue}("");
            require(funded, "interaction:safe-funding");
        }

        (bool success, bytes memory ret) =
            Safe(payable(caller)).execTransactionFromModuleReturnData(engine, 0, data, Enum.Operation.DelegateCall);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        outcome.stackTop = abi.decode(ret, (uint256));

        if (indexingEnabled) {
            outcome.recordId = _recordVaultExecution(msg.sender, id, actor, outcome.stackTop);
        }
    }

    /// @notice Execute an interaction through an OKAccount vault and record the resulting execution.
    /// @param account Account vault that will perform the interaction.
    /// @param id Interaction identifier to execute.
    /// @param args Initial stack arguments forwarded to the account execution.
    /// @param maxSteps Upper bound for interpreter iterations.
    /// @param maxNativeValue Maximum native value the account may forward during execution.
    /// @param caller Resolved actor authorizing the execution for audit/indexing purposes.
    /// @return outcome Stack/result metadata captured from the successful account execution.
    function _executeOnAccount(
        address account,
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 maxNativeValue,
        address caller
    ) internal returns (ExecutionOutcome memory outcome) {
        address analysisEngine = IMiniScriptExecutionHost(address(miniScript)).engine();
        address executionEngine = IOKAccount(account).chainwallEngine();
        if (!ProtocolCodehashes.isCompatibleMiniScriptDeployment(analysisEngine, executionEngine)) {
            revert InteractErrors.AccountEngineMismatch(analysisEngine, executionEngine);
        }
        outcome.stackTop = IOKAccount(account).executeInteraction(id, args, maxSteps, maxNativeValue, caller, policyId);
        if (indexingEnabled) {
            outcome.recordId = _recordVaultExecution(account, id, caller, outcome.stackTop);
        }
    }

    /// @notice Fail closed until the instance accepts its locally snapshotted initial document.
    function _requireTermsAccepted() internal view {
        IRegistryTerms terms = IRegistryTerms(address(registry));
        if (!terms.instanceHasAcceptedInitialTerms()) {
            // The acceptance gate needs the initial document hash for its error, not the publishing factory address.
            // forge-lint: disable-next-line(unused-return)
            (, TermsDocument memory initialTerms) = terms.getTermsContext();
            revert InteractErrors.TermsNotAccepted(initialTerms.documentHash);
        }
    }

    /// @notice Emit the inherited vault execution event from shared helper code.
    function _emitVaultInteractionExecuted(
        address vault,
        bytes32 interactionId,
        uint256 recordId,
        address actor,
        uint256 stackTop
    ) internal {
        // Execution entrypoints hold the shared nonReentrant guard through this event; failed signature events
        // revert with the call.
        // forge-lint: disable-next-line(reentrancy-events)
        emit VaultInteractionExecuted(vault, interactionId, recordId, actor, stackTop);
    }

    function _finalizeExecution(
        bytes32 id,
        address vault,
        address actor,
        ExecutionOutcome memory outcome,
        uint64 expectedSemanticsRevision
    ) internal returns (uint256 stackTop) {
        _requireExecutionSemanticsRevision(expectedSemanticsRevision);
        _emitVaultInteractionExecuted(vault, id, outcome.recordId, actor, outcome.stackTop);
        return outcome.stackTop;
    }

    function _executeSafeAndFinalize(
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 nativeValue,
        address vault,
        address actor,
        address caller,
        uint64 expectedSemanticsRevision
    ) internal returns (uint256 stackTop) {
        ExecutionOutcome memory outcome = _executeUnsafe(policyId, id, args, maxSteps, nativeValue, actor, caller);
        return _finalizeExecution(id, vault, actor, outcome, expectedSemanticsRevision);
    }

    function _executeAccountAndFinalize(
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 nativeValue,
        address account,
        address actor,
        uint64 expectedSemanticsRevision
    ) internal returns (uint256 stackTop) {
        ExecutionOutcome memory outcome = _executeOnAccount(account, policyId, id, args, maxSteps, nativeValue, actor);
        return _finalizeExecution(id, account, actor, outcome, expectedSemanticsRevision);
    }

    /// @notice Resolve the logical actor for the current execution path.
    /// @dev Signature verification is deferred to {_authorizedPolicyActor} so access-control modifiers can
    ///      inspect the actor without repeating an expensive ERC-1271 verification. Safe execution always
    ///      requires a trailer; account execution may use the direct caller as its actor.
    function _policyActor() internal view virtual override returns (address actor) {
        bytes4 selector = msg.sig;
        if (selector == _DIRECT_EXECUTE_SELECTOR || selector == _DIRECT_EXECUTE_PRIVATE_SELECTOR) {
            // The external ABI decoder has already validated the fixed argument head.
            assembly ("memory-safe") {
                actor := calldataload(0xc4)
            }
        } else if (
            selector == _DIRECT_EXECUTE_FROM_ACCOUNT_SELECTOR
                || selector == _DIRECT_EXECUTE_PRIVATE_FROM_ACCOUNT_SELECTOR
        ) {
            assembly ("memory-safe") {
                actor := calldataload(0xe4)
            }
        } else {
            // Every non-direct entrypoint that resolves a policy actor supports the
            // signed trailer. Standalone management selectors are overridden by the
            // fixed delegatecall module and never reach this hook.
            (bool present, address trailerActor,) = SignedActorTrailer.decode(msg.data);
            if (!present) {
                if (_allowsUnsignedActor()) {
                    return msg.sender;
                }
                revert InteractErrors.SignatureRequired();
            }
            actor = trailerActor;
        }
    }

    /// @notice Resolve and, when present, verify the operation actor exactly once before mutation.
    /// @dev Called only by the operation entrypoints that support a signed actor trailer.
    function _authorizedPolicyActor() internal view returns (address actor) {
        (bool present, address trailerActor, bytes calldata signature) = SignedActorTrailer.decode(msg.data);
        if (!present) {
            if (_allowsUnsignedActor()) return msg.sender;
            revert InteractErrors.SignatureRequired();
        }
        _verifySignedActor(trailerActor, signature);
        return trailerActor;
    }

    /// @notice Account-mode execution may use its direct caller as the policy actor.
    function _allowsUnsignedActor() internal pure returns (bool) {
        bytes4 selector = msg.sig;
        return selector == _EXECUTE_FROM_ACCOUNT_SELECTOR || selector == _EXECUTE_PRIVATE_FROM_ACCOUNT_SELECTOR
            || selector == _APPROVE_AND_EXECUTE_FROM_ACCOUNT_SELECTOR
            || selector == _APPROVE_AND_EXECUTE_PRIVATE_FROM_ACCOUNT_SELECTOR;
    }

    /// @notice Verify a signed actor trailer for approval/execute flows.
    /// @dev Supported trailer entrypoints encode the operation id in the first argument word.
    function _verifySignedActor(address actor, bytes memory signature) internal view {
        bytes32 typehash = EXECUTION_ACTOR_TYPEHASH;
        bytes32 structHash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, typehash)
            mstore(add(ptr, 0x20), actor)
            mstore(add(ptr, 0x40), caller())
            mstore(add(ptr, 0x60), shl(224, shr(224, calldataload(0))))
            mstore(add(ptr, 0x80), calldataload(4))
            mstore(add(ptr, 0xa0), chainid())
            structHash := keccak256(ptr, 0xc0)
            mstore(0x40, add(ptr, 0xc0))
        }
        // ERC-1271 must never be answered by an unapproved EIP-7702 delegate on the actor's behalf.
        _requireActorUsable(actor);
        if (!SignatureChecker.isValidSignatureNow(actor, _hashTypedDataV4(structHash), signature)) {
            revert InteractErrors.InvalidActorSignature();
        }
    }

    /// @notice Resolve the caller forwarded into MiniScript.
    /// @dev Kept as a separate hook so forwarding semantics can evolve without touching call sites.
    function _executionCaller(address) internal view returns (address caller) {
        return msg.sender;
    }

    /// @notice Record a successful vault execution into global and per-vault indexes.
    /// @param vault Safe or account vault that executed the interaction.
    /// @param interactionId Interaction identifier that was executed.
    /// @param caller Resolved actor that authorized the execution.
    /// @param stackTop Final MiniScript stack top returned by the execution.
    /// @return recordId Global execution record identifier assigned to the new record.
    function _recordVaultExecution(address vault, bytes32 interactionId, address caller, uint256 stackTop)
        internal
        returns (uint256 recordId)
    {
        recordId = PagedIndex.insert(
            _vaultExecutionRecordsIndex, bytes32(PagedIndex.nextId(_vaultExecutionRecordsIndex))
        );
        _vaultExecutionRecords[recordId] = StoredVaultExecutionRecord({
            recordId: recordId,
            interactionId: interactionId,
            vault: vault,
            caller: caller,
            stackTop: stackTop,
            blockNumber: SafeCast.toUint64(block.number)
        });

        uint8 next = _vaultExecutionRecentNext[vault];
        _vaultExecutionRecentRecordIds[vault][next] = recordId;

        uint8 count = _vaultExecutionRecentCount[vault];
        if (count < VAULT_EXECUTION_RECENT_LIMIT) {
            _vaultExecutionRecentCount[vault] = count + 1;
        }
        unchecked {
            _vaultExecutionRecentNext[vault] = (next + 1) % VAULT_EXECUTION_RECENT_LIMIT;
        }
    }

    /// @notice Verify a direct Safe-mode actor signature.
    function _verifyActorSignature(
        address actor,
        address forwarder,
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 nativeValue,
        uint256 deadline,
        uint256 nonce,
        bytes calldata signature
    ) internal returns (bool) {
        bytes32 argsHash;
        bytes memory argsData = abi.encode(args);
        assembly ("memory-safe") {
            argsHash := keccak256(add(argsData, 0x20), mload(argsData))
        }
        (bytes32 executionBindingHash, bytes32[] memory groupHashes, uint256[] memory thresholds) =
            _executionBindingHashAndCriteria(id, policyId);

        bytes32 structHash;
        bytes memory digestData = abi.encode(
            DIRECT_EXECUTE_TYPEHASH,
            actor,
            forwarder,
            policyId,
            id,
            argsHash,
            executionBindingHash,
            maxSteps,
            nativeValue,
            deadline,
            block.chainid,
            nonce
        );
        assembly ("memory-safe") {
            structHash := keccak256(add(digestData, 0x20), mload(digestData))
        }

        bytes32 typedHash = _hashTypedDataV4(structHash);
        // ERC-1271 must never be answered by an unapproved EIP-7702 delegate on the actor's behalf.
        _requireActorUsable(actor);
        if (!SignatureChecker.isValidSignatureNow(actor, typedHash, signature)) {
            // Execution entrypoints hold the shared nonReentrant guard through this event; failed signature events
            // revert with the call.
            // forge-lint: disable-start(reentrancy-events)
            emit DirectExecuteSignatureFailed(
                actor, forwarder, id, policyId, nonce, type(uint8).max, bytes32(0), address(0)
            );
            // forge-lint: disable-end(reentrancy-events)
            revert InteractErrors.InvalidActorSignature();
        }
        return _canUserSatisfyPolicy(policyId, actor, groupHashes, thresholds);
    }

    /// @notice Verify a direct account-mode actor signature.
    function _verifyActorSignatureFromAccount(
        address actor,
        address forwarder,
        address account,
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 nativeValue,
        uint256 deadline,
        uint256 nonce,
        bytes calldata signature
    ) internal returns (bool) {
        bytes32 argsHash;
        bytes memory argsData = abi.encode(args);
        assembly ("memory-safe") {
            argsHash := keccak256(add(argsData, 0x20), mload(argsData))
        }
        (bytes32 executionBindingHash, bytes32[] memory groupHashes, uint256[] memory thresholds) =
            _executionBindingHashAndCriteria(id, policyId);

        bytes32 structHash;
        bytes memory digestData = abi.encode(
            DIRECT_EXECUTE_FROM_ACCOUNT_TYPEHASH,
            actor,
            forwarder,
            account,
            policyId,
            id,
            argsHash,
            executionBindingHash,
            maxSteps,
            nativeValue,
            deadline,
            block.chainid,
            nonce
        );
        assembly ("memory-safe") {
            structHash := keccak256(add(digestData, 0x20), mload(digestData))
        }

        bytes32 typedHash = _hashTypedDataV4(structHash);
        // ERC-1271 must never be answered by an unapproved EIP-7702 delegate on the actor's behalf.
        _requireActorUsable(actor);
        if (!SignatureChecker.isValidSignatureNow(actor, typedHash, signature)) {
            // Execution entrypoints hold the shared nonReentrant guard through this event; failed signature events
            // revert with the call.
            // forge-lint: disable-start(reentrancy-events)
            emit DirectExecuteSignatureFailed(
                actor, forwarder, id, policyId, nonce, type(uint8).max, bytes32(0), address(0)
            );
            // forge-lint: disable-end(reentrancy-events)
            revert InteractErrors.InvalidActorSignature();
        }
        return _canUserSatisfyPolicy(policyId, actor, groupHashes, thresholds);
    }

    /// @notice Reverts when `actor` lacks the interaction executor capability.
    function _requireExecutorRole(address actor) internal view {
        if (!_registry.hasCapability(CapabilityIds.INTERACTION_EXECUTOR, actor)) {
            revert InteractErrors.ExecutorNotAuthorized();
        }
    }

    /// @notice Reverts when the caller is not an allowlisted Safe.
    function _requireSafeCaller() internal view {
        if (!_isSafeProxy(msg.sender)) {
            revert InteractErrors.SafeCallerRequired();
        }
    }

    /// @notice Returns whether `safe` is an allowlisted Safe proxy.
    function _isSafeProxy(address safe) internal view returns (bool) {
        return _registry.isSafeAllowed(safe);
    }

    /// @notice Reverts when the target account is not allowlisted.
    function _requireAccountAllowed(address account) internal view {
        if (!_isAccountAllowed(account)) {
            revert InteractErrors.AccountNotAllowed();
        }
    }

    /// @notice Returns whether `account` is an allowlisted account vault.
    function _isAccountAllowed(address account) internal view returns (bool) {
        return _registry.isAccountAllowed(account);
    }

    /// @notice Returns whether the target is an allowlisted Safe or account vault.
    function _isExecutionTargetAllowed(address target) internal view returns (bool) {
        return _isSafeProxy(target) || _isAccountAllowed(target);
    }

    /**
     * @notice Verifies the calldata against the stored operation payload hash and expected native value.
     * @dev The canonical payload hash is sender-agnostic; executor-bound hashes are also accepted.
     */
    function _validateOperationCalldata(
        uint256 operationId,
        bytes32 id,
        uint256[] calldata args,
        uint256 nativeValue,
        address executor
    ) internal view returns (bytes32 payloadHash) {
        Operation storage op = _storage().operations[operationId];
        uint256 expectedValue = op.nativeValue;
        if (op.safe != msg.sender) {
            revert InteractErrors.OperationSafeMismatch();
        }
        if (op.executor != address(0)) {
            if (executor != op.executor) {
                revert InteractErrors.OperationExecutorMismatch();
            }
            bytes32 executorHash =
                _hashPayloadWithExecutor(id, args, op.policyId, op.deadline, expectedValue, op.safe, op.executor);
            if (op.payloadHash != executorHash) {
                revert InteractErrors.OperationHashMismatch();
            }
            payloadHash =
                _hashPolicyPayloadWithExecutor(id, args, op.policyId, op.deadline, expectedValue, op.safe, op.executor);
        } else {
            bytes32 binding = _executionBindingHash(id, op.policyId);
            bytes32 canonicalHash =
                _hashBoundPayload(id, args, op.policyId, op.deadline, expectedValue, op.safe, binding);
            if (op.payloadHash == canonicalHash) {
                payloadHash = _hashPolicyPayload(id, args, op.policyId, op.deadline, expectedValue, op.safe);
            } else {
                bytes32 executorHash = _hashBoundPayloadWithExecutor(
                    id, args, op.policyId, op.deadline, expectedValue, op.safe, executor, binding
                );
                if (op.payloadHash != executorHash) {
                    revert InteractErrors.OperationHashMismatch();
                }
                payloadHash = _hashPolicyPayloadWithExecutor(
                    id, args, op.policyId, op.deadline, expectedValue, op.safe, executor
                );
            }
        }
        if (nativeValue != expectedValue) {
            revert InteractErrors.OperationNativeMismatch();
        }
    }

    /// @notice Account-mode variant of {_validateOperationCalldata}.
    /// @dev Verifies the stored target account instead of `msg.sender`.
    function _validateOperationCalldataForTarget(
        uint256 operationId,
        bytes32 id,
        uint256[] calldata args,
        uint256 nativeValue,
        address executor,
        address target
    ) internal view returns (bytes32 payloadHash) {
        Operation storage op = _storage().operations[operationId];
        uint256 expectedValue = op.nativeValue;
        if (op.safe != target) {
            revert InteractErrors.OperationSafeMismatch();
        }
        if (op.executor != address(0)) {
            if (executor != op.executor) {
                revert InteractErrors.OperationExecutorMismatch();
            }
            bytes32 executorHash =
                _hashPayloadWithExecutor(id, args, op.policyId, op.deadline, expectedValue, op.safe, op.executor);
            if (op.payloadHash != executorHash) {
                revert InteractErrors.OperationHashMismatch();
            }
            payloadHash =
                _hashPolicyPayloadWithExecutor(id, args, op.policyId, op.deadline, expectedValue, op.safe, op.executor);
        } else {
            bytes32 binding = _executionBindingHash(id, op.policyId);
            bytes32 canonicalHash =
                _hashBoundPayload(id, args, op.policyId, op.deadline, expectedValue, op.safe, binding);
            if (op.payloadHash == canonicalHash) {
                payloadHash = _hashPolicyPayload(id, args, op.policyId, op.deadline, expectedValue, op.safe);
            } else {
                bytes32 executorHash = _hashBoundPayloadWithExecutor(
                    id, args, op.policyId, op.deadline, expectedValue, op.safe, executor, binding
                );
                if (op.payloadHash != executorHash) {
                    revert InteractErrors.OperationHashMismatch();
                }
                payloadHash = _hashPolicyPayloadWithExecutor(
                    id, args, op.policyId, op.deadline, expectedValue, op.safe, executor
                );
            }
        }
        if (nativeValue != expectedValue) {
            revert InteractErrors.OperationNativeMismatch();
        }
    }

    /// @dev Execute already-constructed policy arguments with immutable subject context.
    ///      PolicyState writes are authorized only for the duration of this call.
    function _executePolicyProgram(
        bytes32 policyId,
        bytes memory program,
        uint32 maxSteps,
        uint256[] memory policyArgs,
        address safe,
        IMiniScript.SubjectContext memory subject
    ) internal returns (uint256 stackTop) {
        require(maxSteps != 0, "policy:program-steps");

        uint256 steps = maxSteps;
        if (steps > POLICY_PROGRAM_STEP_CAP) {
            steps = POLICY_PROGRAM_STEP_CAP;
        }

        IRegistryPolicyStateContext policyState = IRegistryPolicyStateContext(address(registry));
        // A policy may call custom contracts. Never run it without its own
        // authenticated context, or inside another policy's active context.
        // Simulation uses this same path and rolls the entire call tree back.
        policyState.beginPolicyStateExecution(policyId, address(miniScript));

        bytes memory data =
            abi.encodeWithSelector(IMiniScript.runPolicyProgram.selector, program, policyArgs, steps, subject);
        // ABI calldata has length 4 + 32*n. Its last allocated word contains
        // four data bytes followed by 28 padding bytes, enough for the vault.
        // Preserve those four bytes, write the 20-byte address and zero the
        // remaining padding. No second buffer or free-memory growth is needed.
        assembly ("memory-safe") {
            let length := mload(data)
            let tail := add(data, add(length, 28))
            mstore(tail, or(and(mload(tail), shl(224, 0xffffffff)), shr(32, shl(96, safe))))
            mstore(data, add(length, 20))
        }
        (bool success, bytes memory ret) = address(miniScript).call(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        stackTop = abi.decode(ret, (uint256));
        // Reverts roll back the opened context and all custom writes atomically.
        policyState.endPolicyStateExecution();
    }

    /// @notice Execute the registry policy program, when configured, before the interaction runs.
    /// @dev Policy arguments are, in order: interaction id, policy id, actor,
    ///      native value, operation id, payload hash, timestamp, chain id,
    ///      the original interaction arguments, and the final Safe/account vault.
    ///      The same root operation is also passed as immutable subject context.
    function _runPolicyProgram(
        bytes32 policyId,
        bytes32 interactionId,
        uint256[] calldata interactionArgs,
        uint256 operationId,
        uint256 nativeValue,
        bytes32 payloadHash,
        address actor,
        address safe
    ) internal returns (uint256 stackTop, uint64 semanticsRevision) {
        semanticsRevision = registry.getExecutionSemanticsRevision();
        // Execution consumes program bytes and the step cap; the other fields are publication metadata.
        // forge-lint: disable-next-line(unused-return)
        (bytes memory program, uint32 maxSteps,,) = _registry.getPolicyProgram(policyId);
        if (program.length == 0) {
            _requireExecutionSemanticsRevision(semanticsRevision);
            return (0, semanticsRevision);
        }
        uint256[] memory policyArgs = new uint256[](POLICY_PROGRAM_BASE_ARGS + interactionArgs.length + 1);
        policyArgs[0] = uint256(interactionId);
        policyArgs[1] = uint256(policyId);
        policyArgs[2] = uint256(uint160(actor));
        policyArgs[3] = nativeValue;
        policyArgs[4] = operationId;
        policyArgs[5] = uint256(payloadHash);
        policyArgs[6] = block.timestamp;
        policyArgs[7] = block.chainid;
        // The ABI decoder bounds the source, and the allocated array reserves
        // the fixed prefix, all interaction arguments and the final vault word.
        assembly ("memory-safe") {
            calldatacopy(add(policyArgs, 0x120), interactionArgs.offset, shl(5, interactionArgs.length))
        }
        policyArgs[POLICY_PROGRAM_BASE_ARGS + interactionArgs.length] = uint256(uint160(safe));

        IMiniScript.SubjectContext memory subject = IMiniScript.SubjectContext({
            version: 2,
            interactionId: interactionId,
            nativeValue: nativeValue,
            actor: actor,
            vault: safe,
            policyId: policyId,
            interactionArgs: interactionArgs
        });
        stackTop = _executePolicyProgram(policyId, program, maxSteps, policyArgs, safe, subject);
        _requireExecutionSemanticsRevision(semanticsRevision);
    }

    /// @dev Recheck after every untrusted external phase. Changes between
    ///      transactions remain live because each execution samples afresh.
    function _requireExecutionSemanticsRevision(uint64 expectedRevision) internal view {
        uint64 actualRevision = registry.getExecutionSemanticsRevision();
        if (actualRevision != expectedRevision) {
            revert InteractErrors.RegistryExecutionSemanticsChanged(expectedRevision, actualRevision);
        }
    }

    /// @notice Reveal a private interaction commit and require its published bundle to be executable.
    /// @dev The flag check occurs only after the exact committed bundle is active in the Registry.
    function _revealInteraction(bytes32 id, StoredRevealPayload calldata reveal) internal {
        if (reveal.bundle.id != id) revert InteractErrors.PrivateRevealBundleMismatch(id, bytes32(0), bytes32(0));
        registry.revealInteractionCommit(reveal.bundle, reveal.relatedContracts, reveal.salt, reveal.signature);
        InteractionBundleInput memory activeBundle = registry.getInteractionBundle(id);
        bytes32 expectedBundleHash = keccak256(abi.encode(reveal.bundle));
        bytes32 activeBundleHash = keccak256(abi.encode(activeBundle));
        if (activeBundleHash != expectedBundleHash) {
            revert InteractErrors.PrivateRevealBundleMismatch(id, expectedBundleHash, activeBundleHash);
        }
        _requireInteractionActive(id, activeBundle.flags);
    }

    /// @notice Prepare a direct Safe-mode execution.
    /// @dev Validates the deadline, optional actor signature, and single-actor policy satisfiability.
    ///      The entrypoint checks interaction flags before preparation or after private reveal.
    /// @return ctx Execution context consumed by the direct-execute paths.
    function _directExecutePrepare(
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 nativeValue,
        uint256 deadline,
        address actor,
        bytes calldata actorSignature
    ) internal returns (DirectExecutionContext memory ctx) {
        if (msg.value != nativeValue) {
            revert InteractErrors.DirectNativeMismatch();
        }
        if (deadline != 0) {
            // forge-lint: disable-next-line(block-timestamp)
            if (block.timestamp > deadline) {
                revert InteractErrors.DirectExecuteDeadlineExpired();
            }
        }
        uint256 nonce = _directExecuteNonces[actor];
        bool canSatisfy;
        if (actorSignature.length == 0) {
            if (msg.sender != actor) {
                revert InteractErrors.SignatureRequired();
            }
            canSatisfy = _canUserSatisfyPolicy(policyId, actor);
        } else {
            if (deadline == 0) revert InteractErrors.DirectExecuteDeadlineRequired();
            canSatisfy = _verifyActorSignature(
                actor, msg.sender, policyId, id, args, maxSteps, nativeValue, deadline, nonce, actorSignature
            );
        }

        if (!canSatisfy) {
            revert InteractErrors.PolicyCallerCannotSatisfy();
        }

        unchecked {
            _directExecuteNonces[actor] = nonce + 1;
        }

        ctx.caller = _executionCaller(actor);
        ctx.payloadHash = _hashPolicyPayload(id, args, policyId, DIRECT_EXECUTE_DEADLINE, msg.value, msg.sender);
    }

    /// @notice Prepare a direct account-mode execution.
    /// @dev Validates the deadline, optional actor signature, and single-actor policy satisfiability.
    ///      The entrypoint checks interaction flags before preparation or after private reveal.
    /// @return ctx Execution context consumed by the account direct-execute paths.
    function _directExecuteAccountPrepare(
        address account,
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 maxNativeValue,
        uint256 deadline,
        address actor,
        bytes calldata actorSignature
    ) internal returns (DirectExecutionContext memory ctx) {
        _requireAccountAllowed(account);
        if (deadline != 0) {
            // forge-lint: disable-next-line(block-timestamp)
            if (block.timestamp > deadline) {
                revert InteractErrors.DirectExecuteDeadlineExpired();
            }
        }
        uint256 nonce = _directExecuteNonces[actor];
        bool canSatisfy;
        if (actorSignature.length == 0) {
            if (msg.sender != actor) {
                revert InteractErrors.SignatureRequired();
            }
            canSatisfy = _canUserSatisfyPolicy(policyId, actor);
        } else {
            if (deadline == 0) revert InteractErrors.DirectExecuteDeadlineRequired();
            canSatisfy = _verifyActorSignatureFromAccount(
                actor,
                msg.sender,
                account,
                policyId,
                id,
                args,
                maxSteps,
                maxNativeValue,
                deadline,
                nonce,
                actorSignature
            );
        }

        if (!canSatisfy) {
            revert InteractErrors.PolicyCallerCannotSatisfy();
        }

        unchecked {
            _directExecuteNonces[actor] = nonce + 1;
        }

        ctx.actor = actor;
        ctx.payloadHash = _hashPolicyPayload(id, args, policyId, DIRECT_EXECUTE_DEADLINE, maxNativeValue, account);
    }
}
