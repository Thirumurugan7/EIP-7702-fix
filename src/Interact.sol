// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {ChainwallUUPSUpgradeable} from "./ChainwallUpgradeable.sol";
import {InteractOpsModule} from "./InteractOpsModule.sol";
import {IMiniScriptExecutionHost, InteractStorage, PolicySimulationInput} from "./InteractStorage.sol";
import {IMiniScript} from "./MiniScript.sol";
import {PagedIndex} from "./PagedIndex.sol";
import {ProtocolCodehashes} from "./ProtocolCodehashes.sol";
import {StoredBundleRevealPayload as RevealPayload} from "./RegistryTypes.sol";
import {IRegistry} from "./registry/RegistryShared.sol";

/**
 * @title Interact
 * @notice Executes registry-defined MiniScript interactions under multi-group policies.
 * @dev Supports propose/approve/execute workflows and direct execution when a single
 *      actor satisfies the policy. Payload hashes bind calldata to the operation
 *      parameters so execution can be relayed, while the proxy-facing wrapper keeps
 *      upgrades and public ABI surface local and delegates execution logic to a
 *      fixed module to remain under EIP-170.
 * @author Henri Binsztok
 */
contract Interact is InteractStorage, ChainwallUUPSUpgradeable {
    bytes32 public constant CHAINWALL_COMPONENT_ID = keccak256("Chainwall.Interact");

    /// @notice Indexed execution record returned by public indexing view functions.
    struct VaultExecutionRecord {
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
    /// @param expectedBundleHash Hash of the complete bundle supplied in the reveal payload.
    /// @param activeBundleHash Hash of the complete bundle currently stored under `interactionId`.
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
    /// @notice Thrown when the immutable delegatecall module is not an accepted exact runtime.
    error InteractOpsModuleInvalid(address module, bytes32 codehash);
    /// @notice Thrown when Registry semantics change during one atomic execution.
    error RegistryExecutionSemanticsChanged(uint64 expectedRevision, uint64 actualRevision);
    /// @notice Revert payload used by policy-program simulation after the program succeeds.
    /// @dev The simulation path always reverts so it cannot persist PolicyState writes in a real transaction.
    /// @param stackTop Final MiniScript stack top returned by the policy program.
    error PolicyProgramSimulationResult(uint256 stackTop);

    /// @dev Fixed delegatecall target for queued-operation and direct execution.
    address public immutable OPS_MODULE;

    /// @notice Deploys the fixed execution module used by all wrapper instances of this implementation.
    constructor() {
        OPS_MODULE = address(new InteractOpsModule());
    }

    /// @notice Initializes a tenant Interact proxy with its registry and MiniScript dependencies.
    /// @param registry_ Registry contract for lookups.
    /// @param miniScript_ Tenant MiniScript interpreter.
    /// @param indexingEnabled_ Whether execution history indexing should be enabled for this instance.
    function initialize(IRegistry registry_, IMiniScript miniScript_, bool indexingEnabled_) external initializer {
        _requireCanonicalOpsModule(OPS_MODULE);
        _initializeInteract(registry_, miniScript_, indexingEnabled_);
        __UUPSUpgradeable_init();
    }

    /// @notice Expose the canonical MiniScript engine and Registry to Safe-hosted execution.
    /// @dev MiniScriptEngine authenticates this contract as the execution authority
    ///      when the engine runs by delegatecall inside an allowlisted Safe.
    function miniScriptHostConfig() external view returns (address engine, address registry_) {
        // Use the engine from the execution host and this Interact instance's own bound Registry.
        // forge-lint: disable-next-line(unused-return)
        (engine,) = IMiniScriptExecutionHost(address(miniScript)).miniScriptHostConfig();
        registry_ = address(registry);
    }

    /// @notice Compute the payload hash used in propose/execute flows.
    /// @dev Binds `args`, `policyId`, `deadline`, `nativeValue`, and Safe address in a sender-agnostic way.
    /// @param id Interaction identifier.
    /// @param args Initial stack arguments forwarded to MiniScript.
    /// @param policyId Policy hash that governs the operation.
    /// @param deadline Operation expiration timestamp.
    /// @param nativeValue Native value bound into the payload.
    /// @param safe Safe or account vault bound into the payload.
    /// @return payloadHash Sender-agnostic operation hash used by propose/execute flows.
    function getPayloadHash(
        bytes32 id,
        uint256[] calldata args,
        bytes32 policyId,
        uint256 deadline,
        uint256 nativeValue,
        address safe
    ) public view returns (bytes32 payloadHash) {
        payloadHash = _hashPayload(id, args, policyId, deadline, nativeValue, safe);
    }

    /// @notice Return the stable canonical intent hash received by policy programs.
    /// @dev Unlike `getPayloadHash`, this excludes mutable execution artifacts to
    ///      avoid a fixed point when a policy program validates its own intent.
    function getPolicyPayloadHash(
        bytes32 id,
        uint256[] calldata args,
        bytes32 policyId,
        uint256 deadline,
        uint256 nativeValue,
        address safe
    ) external pure returns (bytes32) {
        return _hashPolicyPayload(id, args, policyId, deadline, nativeValue, safe);
    }

    /// @notice Compute the payload hash that binds execution to a specific executor.
    /// @dev Use this when only `executor` should be able to execute the stored operation.
    /// @param executor Resolved actor that must execute the operation.
    /// @return payloadHash Executor-bound operation hash.
    function getPayloadHashWithExecutor(
        bytes32 id,
        uint256[] calldata args,
        bytes32 policyId,
        uint256 deadline,
        uint256 nativeValue,
        address safe,
        address executor
    ) public view returns (bytes32 payloadHash) {
        payloadHash = _hashPayloadWithExecutor(id, args, policyId, deadline, nativeValue, safe, executor);
    }

    /// @notice Return the executor-bound stable intent hash received by policy programs.
    function getPolicyPayloadHashWithExecutor(
        bytes32 id,
        uint256[] calldata args,
        bytes32 policyId,
        uint256 deadline,
        uint256 nativeValue,
        address safe,
        address executor
    ) external pure returns (bytes32) {
        return _hashPolicyPayloadWithExecutor(id, args, policyId, deadline, nativeValue, safe, executor);
    }

    /// @notice Return the current Registry state bound into operation hashes and direct signatures.
    function getExecutionBindingHash(bytes32 interactionId, bytes32 policyId) external view returns (bytes32) {
        return _executionBindingHash(interactionId, policyId);
    }

    /// @notice Propose a new operation to execute an interaction.
    /// @dev Caller must precompute `payloadHash` off-chain. If the proposer belongs to any required
    ///      group, their approval is automatically recorded.
    /// @param payloadHash Operation payload hash computed off-chain.
    /// @param policyId Policy hash that governs the operation.
    /// @param deadline Operation expiration timestamp.
    /// @param nativeValue Native value committed for execution.
    /// @param safe Safe or account vault bound to execution.
    /// @return operationId Newly created operation identifier.
    function propose(bytes32 payloadHash, bytes32 policyId, uint256 deadline, uint256 nativeValue, address safe)
        external
        nonReentrant
        onlyUser
        returns (uint256 operationId)
    {
        return _createProposedOperation(payloadHash, policyId, deadline, nativeValue, safe);
    }

    /// @notice Propose a new operation and bind execution to a specific executor.
    /// @dev The executor must match the resolved actor when executing the stored operation.
    /// @param executor Resolved actor that must execute the operation.
    /// @return operationId Newly created operation identifier.
    function proposeWithExecutor(
        bytes32 payloadHash,
        bytes32 policyId,
        uint256 deadline,
        uint256 nativeValue,
        address safe,
        address executor
    ) external nonReentrant onlyUser returns (uint256 operationId) {
        if (executor == address(0)) revert InvalidExecutor();
        operationId = _createProposedOperation(payloadHash, policyId, deadline, nativeValue, safe);
        _storage().operations[operationId].executor = executor;
    }

    /// @notice Execute the interaction defined by `id` after approval.
    /// @dev Delegates to the shared execution module while preserving the original proxy-facing ABI.
    /// @param operationId Identifier of the operation to execute.
    /// @param id Interaction identifier.
    /// @param args Initial stack arguments forwarded to MiniScript.
    /// @param maxSteps Upper bound for interpreter iterations.
    /// @return stackTop Value on the top of the stack after execution.
    function execute(uint256 operationId, bytes32 id, uint256[] calldata args, uint256 maxSteps)
        external
        payable
        returns (uint256 stackTop)
    {
        _touchDelegatedInputs(operationId, id, args, maxSteps);
        return _delegateUint(OPS_MODULE);
    }

    /// @notice Execute an approved interaction and reveal its committed private bundle.
    /// @param reveal Signed reveal payload authorizing publication of the private interaction.
    function executePrivate(
        uint256 operationId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        RevealPayload calldata reveal
    ) external payable returns (uint256 stackTop) {
        _touchDelegatedInputs(operationId, id, args, maxSteps, reveal);
        return _delegateUint(OPS_MODULE);
    }

    /// @notice Approve and execute an interaction in a single transaction.
    /// @dev Useful for the final signer to satisfy the policy and execute immediately.
    /// @param operationId Identifier of the operation to approve and execute.
    /// @param id Interaction identifier.
    /// @param args Initial stack arguments forwarded to MiniScript.
    /// @param maxSteps Upper bound for interpreter iterations.
    /// @return stackTop Value on the top of the stack after execution.
    function approveAndExecute(uint256 operationId, bytes32 id, uint256[] calldata args, uint256 maxSteps)
        external
        payable
        returns (uint256 stackTop)
    {
        _touchDelegatedInputs(operationId, id, args, maxSteps);
        return _delegateUint(OPS_MODULE);
    }

    /// @notice Approve and execute an interaction with a private reveal in one transaction.
    /// @param reveal Signed reveal payload authorizing publication of the private interaction.
    /// @return stackTop Value on the top of the stack after execution.
    function approveAndExecutePrivate(
        uint256 operationId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        RevealPayload calldata reveal
    ) external payable returns (uint256 stackTop) {
        _touchDelegatedInputs(operationId, id, args, maxSteps, reveal);
        return _delegateUint(OPS_MODULE);
    }

    /// @notice Execute an approved operation on an allowlisted account.
    /// @param operationId Identifier of the approved operation to execute.
    /// @param id Interaction identifier.
    /// @param args Initial stack arguments forwarded to the account execution.
    /// @param maxSteps Upper bound for interpreter iterations.
    /// @return stackTop Value on the top of the stack after execution.
    function executeFromAccount(uint256 operationId, bytes32 id, uint256[] calldata args, uint256 maxSteps)
        external
        returns (uint256 stackTop)
    {
        _touchDelegatedInputs(operationId, id, args, maxSteps);
        return _delegateUint(OPS_MODULE);
    }

    /// @notice Execute an approved private interaction on an allowlisted account.
    /// @param reveal Signed reveal payload authorizing publication of the private interaction.
    /// @return stackTop Value on the top of the stack after execution.
    function executePrivateFromAccount(
        uint256 operationId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        RevealPayload calldata reveal
    ) external returns (uint256 stackTop) {
        _touchDelegatedInputs(operationId, id, args, maxSteps, reveal);
        return _delegateUint(OPS_MODULE);
    }

    /// @notice Approve and execute an operation on an allowlisted account.
    /// @param operationId Identifier of the operation to approve and execute.
    /// @param id Interaction identifier.
    /// @param args Initial stack arguments forwarded to the account execution.
    /// @param maxSteps Upper bound for interpreter iterations.
    /// @return stackTop Value on the top of the stack after execution.
    function approveAndExecuteFromAccount(uint256 operationId, bytes32 id, uint256[] calldata args, uint256 maxSteps)
        external
        returns (uint256 stackTop)
    {
        _touchDelegatedInputs(operationId, id, args, maxSteps);
        return _delegateUint(OPS_MODULE);
    }

    /// @notice Approve and execute a private interaction on an allowlisted account.
    /// @param reveal Signed reveal payload authorizing publication of the private interaction.
    /// @return stackTop Value on the top of the stack after execution.
    function approveAndExecutePrivateFromAccount(
        uint256 operationId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        RevealPayload calldata reveal
    ) external returns (uint256 stackTop) {
        _touchDelegatedInputs(operationId, id, args, maxSteps, reveal);
        return _delegateUint(OPS_MODULE);
    }

    /// @notice Execute an interaction immediately if the actor alone satisfies the policy.
    /// @dev Skips the propose/approve workflow when the policy can be met by a single actor.
    ///      If msg.sender differs from `actor`, a signature is required and bound to the forwarder and nonce.
    /// @param policyId Policy hash defining the required approval groups.
    /// @param id Interaction identifier.
    /// @param args Initial stack for the MiniScript interpreter.
    /// @param maxSteps Interpreter step limit.
    /// @param nativeValue Native value committed for the direct execution request.
    /// @param deadline Expiration timestamp. Zero is allowed only for an unsigned
    ///        actor-self call; every relayed signed request requires a finite deadline.
    /// @param actor Actor that must satisfy the policy or sign the request.
    /// @param actorSignature Optional actor signature bound to the request and forwarder.
    /// @return stackTop Value on top of the stack after execution.
    function directExecute(
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 nativeValue,
        uint256 deadline,
        address actor,
        bytes calldata actorSignature
    ) external payable returns (uint256 stackTop) {
        _touchDelegatedInputs(policyId, id, args, maxSteps, nativeValue, deadline, actor, actorSignature);
        return _delegateUint(OPS_MODULE);
    }

    /// @notice Direct execute with an accompanying private interaction reveal.
    /// @param reveal Signed reveal payload authorizing publication of the private interaction.
    /// @return stackTop Value on top of the stack after execution.
    function directExecutePrivate(
        bytes32 policyId,
        bytes32 id,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 nativeValue,
        uint256 deadline,
        address actor,
        bytes calldata actorSignature,
        RevealPayload calldata reveal
    ) external payable returns (uint256 stackTop) {
        _touchDelegatedInputs(policyId, id, args, maxSteps, nativeValue, deadline, actor, actorSignature, reveal);
        return _delegateUint(OPS_MODULE);
    }

    /// @notice Direct execute against an allowlisted account.
    /// @param account Allowlisted account vault that will execute the interaction.
    /// @param maxNativeValue Maximum native value the account may forward during execution.
    /// @return stackTop Value on top of the stack after execution.
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
    ) external returns (uint256 stackTop) {
        _touchDelegatedInputs(account, policyId, id, args, maxSteps, maxNativeValue, deadline, actor, actorSignature);
        return _delegateUint(OPS_MODULE);
    }

    /// @notice Direct execute against an allowlisted account with an accompanying private interaction reveal.
    /// @param reveal Signed reveal payload authorizing publication of the private interaction.
    /// @return stackTop Value on top of the stack after execution.
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
        RevealPayload calldata reveal
    ) external returns (uint256 stackTop) {
        _touchDelegatedInputs(
            account, policyId, id, args, maxSteps, maxNativeValue, deadline, actor, actorSignature, reveal
        );
        return _delegateUint(OPS_MODULE);
    }

    /// @notice Simulate the configured policy program with the PolicyState execution context opened.
    /// @dev Always reverts with {PolicyProgramSimulationResult} after success so state writes cannot persist.
    /// @dev This is an eth_call/preflight entrypoint, not an execution path. It intentionally delegates to
    ///      the ops module so PolicyState runtime authorization sees this Interact proxy as the executor.
    /// @param policyId Policy hash whose program should be simulated.
    /// @param input Semantic interaction context used to construct policy arguments.
    function simulatePolicyProgram(bytes32 policyId, PolicySimulationInput calldata input) external {
        _touchDelegatedInputs(policyId, input);
        _delegate(OPS_MODULE);
    }

    /// @notice Upgrade entry point reserved for the registry timelock.
    /// @param newImplementation New UUPS implementation to install on the proxy.
    /// @param initData Optional initializer call executed immediately after upgrading.
    function timelockUpgrade(address newImplementation, bytes calldata initData) external {
        if (msg.sender != address(registry)) revert OnlyRegistry();
        _performUpgrade(newImplementation, initData);
    }

    /// @notice Returns the total number of indexed vault execution records.
    /// @dev Reverts with {IndexingDisabled} when indexing is disabled for this instance.
    function getVaultExecutionRecordCount() external view whenIndexingEnabled returns (uint256) {
        return PagedIndex.length(_vaultExecutionRecordsIndex);
    }

    /// @notice Returns a page of indexed vault execution records from the global execution history.
    /// @param start Zero-based start offset within the global execution history.
    /// @param count Maximum number of records to return.
    /// @return out Execution records ordered by ascending global record id.
    function getVaultExecutionRecordPage(uint256 start, uint256 count)
        external
        view
        whenIndexingEnabled
        returns (VaultExecutionRecord[] memory out)
    {
        bytes32[] memory ids = PagedIndex.page(_vaultExecutionRecordsIndex, start, count);
        out = new VaultExecutionRecord[](ids.length);
        for (uint256 i; i < ids.length; i++) {
            InteractStorage.StoredVaultExecutionRecord storage record = _vaultExecutionRecords[uint256(ids[i])];
            out[i] = VaultExecutionRecord({
                recordId: record.recordId,
                interactionId: record.interactionId,
                vault: record.vault,
                caller: record.caller,
                stackTop: record.stackTop,
                blockNumber: record.blockNumber
            });
        }
    }

    /// @notice Returns the most recent indexed execution records for a vault.
    /// @dev Records are returned newest first and capped by `VAULT_EXECUTION_RECENT_LIMIT`.
    /// @param vault Safe or account vault to inspect.
    /// @return out Most recent execution records for `vault`, ordered from newest to oldest.
    function getVaultExecutionRecent(address vault)
        external
        view
        whenIndexingEnabled
        returns (VaultExecutionRecord[] memory out)
    {
        uint8 count = _vaultExecutionRecentCount[vault];
        out = new VaultExecutionRecord[](count);
        uint8 next = _vaultExecutionRecentNext[vault];
        uint8 latest = next == 0 ? VAULT_EXECUTION_RECENT_LIMIT - 1 : next - 1;
        for (uint8 i; i < count; i++) {
            uint8 index = latest >= i ? latest - i : VAULT_EXECUTION_RECENT_LIMIT + latest - i;
            InteractStorage.StoredVaultExecutionRecord storage record =
                _vaultExecutionRecords[_vaultExecutionRecentRecordIds[vault][index]];
            out[i] = VaultExecutionRecord({
                recordId: record.recordId,
                interactionId: record.interactionId,
                vault: record.vault,
                caller: record.caller,
                stackTop: record.stackTop,
                blockNumber: record.blockNumber
            });
        }
    }

    /// @notice Returns the current directExecute nonce for an actor.
    function directExecuteNonce(address actor) external view returns (uint256) {
        return _directExecuteNonces[actor];
    }

    function chainwallComponentId() external pure override returns (bytes32) {
        return CHAINWALL_COMPONENT_ID;
    }

    /// @dev Interact releases may replace embedded operation code only with an accepted exact module runtime.
    ///      The tenant Registry, MiniScript host, and forwarding authority remain stable trust roots.
    function _chainwallSecurityBindingsHash() internal view override returns (bytes32) {
        _requireCanonicalOpsModule(OPS_MODULE);
        return _hashSecurityBindings(abi.encode(address(registry), address(_registry), address(miniScript)));
    }

    /// @notice Disabled default UUPS entrypoint.
    /// @dev Interact upgrades must flow through {timelockUpgrade} so the registry remains the sole upgrade gate.
    function upgradeToAndCall(address, bytes memory) public payable override {
        revert("Interact: use timelockUpgrade");
    }

    /// @notice Perform the actual UUPS upgrade once registry authorization has been checked.
    function _performUpgrade(address newImplementation, bytes calldata initData) internal {
        require(newImplementation != address(0), "upgrade:impl=0");
        _upgradePreservingBindings(newImplementation, initData);
    }

    function _createProposedOperation(
        bytes32 payloadHash,
        bytes32 policyId,
        uint256 deadline,
        uint256 nativeValue,
        address safe
    ) private returns (uint256 operationId) {
        if (!_registry.isSafeAllowed(safe) && !_registry.isAccountAllowed(safe)) {
            revert InvalidSafeTarget();
        }
        operationId = _createOperation(payloadHash, policyId, deadline, nativeValue, safe);
        if (_isPolicySignatory(policyId, msg.sender)) {
            _approveOperationInternal(operationId);
        }
    }

    /// @notice Restricts UUPS upgrades to the registry timelock.
    function _authorizeUpgrade(address) internal view override {
        if (msg.sender != address(registry)) revert OnlyRegistry();
    }

    /// @dev Marks delegated wrapper parameters as intentionally part of the public ABI surface.
    // ABI marker only: the wrapper forwards the original msg.data to the validating execution module.
    // forge-lint: disable-next-line(empty-block)
    function _touchDelegatedInputs(uint256, bytes32, uint256[] calldata, uint256) private pure {}

    /// @dev Marks delegated wrapper parameters as intentionally part of the public ABI surface.
    function _touchDelegatedInputs(uint256, bytes32, uint256[] calldata, uint256, RevealPayload calldata)
        private
        // ABI marker only: the wrapper forwards the original msg.data to the validating execution module.
        // forge-lint: disable-next-line(empty-block)
        pure {}

    /// @dev Marks delegated wrapper parameters as intentionally part of the public ABI surface.
    // ABI marker only: the wrapper forwards the original msg.data to the validating execution module.
    // forge-lint: disable-next-line(empty-block)
    function _touchDelegatedInputs(uint256, bytes32, uint256[] calldata, uint256, bytes32) private pure {}

    /// @dev Marks delegated wrapper parameters as intentionally part of the public ABI surface.
    // ABI marker only: the wrapper forwards the original msg.data to the validating execution module.
    // forge-lint: disable-next-line(empty-block)
    function _touchDelegatedInputs(bytes32, PolicySimulationInput calldata) private pure {}

    /// @dev Marks delegated wrapper parameters as intentionally part of the public ABI surface.
    function _touchDelegatedInputs(
        bytes32,
        bytes32,
        uint256[] calldata,
        uint256,
        uint256,
        uint256,
        address,
        bytes calldata
        // ABI marker only: the wrapper forwards the original msg.data to the validating execution module.
        // forge-lint: disable-next-line(empty-block)
    ) private pure {}

    /// @dev Marks delegated wrapper parameters as intentionally part of the public ABI surface.
    function _touchDelegatedInputs(
        bytes32,
        bytes32,
        uint256[] calldata,
        uint256,
        uint256,
        uint256,
        address,
        bytes calldata,
        RevealPayload calldata
        // ABI marker only: the wrapper forwards the original msg.data to the validating execution module.
        // forge-lint: disable-next-line(empty-block)
    ) private pure {}

    /// @dev Marks delegated wrapper parameters as intentionally part of the public ABI surface.
    function _touchDelegatedInputs(
        address,
        bytes32,
        bytes32,
        uint256[] calldata,
        uint256,
        uint256,
        uint256,
        address,
        bytes calldata
        // ABI marker only: the wrapper forwards the original msg.data to the validating execution module.
        // forge-lint: disable-next-line(empty-block)
    ) private pure {}

    /// @dev Marks delegated wrapper parameters as intentionally part of the public ABI surface.
    function _touchDelegatedInputs(
        address,
        bytes32,
        bytes32,
        uint256[] calldata,
        uint256,
        uint256,
        uint256,
        address,
        bytes calldata,
        RevealPayload calldata
        // ABI marker only: the wrapper forwards the original msg.data to the validating execution module.
        // forge-lint: disable-next-line(empty-block)
    ) private pure {}

    /// @notice Delegate the current calldata to the execution module and decode a uint256 return value.
    function _delegateUint(address implementation) private returns (uint256 value) {
        value = abi.decode(_delegate(implementation), (uint256));
    }

    /// @notice Delegate the current calldata to the execution module and bubble any revert data.
    function _delegate(address implementation) private returns (bytes memory ret) {
        // All callers pass constructor-created OPS_MODULE; initialization and upgrade admission verify its
        // canonical runtime.
        // forge-lint: disable-next-line(controlled-delegatecall)
        (bool success, bytes memory data) = implementation.delegatecall(msg.data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(data, 0x20), mload(data))
            }
        }
        return data;
    }

    /// @dev The parent release matcher masks immutable addresses. Validate this
    ///      constructor-created immutable once at implementation admission, not on
    ///      every interaction delegated through the proxy.
    function _requireCanonicalOpsModule(address module) private view {
        bytes32 codehash = module.codehash;
        if (!ProtocolCodehashes.isAcceptedInteractOpsModuleCodehash(codehash)) {
            revert InteractOpsModuleInvalid(module, codehash);
        }
    }
}
