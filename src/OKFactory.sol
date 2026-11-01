// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {OKFactoryAddressDerivation} from "./OKFactoryAddressDerivation.sol";
import {OKFactoryConfig} from "./OKFactoryConfig.sol";
import {OKFactoryDeploymentKey} from "./OKFactoryDeploymentKey.sol";
import {OKFactoryPredictor} from "./OKFactoryPredictor.sol";
import {OKFactoryStage1Module} from "./OKFactoryStage1Module.sol";
import {OKFactoryStage2Module} from "./OKFactoryStage2Module.sol";
import {ICapabilityActorsRegistry, OKFactoryState} from "./OKFactoryState.sol";
import {ProtocolCodehashes} from "./ProtocolCodehashes.sol";
import {RegistryDiamond} from "./RegistryDiamond.sol";
import {TermsRegistry} from "./TermsRegistry.sol";
import {CapabilityIds} from "./registry/Capabilities.sol";
import {TermsDocument, TermsDocumentLib} from "./registry/Terms.sol";

/**
 * @title OKFactory
 * @notice Coordinates creation of per-tenant stacks:
 *         {Registry, TimelockPolicyProgramRunner, MiniScript, Interact,
 *         SafeFactoryWithCreate2, AccountFactory, optional WebAuthnAuthAccountFactory}.
 * @dev Supports a staged flow where the registry is bootstrapped first, configured while paused next, and then
 *      atomically completed with its runtime contracts and transferred to tenant ownership.
 *      The public ABI and all authority checks remain on this contract, while the CREATE2-heavy deployment logic is
 *      delegated to fixed immutable modules so the factory can stay under EIP-170 without changing its trust model.
 *      A typical staged deployment is:
 *      1. Call `deployInstanceStage1Deterministic(owner, flags, userSalt)` to bootstrap an index-independent address
 *         family.
 *      2. Call `deployInstanceStage1Finalize(registry)` to install setup facets, deploy the timelock
 *         policy runner, and configure terms, capabilities, auth, and indexing while the registry remains paused
 *         and factory-owned.
 *      3. Call `deployInstanceStage2(registry)` to install deferred catalog/core facets; deploy MiniScript, Interact,
 *         SafeFactory, and AccountFactory; then atomically hand control to the tenant.
 */
contract OKFactory is OKFactoryState {
    bytes4 private constant _PREDICTOR_SELECTOR = 0x118c6eed;

    /// @notice Thrown when the factory config address is zero during deployment.
    error ConfigZero();
    /// @notice Thrown when the factory config address has no deployed code during deployment.
    error ConfigNotContract(address config);
    /// @notice Thrown when the factory config predictor getter reverts during deployment.
    error ConfigPredictorUnreadable(address config);
    /// @notice Thrown when the factory config predictor getter returns malformed data during deployment.
    error ConfigPredictorMalformed(address config);
    /// @notice Thrown when the configured predictor does not match the canonical OKFactoryPredictor runtime.
    error PredictorNotCanonical(address predictor);
    /// @notice Thrown when the configured stage-1 module does not match the canonical OKFactoryStage1Module runtime.
    error Stage1ModuleNotCanonical(address module);
    /// @notice Thrown when the configured stage-2 module does not match the canonical OKFactoryStage2Module runtime.
    error Stage2ModuleNotCanonical(address module);
    /// @notice Thrown when the configured auth module does not match the canonical OKFactoryAuthAccountModule runtime.
    error AuthAccountModuleNotCanonical(address module);
    /// @notice Thrown when a new instance is requested with a zero owner.
    error OwnerZero();
    /// @notice Thrown when stage-1 finalize is requested for a registry that has not been bootstrapped.
    error NotBootstrapped();
    /// @notice Thrown when stage 2 is requested for a registry that is not currently staged.
    error NotPending();
    /// @notice Thrown when unsupported deployment flags are provided.
    error UnsupportedFlags();
    /// @notice Thrown if the domain-separated deployment key unexpectedly resolves to zero.
    error DeploymentKeyZero();
    /// @notice Thrown when a deterministic deployment key was already committed to a registry.
    error DeploymentKeyAlreadyUsed(bytes32 deploymentKey, address registry);
    /// @notice Thrown when the staged registry no longer authorizes the predicted system actors.
    error SystemActorsNotAuthorized();
    /// @notice Thrown when staged registry ownership no longer matches the expected protected bootstrap owner.
    /// @param expected Factory owner required until stage 2 completes tenant handoff.
    /// @param actual Current owner observed during a staged transition.
    error RegistryOwner(address expected, address actual);
    /// @notice Thrown when an incomplete staged registry is unexpectedly unpaused.
    error RegistryNotPaused(address registry);
    /// @notice Thrown when the derived stage-2 deployment bindings drift after stage 1.
    error StageDeploymentChanged();
    /// @notice Immutable configuration contract that supplies implementations and facet sets.
    OKFactoryConfig public immutable CONFIG;
    /// @notice Predictor address validated during construction and frozen for all later stage-binding derivations.
    /// @dev The config is immutable, but the factory stores the predictor directly so staged bindings never depend
    ///      on an external read after construction.
    address public immutable STAGE_BINDINGS_PREDICTOR;
    /// @notice Fixed delegatecall target for stage-1 deployment logic.
    /// @dev Public introspection lets release verification authenticate immutable
    ///      children after normalizing the parent runtime's immutable regions.
    address public immutable STAGE1_MODULE;
    /// @notice Fixed delegatecall target for stage-2 finalization logic.
    address public immutable STAGE2_MODULE;
    /// @notice Fixed delegatecall target for optional AuthAccount factory deployment logic.
    address public immutable AUTH_ACCOUNT_MODULE;

    /// @notice Fixed publisher for optional later documents. Initial terms are compiled into this factory.
    TermsRegistry public immutable TERMS_REGISTRY;
    /// @notice Thrown when the publisher does not contain the factory's exact compiled initial document.
    /// @param termsRegistry Publisher rejected during factory deployment.
    /// @param documentHash Compiled initial document hash that must resolve to the compiled URI.
    error TermsRegistryInitialTermsMismatch(address termsRegistry, bytes32 documentHash);
    /// @notice Thrown when the configured publisher does not use the canonical TermsRegistry runtime.
    error TermsRegistryNotCanonical(address termsRegistry);

    /// @notice Deploy the factory wrapper and bind its fixed helper modules.
    /// @param config Immutable implementation/facet registry used by every deployment.
    /// @param stage1Module Canonical delegatecall target for stage-1 deployment logic.
    /// @param stage2Module Canonical delegatecall target for stage-2 deployment logic.
    /// @param authAccountModule Canonical delegatecall target for optional AuthAccount factory deployment logic.
    /// @param termsRegistry Append-only publisher, shared with future factories when desired.
    constructor(
        OKFactoryConfig config,
        // This module must match its canonical nonempty runtime codehash below, which excludes the zero address.
        // forge-lint: disable-next-line(missing-zero-check)
        address stage1Module,
        // This module must match its canonical nonempty runtime codehash below, which excludes the zero address.
        // forge-lint: disable-next-line(missing-zero-check)
        address stage2Module,
        // This module must match its canonical nonempty runtime codehash below, which excludes the zero address.
        // forge-lint: disable-next-line(missing-zero-check)
        address authAccountModule,
        TermsRegistry termsRegistry
    ) {
        if (address(termsRegistry).codehash != keccak256(type(TermsRegistry).runtimeCode)) {
            revert TermsRegistryNotCanonical(address(termsRegistry));
        }
        TermsDocument memory expectedTerms = TermsDocumentLib.initial();
        TermsDocument memory publishedTerms = termsRegistry.getTermsDocument(expectedTerms.documentHash);
        if (
            publishedTerms.documentHash != expectedTerms.documentHash
                || keccak256(bytes(publishedTerms.ipfsUri)) != keccak256(bytes(expectedTerms.ipfsUri))
        ) {
            revert TermsRegistryInitialTermsMismatch(address(termsRegistry), expectedTerms.documentHash);
        }
        if (address(config) == address(0)) revert ConfigZero();
        if (address(config).code.length == 0) revert ConfigNotContract(address(config));
        address predictor = _configPredictor(config);
        bytes32 predictorCodehash = predictor.codehash;
        if (!ProtocolCodehashes.isAcceptedPredictorCodehash(predictorCodehash)) {
            revert PredictorNotCanonical(predictor);
        }
        if (!ProtocolCodehashes.isAcceptedStage1ModuleCodehash(stage1Module.codehash)) {
            revert Stage1ModuleNotCanonical(stage1Module);
        }
        if (!ProtocolCodehashes.isAcceptedStage2ModuleCodehash(stage2Module.codehash)) {
            revert Stage2ModuleNotCanonical(stage2Module);
        }
        if (!ProtocolCodehashes.isAcceptedAuthAccountModuleCodehash(authAccountModule.codehash)) {
            revert AuthAccountModuleNotCanonical(authAccountModule);
        }
        CONFIG = config;
        STAGE_BINDINGS_PREDICTOR = predictor;
        STAGE1_MODULE = stage1Module;
        STAGE2_MODULE = stage2Module;
        AUTH_ACCOUNT_MODULE = authAccountModule;
        _factorySelf = address(this);
        TERMS_REGISTRY = termsRegistry;
    }

    function getTerms() external pure returns (TermsDocument memory) {
        return TermsDocumentLib.initial();
    }

    function getTermsDocument(bytes32 documentHash) external view returns (TermsDocument memory) {
        return TERMS_REGISTRY.getTermsDocument(documentHash);
    }

    /// @notice Address recorded for the delegatecall-only stage-module guard.
    function factorySelf() external view returns (address) {
        return _factorySelf;
    }

    function _configPredictor(OKFactoryConfig config) private view returns (address predictor) {
        (bool ok, bytes memory data) = address(config).staticcall(abi.encodeWithSelector(_PREDICTOR_SELECTOR));
        if (!ok) revert ConfigPredictorUnreadable(address(config));
        if (data.length < 32) revert ConfigPredictorMalformed(address(config));
        predictor = abi.decode(data, (address));
    }

    /// @notice Bootstrap a tenant whose addresses do not depend on this factory's global deployment sequence.
    /// @dev The key binds `userSalt`, `instanceOwner`, and `flags`. Therefore an arbitrary caller can only front-run
    ///      the exact deployment the owner intended; changing any semantic input creates another address family.
    ///      The factory address, config-derived creation code, owner, flags, and user salt must still match on every
    ///      target chain.
    function deployInstanceStage1Deterministic(address instanceOwner, uint8 flags, bytes32 userSalt) external {
        bytes32 deploymentKey = OKFactoryDeploymentKey.derive(userSalt, instanceOwner, flags);
        if (deploymentKey == bytes32(0)) revert DeploymentKeyZero();
        address existingRegistry = _deploymentKeyRegistries[deploymentKey];
        if (existingRegistry != address(0)) {
            revert DeploymentKeyAlreadyUsed(deploymentKey, existingRegistry);
        }
        bytes memory ret = _delegate(
            STAGE1_MODULE,
            abi.encodeCall(
                OKFactoryStage1Module.deployInstanceStage1Deterministic, (CONFIG, instanceOwner, flags, deploymentKey)
            )
        );
        (address registryAddr, uint256 index) = abi.decode(ret, (address, uint256));
        _recordStage1Bootstrap(registryAddr, index, instanceOwner, flags, deploymentKey);
    }

    function _recordStage1Bootstrap(
        address registryAddr,
        uint256 index,
        address instanceOwner,
        uint8 flags,
        bytes32 deploymentKey
    ) private {
        (address miniScript, address interact, address safeFactory, address accountFactory, bytes32 stage2Commitment) =
            _deriveStageBindings(registryAddr, deploymentKey, flags);

        _bootstrappedInstances[registryAddr] =
            (uint256(uint160(instanceOwner)) << 96) | (uint256(flags) << _PENDING_FLAGS_SHIFT) | index;
        _bootstrappedStageCommitments[registryAddr] = stage2Commitment;
        _bootstrappedAuthConfigCommitments[registryAddr] = _authConfigCommitment(flags);
        _bootstrappedDeploymentKeys[registryAddr] = deploymentKey;
        _deploymentKeyRegistries[deploymentKey] = registryAddr;
        // The event records this completed CREATE2 bootstrap using its reserved index and deployment key; finalize
        // state is consumed before calls.
        // forge-lint: disable-next-line(reentrancy-events)
        emit InstanceDeploymentKeyCommitted(deploymentKey, index, registryAddr);
        // The event records this completed CREATE2 bootstrap using its reserved index and deployment key; finalize
        // state is consumed before calls.
        // forge-lint: disable-next-line(reentrancy-events)
        emit InstanceStage1Bootstrapped(index, instanceOwner, registryAddr);
        // The event records this completed CREATE2 bootstrap using its reserved index and deployment key; finalize
        // state is consumed before calls.
        // forge-lint: disable-start(reentrancy-events)
        emit InstanceStage1BindingsCommitted(
            index, instanceOwner, registryAddr, miniScript, interact, safeFactory, accountFactory, stage2Commitment
        );
        // forge-lint: disable-end(reentrancy-events)
    }

    /// @notice Complete stage 1 by installing setup facets and wiring terms, auth, indexing, and system actors.
    /// @param registryAddr Address returned by `deployInstanceStage1Deterministic`.
    /// @dev Any caller may pay the gas to advance a bootstrapped registry through this step. This is intentional:
    ///      the caller cannot change the staged owner, flags, index, or bootstrap-frozen runtime bindings, and the
    ///      only effect is to prepare the already-recorded deployment on behalf of the staged owner.
    /// @dev IMPORTANT: this is not an approval or consent checkpoint. The bootstrap/finalize split exists to fit the
    ///      deployment under public-chain gas caps while still giving operators a chance to inspect the bootstrapped
    ///      registry off-chain before anyone advances it.
    /// @dev IMPORTANT: stage-1 finalize re-validates the binding frozen during bootstrap before authorizing the
    ///      predicted Interact, SafeFactory, and AccountFactory addresses. The registry remains paused and
    ///      factory-owned until stage 2 closes routing and performs the tenant handoff. This step does not seed
    ///      production timelock delays; the tenant configures them after handoff.
    function deployInstanceStage1Finalize(address registryAddr) external {
        uint256 packed = _bootstrappedInstances[registryAddr];
        address pendingOwner;
        assembly ("memory-safe") {
            pendingOwner := shr(96, packed)
        }
        if (pendingOwner == address(0)) revert NotBootstrapped();
        // _INSTANCE_FLAGS_MASK is uint8, so masking removes every bit above the target width.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint8 pendingFlags = uint8((packed >> _PENDING_FLAGS_SHIFT) & _INSTANCE_FLAGS_MASK);
        uint256 pendingIndex = packed & _PENDING_INDEX_MASK;
        bytes32 deploymentKey = _bootstrappedDeploymentKeys[registryAddr];

        RegistryDiamond registry = RegistryDiamond(registryAddr);
        address currentOwner = registry.owner();
        if (currentOwner != address(this)) {
            revert RegistryOwner(address(this), currentOwner);
        }
        if (!registry.paused()) revert RegistryNotPaused(registryAddr);

        (, address interact, address safeFactory, address accountFactory, bytes32 stage2Commitment) =
            _deriveStageBindings(registryAddr, deploymentKey, pendingFlags);
        if (_bootstrappedStageCommitments[registryAddr] != stage2Commitment) revert StageDeploymentChanged();
        if (_bootstrappedAuthConfigCommitments[registryAddr] != _authConfigCommitment(pendingFlags)) {
            revert StageDeploymentChanged();
        }

        delete _bootstrappedInstances[registryAddr];
        delete _bootstrappedStageCommitments[registryAddr];
        delete _bootstrappedAuthConfigCommitments[registryAddr];
        delete _bootstrappedDeploymentKeys[registryAddr];
        _delegate(
            STAGE1_MODULE,
            abi.encodeCall(
                OKFactoryStage1Module.deployInstanceStage1Finalize,
                (
                    CONFIG,
                    registryAddr,
                    pendingOwner,
                    pendingIndex,
                    pendingFlags,
                    interact,
                    safeFactory,
                    accountFactory,
                    stage2Commitment,
                    AUTH_ACCOUNT_MODULE,
                    deploymentKey
                )
            )
        );
    }

    /// @notice Finalise a staged deployment by closing registry routing, wiring MiniScript, Interact, Safe factory and
    ///         AccountFactory, and handing the completed registry to the staged owner.
    /// @dev Any caller may execute stage two while the registry remains paused and factory-owned. Component salts are
    ///      derived from the bootstrap-frozen deployment key. Reverts if the registry is not pending or its protected
    ///      bootstrap state has changed.
    /// @dev IMPORTANT: stage 2 re-validates the commitment stored during stage-1 finalize before deploying the
    ///      runtime contracts.
    /// @param registryAddr Address returned by `deployInstanceStage1Deterministic`.
    function deployInstanceStage2(address registryAddr) external {
        uint256 packed = _pendingInstances[registryAddr];
        address pendingOwner;
        assembly ("memory-safe") {
            pendingOwner := shr(96, packed)
        }
        if (pendingOwner == address(0)) revert NotPending();
        // _INSTANCE_FLAGS_MASK is uint8, so masking removes every bit above the target width.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint8 pendingFlags = uint8((packed >> _PENDING_FLAGS_SHIFT) & _INSTANCE_FLAGS_MASK);
        uint256 pendingIndex = packed & _PENDING_INDEX_MASK;
        bytes32 deploymentKey = _pendingDeploymentKeys[registryAddr];

        RegistryDiamond registry = RegistryDiamond(registryAddr);
        address currentOwner = registry.owner();
        if (currentOwner != address(this)) {
            revert RegistryOwner(address(this), currentOwner);
        }
        if (!registry.paused()) revert RegistryNotPaused(registryAddr);

        (,, address safeFactory, address accountFactory, bytes32 stage2Commitment) =
            _deriveStageBindings(registryAddr, deploymentKey, pendingFlags);
        if (_pendingStageCommitments[registryAddr] != stage2Commitment) revert StageDeploymentChanged();
        address authAccountFactory = _pendingAuthAccountFactories[registryAddr];

        delete _pendingInstances[registryAddr];
        delete _pendingStageCommitments[registryAddr];
        delete _pendingAuthAccountFactories[registryAddr];
        delete _pendingDeploymentKeys[registryAddr];
        _requireSystemActorsAuthorized(registryAddr, safeFactory, accountFactory);
        _delegate(
            STAGE2_MODULE,
            abi.encodeCall(
                OKFactoryStage2Module.deployInstanceStage2,
                (CONFIG, registryAddr, pendingOwner, pendingIndex, pendingFlags, authAccountFactory, deploymentKey)
            )
        );
    }

    /// @notice Derive the domain-separated identity used by an index-independent tenant deployment.
    /// @dev This helper is pure and can be used before deployment to compare plans across chains.
    function deriveInstanceDeploymentKey(bytes32 userSalt, address instanceOwner, uint8 flags)
        external
        pure
        returns (bytes32)
    {
        return OKFactoryDeploymentKey.derive(userSalt, instanceOwner, flags);
    }

    /// @notice Return the registry committed to a deterministic deployment key, or zero if unused.
    function getRegistryByDeploymentKey(bytes32 deploymentKey) external view returns (address) {
        return _deploymentKeyRegistries[deploymentKey];
    }

    /// @notice Return a registry's deterministic deployment key throughout its staged lifecycle.
    /// @dev Unknown registries return zero.
    function getInstanceDeploymentKey(address registryAddr) external view returns (bytes32 deploymentKey) {
        deploymentKey = _bootstrappedDeploymentKeys[registryAddr];
        if (deploymentKey == bytes32(0)) deploymentKey = _pendingDeploymentKeys[registryAddr];
        if (deploymentKey == bytes32(0)) deploymentKey = _deployedInstanceKeys[registryAddr];
    }

    /// @notice Return the persisted deployment snapshot for a tenant registry.
    /// @dev Unknown or not-yet-stage-2 registries return the zero struct. The record is stored during stage 2 so
    ///      discovery is independent of later registry state. The snapshot's `initialOwner` is the staged owner
    ///      observed at deployment time, not a live registry ownership mirror.
    function getInstance(address registryAddr) external view returns (FactoryInstance memory instance) {
        return _deployedInstances[registryAddr];
    }

    /// @dev The predicted system actors are not yet deployed during stage 2, so authorization must be checked by
    ///      inspecting raw capability membership instead of capability probes on the actors themselves.
    function _requireSystemActorsAuthorized(address registryAddr, address safeFactory, address accountFactory)
        private
        view
    {
        address[] memory actors =
            ICapabilityActorsRegistry(registryAddr).getCapabilityActors(CapabilityIds.ACCOUNT_MANAGER);
        bool safeAuthorized = false;
        bool accountAuthorized = false;
        uint256 len = actors.length;
        for (uint256 i; i < len; ++i) {
            address actor = actors[i];
            if (actor == safeFactory) safeAuthorized = true;
            if (actor == accountFactory) accountAuthorized = true;
            if (safeAuthorized && accountAuthorized) return;
        }
        revert SystemActorsNotAuthorized();
    }

    /// @dev Derive the remaining stage-2 bindings and commitment from the predictor address frozen at construction.
    function _deriveStageBindings(address registryAddr, bytes32 deploymentKey, uint8 flags)
        private
        view
        returns (
            address miniScript,
            address interact,
            address safeFactory,
            address accountFactory,
            bytes32 stage2Commitment
        )
    {
        return OKFactoryPredictor(STAGE_BINDINGS_PREDICTOR)
            .deriveDeterministicStageBindings(CONFIG, address(this), registryAddr, deploymentKey, flags);
    }

    /// @dev Commit the AuthAccount factory constructor config without pulling the factory initcode into the predictor.
    function _authConfigCommitment(uint8 flags) private view returns (bytes32 hash) {
        if (flags & _INSTANCE_FLAG_AUTH_ACCOUNT_FACTORY == 0) return bytes32(0);

        bytes32 rpIdHash = CONFIG.WEB_AUTHN_RP_ID_HASH();
        address entryPoint = CONFIG.WEB_AUTHN_ENTRY_POINT();
        address factoryImplementation = CONFIG.WEB_AUTHN_FACTORY_IMPL();
        address accountImplementation = CONFIG.WEB_AUTHN_ACCOUNT_IMPL();
        bytes memory originBytes = bytes(CONFIG.WEB_AUTHN_ORIGIN());
        bytes32 originHash;
        assembly ("memory-safe") {
            originHash := keccak256(add(originBytes, 0x20), mload(originBytes))
        }

        uint256 requireUserVerification = CONFIG.WEB_AUTHN_REQUIRE_USER_VERIFICATION() ? 1 : 0;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, rpIdHash)
            mstore(add(ptr, 0x20), originHash)
            mstore(add(ptr, 0x40), requireUserVerification)
            mstore(add(ptr, 0x60), entryPoint)
            mstore(add(ptr, 0x80), factoryImplementation)
            mstore(add(ptr, 0xa0), accountImplementation)
            hash := keccak256(ptr, 0xc0)
        }
    }

    /// @dev Delegate a module call and bubble any revert data unchanged.
    function _delegate(address implementation, bytes memory data) private returns (bytes memory ret) {
        // Stage IDs are reserved before creation, and finalize stages consume pending state before delegation;
        // targets are canonical immutables. All callers pass immutable STAGE1_MODULE
        // or STAGE2_MODULE, whose exact runtime hashes are checked in the constructor.
        // forge-lint: disable-next-line(reentrancy-no-eth, controlled-delegatecall)
        (bool success, bytes memory returnedData) = implementation.delegatecall(data);
        if (!success) {
            assembly {
                revert(add(returnedData, 0x20), mload(returnedData))
            }
        }
        return returnedData;
    }
}
