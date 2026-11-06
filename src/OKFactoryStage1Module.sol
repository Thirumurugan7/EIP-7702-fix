// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {Delegation7702} from "./Delegation7702.sol";
import {OKFactoryConfig} from "./OKFactoryConfig.sol";
import {OKFactoryErrors} from "./OKFactoryErrors.sol";
import {OKFactoryModuleBase} from "./OKFactoryModuleBase.sol";
import {IRegistryIndexing} from "./OKFactoryState.sol";
import {RegistryDiamond} from "./RegistryDiamond.sol";
import {TimelockPolicyProgramRunner} from "./TimelockPolicyProgramRunner.sol";
import {CapabilityIds} from "./registry/Capabilities.sol";
import {IRegistryTerms} from "./registry/Terms.sol";
import {RegistryCapabilitiesFacet} from "./registry/facets/RegistryCapabilitiesFacet.sol";

interface IOKFactoryAuthAccountModule {
    function deployAuthAccountFactory(
        OKFactoryConfig config,
        address registryAddr,
        address interact,
        address safeFactory,
        bytes32 deploymentKey
    ) external returns (address deployedAuthFactory);
}

interface IRegistryTimelockPolicyRunnerConfig {
    function setTimelockPolicyRunner(address runner) external;
}

/// @title OKFactoryStage1Module
/// @notice Delegatecall module that handles stage-1 registry deployment.
/// @dev This module carries the CREATE2-heavy registry deployment code so the public OKFactory wrapper can stay
///      under EIP-170 while preserving the factory as the actual deployer and authority boundary.
///      Stage 1 is split into a bootstrap transaction that deploys and pauses the registry shell, followed by a
///      finalize transaction that installs the setup facets and wires terms/system actors. The registry stays paused
///      and factory-owned until stage 2 atomically installs the deferred catalog/core facets, deploys the runtime
///      contracts, and hands control to the tenant.
contract OKFactoryStage1Module is OKFactoryModuleBase {
    /// @notice Deploy stage 1 from an index-independent deployment key already validated by the factory wrapper.
    /// @param deploymentKey Domain-separated owner/flags/user-salt binding used for every component salt.
    function deployInstanceStage1Deterministic(
        OKFactoryConfig config,
        address instanceOwner,
        uint8 flags,
        bytes32 deploymentKey
    ) external onlyDelegateCall returns (address registryAddr, uint256 index) {
        _validateFlags(flags);
        return _deployInstanceStage1(config, instanceOwner, deploymentKey);
    }

    /// @notice Complete stage 1 by installing setup facets and wiring system actors.
    /// @dev The registry deliberately remains paused and factory-owned. Stage 2 closes the selector table with the
    ///      core facets and performs one atomic runtime deployment and tenant handoff.
    /// @param config Immutable factory config mirrored from the wrapper.
    /// @param registryAddr Address returned by stage-1 bootstrap.
    /// @param instanceOwner Address that will receive admin/owner rights on the new registry.
    /// @param idx Tenant index recorded during stage-1 bootstrap.
    /// @param flags Instance deployment flags recorded during stage-1 bootstrap.
    /// @param interact Bootstrap-frozen Interact address to authorize.
    /// @param safeFactory Bootstrap-frozen SafeFactory address to authorize.
    /// @param accountFactory Bootstrap-frozen AccountFactory address to authorize.
    /// @param stage2Commitment Bootstrap-frozen commitment that stage 2 must later re-validate.
    /// @param authAccountModule Canonical delegatecall target for optional AuthAccount factory deployment.
    /// @param deploymentKey Domain-separated component salt key committed during stage-1 bootstrap.
    function deployInstanceStage1Finalize(
        OKFactoryConfig config,
        address registryAddr,
        address instanceOwner,
        uint256 idx,
        uint8 flags,
        address interact,
        address safeFactory,
        address accountFactory,
        bytes32 stage2Commitment,
        address authAccountModule,
        bytes32 deploymentKey
    ) external onlyDelegateCall {
        _deployInstanceStage1Finalize(
            config, registryAddr, flags, interact, safeFactory, accountFactory, authAccountModule, deploymentKey
        );
        _pendingInstances[registryAddr] =
            (uint256(uint160(instanceOwner)) << 96) | (uint256(flags) << _PENDING_FLAGS_SHIFT) | idx;
        _pendingStageCommitments[registryAddr] = stage2Commitment;
        _pendingDeploymentKeys[registryAddr] = deploymentKey;
    }

    /// @dev Internal stage-1 deployment flow. The factory remains the CREATE2 deployer because this runs via
    ///      delegatecall in the factory context.
    function _deployInstanceStage1(OKFactoryConfig config, address instanceOwner, bytes32 deploymentKey)
        internal
        returns (address registry, uint256 index)
    {
        if (instanceOwner == address(0)) revert OKFactoryErrors.OwnerZero();
        address ownerDelegate = Delegation7702.delegateOf(instanceOwner);
        if (ownerDelegate != address(0)) revert OKFactoryErrors.OwnerDelegated(instanceOwner, ownerDelegate);

        index = nextInstanceId;
        unchecked {
            nextInstanceId = index + 1;
        }

        bytes memory initData = abi.encodeCall(RegistryDiamond.initialize, ());
        bytes32 salt = _deploymentSalt(1, deploymentKey);
        address registryImpl = config.REGISTRY_IMPL();
        RegistryDiamond tenantRegistry = RegistryDiamond(address(new ERC1967Proxy{salt: salt}(registryImpl, initData)));

        _installBootstrapFacets(tenantRegistry, config);
        tenantRegistry.pause();

        registry = address(tenantRegistry);
    }

    /// @dev Complete stage 1 after the wrapper has validated the bootstrapped registry.
    function _deployInstanceStage1Finalize(
        OKFactoryConfig config,
        address registryAddr,
        uint8 flags,
        address interact,
        address safeFactory,
        address accountFactory,
        address authAccountModule,
        bytes32 deploymentKey
    ) internal {
        RegistryDiamond tenantRegistry = RegistryDiamond(registryAddr);
        // Setup writes use the same pause guards as tenant writes. Open the
        // Registry only within this atomic transaction, then re-pause before
        // returning. Only the authenticated config and canonical setup modules
        // run in this window; no tenant authority has been handed over.
        tenantRegistry.unpause();
        _installFinalizeFacets(tenantRegistry, config);

        address engine = config.ACCOUNT_ENGINE();
        _configureTimelockPolicyRunner(tenantRegistry, engine, deploymentKey);
        IRegistryTerms(registryAddr).initializeTermsContext();
        _authorizeSystemActors(tenantRegistry, safeFactory, accountFactory, interact);
        if (flags & _INSTANCE_FLAG_AUTH_ACCOUNT_FACTORY != 0) {
            _delegate(
                authAccountModule,
                abi.encodeCall(
                    IOKFactoryAuthAccountModule.deployAuthAccountFactory,
                    (config, registryAddr, interact, safeFactory, deploymentKey)
                )
            );
        }
        if (flags & _INSTANCE_FLAG_INDEXING != 0) {
            IRegistryIndexing(registryAddr).enableIndexing();
        }
        tenantRegistry.pause();
    }

    /// @dev Install the bootstrap facet tranche using the config contract as the temporary privileged installer.
    function _installBootstrapFacets(RegistryDiamond target, OKFactoryConfig config) internal {
        address configAddr = address(config);
        target.grantRole(_ADMIN_ROLE, configAddr);
        config.installRegistryBootstrapFacets(target);
        target.revokeRole(_ADMIN_ROLE, configAddr);
    }

    /// @dev Install the finalize facet tranche using the config contract as the temporary privileged installer.
    function _installFinalizeFacets(RegistryDiamond target, OKFactoryConfig config) internal {
        address configAddr = address(config);
        target.grantRole(_ADMIN_ROLE, configAddr);
        config.installRegistryFinalizeFacets(target);
        target.revokeRole(_ADMIN_ROLE, configAddr);
    }

    /// @dev Timelock policy programs execute through a registry-bound, non-upgradeable runner. The runner uses the
    ///      tenant component salt family so its address is reproducible across chains just like every other tenant
    ///      security component; the constructor still binds the exact Registry and canonical account engine.
    ///      Fresh registries have zero-delay timelock config, so this executes immediately before tenant handoff.
    function _configureTimelockPolicyRunner(RegistryDiamond registry, address engine, bytes32 deploymentKey) internal {
        TimelockPolicyProgramRunner runner =
            new TimelockPolicyProgramRunner{salt: _deploymentSalt(9, deploymentKey)}(address(registry), engine);
        IRegistryTimelockPolicyRunnerConfig(address(registry)).setTimelockPolicyRunner(address(runner));
    }

    /// @dev Runs while the factory is still temporary registry admin. Fresh tenant registries auto-init capability
    ///      timelock to zero delay/policy, so these grants and the actor lock execute immediately. If a customized
    ///      deployment preconfigures nonzero capability delays, these writes may queue and must be executed before
    ///      the lock can be finalized.
    function _authorizeSystemActors(
        RegistryDiamond registry,
        address safeFactory,
        address accountFactory,
        address interact
    ) internal {
        RegistryCapabilitiesFacet(address(registry)).grantCapabilityActor(CapabilityIds.ACCOUNT_MANAGER, safeFactory);
        RegistryCapabilitiesFacet(address(registry)).grantCapabilityActor(CapabilityIds.ACCOUNT_MANAGER, accountFactory);
        RegistryCapabilitiesFacet(address(registry)).grantCapabilityActor(CapabilityIds.POLICY_STATE_RUNNER, interact);
        RegistryCapabilitiesFacet(address(registry)).lockCapabilityActors();
    }

    function _validateFlags(uint8 flags) internal pure {
        if (flags & ~_INSTANCE_FLAGS_MASK != 0) revert OKFactoryErrors.UnsupportedFlags();
    }

    /// @dev Delegate a module call and bubble any revert data unchanged.
    function _delegate(address implementation, bytes memory data) private returns (bytes memory ret) {
        // The delegatecall-only entry receives the factory immutable AUTH_ACCOUNT_MODULE, checked against its
        // canonical hash.
        // forge-lint: disable-next-line(controlled-delegatecall)
        (bool success, bytes memory returnedData) = implementation.delegatecall(data);
        if (!success) {
            assembly {
                revert(add(returnedData, 0x20), mload(returnedData))
            }
        }
        return returnedData;
    }
}
