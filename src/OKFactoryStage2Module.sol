// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AccountFactory} from "./AccountFactory.sol";
import {Interact} from "./Interact.sol";
import {IMiniScript, MiniScript} from "./MiniScript.sol";
import {OKFactoryConfig} from "./OKFactoryConfig.sol";
import {OKFactoryModuleBase} from "./OKFactoryModuleBase.sol";
import {RegistryDiamond} from "./RegistryDiamond.sol";
import {SafeFactoryWithCreate2} from "./SafeFactory.sol";
import {IRegistry} from "./registry/RegistryShared.sol";

/// @title OKFactoryStage2Module
/// @notice Delegatecall module that finalizes staged deployments by deploying the remaining tenant runtime components.
/// @dev The wrapper still enforces the public ABI and ownership checks. This module exists only to carry the heavy
///      CREATE2 deployment code while preserving the factory as the actual deployer and security boundary.
///      deploys the predicted runtime addresses, and only then transfers registry authority to the tenant.
contract OKFactoryStage2Module is OKFactoryModuleBase {
    struct Stage2RuntimeAddresses {
        address miniScript;
        address interact;
        address safeFactory;
        address accountFactory;
        address authAccountFactory;
    }

    /// @notice Finalize a staged deployment after the wrapper has validated the staged registry and bindings.
    /// @param config Immutable factory config mirrored from the wrapper.
    /// @param registryAddr Address returned by stage 1.
    /// @param instanceOwner Owner recorded during stage 1.
    /// @param idx Tenant index recorded during stage 1.
    /// @param flags Instance deployment flags recorded during stage 1.
    /// @param authAccountFactory WebAuthn AuthAccount factory deployed during stage-1 finalize, or zero when disabled.
    /// @param deploymentKey Domain-separated component salt key committed during stage-1 bootstrap.
    function deployInstanceStage2(
        OKFactoryConfig config,
        address registryAddr,
        address instanceOwner,
        uint256 idx,
        uint8 flags,
        address authAccountFactory,
        bytes32 deploymentKey
    ) external onlyDelegateCall {
        _deployInstanceStage2(config, registryAddr, instanceOwner, idx, flags, authAccountFactory, deploymentKey);
    }

    /// @dev Complete routing and deploy the remaining tenant components after the staged registry has been validated.
    ///      The registry is paused and factory-owned; tenant authority transfers only after the full stack exists.
    ///      The extra owner-controlled MiniScript proxy exists for direct raw-script testing against the tenant
    ///      registry without going through the interaction catalog.
    function _deployInstanceStage2(
        OKFactoryConfig config,
        address registryAddr,
        address instanceOwner,
        uint256 idx,
        uint8 flags,
        address authAccountFactory,
        bytes32 deploymentKey
    ) internal {
        bool indexingEnabled = (flags & _INSTANCE_FLAG_INDEXING) != 0;
        Stage2RuntimeAddresses memory deployed;
        if (flags & _INSTANCE_FLAG_AUTH_ACCOUNT_FACTORY != 0) {
            require(authAccountFactory != address(0), "auth factory missing");
            deployed.authAccountFactory = authAccountFactory;
            require(deployed.authAccountFactory.code.length != 0, "auth factory missing");
        }
        RegistryDiamond tenantRegistry = RegistryDiamond(registryAddr);
        // The wrapper consumed the pending deployment and checked its immutable
        // bindings before entering. Bootstrap uses ordinary pause guards too.
        // Re-pause before constructing runtime components; no tenant has roles
        // until the final atomic handover below.
        tenantRegistry.unpause();
        _installCompletionFacets(tenantRegistry, config);
        tenantRegistry.pause();

        IRegistry registry = IRegistry(registryAddr);
        address engine = config.ACCOUNT_ENGINE();

        deployed.miniScript = _deployMiniScript(config, 2, deploymentKey);
        deployed.interact = _deployInteract(config, registry, deployed.miniScript, deploymentKey, indexingEnabled);
        MiniScript(payable(deployed.miniScript))
            .initializeWithEngine(registry, deployed.interact, deployed.interact, engine);
        deployed.safeFactory = _deploySafeFactory(config, deployed.interact, deploymentKey, indexingEnabled);
        deployed.accountFactory =
            _deployAccountFactory(config, deployed.interact, deploymentKey, indexingEnabled, engine);

        _recordInstance(registryAddr, instanceOwner, idx, flags, deploymentKey, deployed);
        _handoverRegistry(tenantRegistry, instanceOwner);
    }

    /// @dev Install the deferred catalog selectors and core facets while the config is a temporary registry admin.
    ///      Core installation permanently closes the direct bootstrap path before the registry is exposed to tenants.
    function _installCompletionFacets(RegistryDiamond target, OKFactoryConfig config) internal {
        address configAddr = address(config);
        target.grantRole(_ADMIN_ROLE, configAddr);
        config.installRegistryCompletionFacets(target);
        target.revokeRole(_ADMIN_ROLE, configAddr);
    }

    /// @dev Expose the completed registry and atomically transfer every administration plane to the staged owner.
    ///      Unpausing occurs before the factory renounces ADMIN_ROLE because ownership alone has no pause authority.
    function _handoverRegistry(RegistryDiamond registry, address newOwner) internal {
        registry.unpause();
        registry.grantRole(_ADMIN_ROLE, newOwner);
        registry.grantRole(_UPGRADER_ROLE, newOwner);
        registry.enableRoleGovernance();
        registry.renounceRole(_ADMIN_ROLE, address(this));
        registry.renounceRole(_UPGRADER_ROLE, address(this));
        registry.completeOwnershipHandover(newOwner);
    }

    function _deployMiniScript(OKFactoryConfig config, uint8 component, bytes32 deploymentKey)
        internal
        returns (address)
    {
        return address(
            new ERC1967Proxy{salt: _deploymentSalt(component, deploymentKey)}(config.MINISCRIPT_IMPL(), bytes(""))
        );
    }

    function _deployInteract(
        OKFactoryConfig config,
        IRegistry registry,
        address miniScript,
        bytes32 deploymentKey,
        bool indexingEnabled
    ) internal returns (address) {
        bytes memory interactInitData = abi.encodeCall(
            Interact.initialize, (registry, IMiniScript(miniScript), indexingEnabled)
        );
        return
            address(new ERC1967Proxy{salt: _deploymentSalt(3, deploymentKey)}(config.INTERACT_IMPL(), interactInitData));
    }

    function _deploySafeFactory(OKFactoryConfig config, address interact, bytes32 deploymentKey, bool indexingEnabled)
        internal
        returns (address)
    {
        bytes memory safeFactoryInitData = abi.encodeCall(
            SafeFactoryWithCreate2.initialize,
            (config.SAFE_SINGLETON(), config.SAFE_PROXY_FACTORY(), Interact(interact), indexingEnabled)
        );
        return address(
            new ERC1967Proxy{salt: _deploymentSalt(4, deploymentKey)}(config.SAFE_FACTORY_IMPL(), safeFactoryInitData)
        );
    }

    function _deployAccountFactory(
        OKFactoryConfig config,
        address interact,
        bytes32 deploymentKey,
        bool indexingEnabled,
        address engine
    ) internal returns (address) {
        bytes memory accountInitData = abi.encodeCall(
            AccountFactory.initialize, (Interact(interact), engine, config.OK_ACCOUNT_IMPL(), indexingEnabled)
        );
        return address(
            new ERC1967Proxy{salt: _deploymentSalt(5, deploymentKey)}(config.ACCOUNT_FACTORY_IMPL(), accountInitData)
        );
    }

    function _recordInstance(
        address registryAddr,
        address instanceOwner,
        uint256 idx,
        uint8 flags,
        bytes32 deploymentKey,
        Stage2RuntimeAddresses memory deployed
    ) internal {
        _deployedInstances[registryAddr] = FactoryInstance({
            index: idx,
            initialOwner: instanceOwner,
            miniScript: deployed.miniScript,
            interact: deployed.interact,
            safeFactory: deployed.safeFactory,
            accountFactory: deployed.accountFactory,
            flags: flags,
            authAccountFactory: deployed.authAccountFactory
        });
        _deployedInstanceKeys[registryAddr] = deploymentKey;

        // The factory consumes the pending deployment before stage 2; this event records only the completed
        // instance and fixed bindings.
        // forge-lint: disable-start(reentrancy-events)
        emit InstanceDeployed(
            idx,
            instanceOwner,
            registryAddr,
            deployed.miniScript,
            deployed.interact,
            deployed.safeFactory,
            deployed.accountFactory,
            deployed.authAccountFactory
        );
        // forge-lint: disable-end(reentrancy-events)
    }
}
