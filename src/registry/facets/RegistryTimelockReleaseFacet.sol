// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {IProxy} from "@gnosis.pm/safe-contracts/proxies/SafeProxy.sol";
import {SafeProxyFactory} from "@gnosis.pm/safe-contracts/proxies/SafeProxyFactory.sol";

import {IChainwallUpgradeable} from "../../ChainwallUpgradeable.sol";
import {ExecutionCatalogStorage} from "../../registry/RegistryShared.sol";
import {ExecutionContextLib, TimelockLib, TimelockRequest} from "../../registry/TimelockLib.sol";
import {RegistryUpgradeFacetBase} from "./RegistryUpgradeFacetBase.sol";

interface IChainwallEngineHost {
    function chainwallEngine() external view returns (address);
    function setChainwallEngine(address newEngine) external;
}

interface IChainwallAccountFactoryRelease {
    function chainwallAccountImplementation() external view returns (address);
    function accountImplementationCodehash() external view returns (bytes32);
    function setChainwallAccountImplementation(address newImplementation) external;
}

interface IChainwallAuthAccountFactoryRelease {
    function chainwallAuthAccountImplementation() external view returns (address);
    function CHAINWALL_AUTH_ACCOUNT_IMPLEMENTATION_CODEHASH() external view returns (bytes32);
    function setChainwallAuthAccountImplementation(address newImplementation) external;
}

interface IChainwallSafeFactoryRelease {
    function PROXY_FACTORY() external view returns (address);
    function INTERACT_CONTRACT() external view returns (address);
    function GUARD_CONTRACT() external view returns (address);
    function MODULE_CONTRACT() external view returns (address);
    function SAFE_SINGLETON_MIGRATOR() external view returns (address);
    function CONFIGURATOR() external view returns (address);
    function SAFE_PROXY_FACTORY_CODEHASH() external view returns (bytes32);
    function SAFE_PROXY_CREATION_CODEHASH() external view returns (bytes32);
    function SAFE_SINGLETON_CODEHASH() external view returns (bytes32);
    function chainwallSafeSingleton() external view returns (address);
    function isSafe(address safe) external view returns (bool);
    function isSafeSingletonApproved(address singleton) external view returns (bool);
    function isSafeSingletonMigrationTarget(address singleton) external view returns (bool);
    function setChainwallSafeProxyFactory(address newProxyFactory, bytes32 expectedCreationCodehash) external;
    function setChainwallSafeSingleton(address newSingleton) external;
    function setChainwallSafeSingletonMigrator(address newMigrator) external;
    function setChainwallConfigurator(address newConfigurator) external;
}

interface IChainwallSafeExtensionRelease {
    function SAFE_SINGLETON_MIGRATOR() external view returns (address);
    function setSafeSingletonMigrator(address newMigrator) external;
}

interface IChainwallSafeModuleMigration {
    function migrateSafeSingleton(address safeFactory, address safe, address newSingleton, bytes32 expectedCodehash)
        external;
}

/// @title RegistryTimelockReleaseFacet
/// @notice Timelocked dependency and future-deployment defaults for one tenant.
/// @dev These transitions are separate from implementation upgrades because they
///      intentionally change a component binding rather than only its code.
contract RegistryTimelockReleaseFacet is RegistryUpgradeFacetBase {
    uint256 public constant VERSION = 1;

    bytes32 private constant MINISCRIPT_COMPONENT_ID = keccak256("Chainwall.MiniScript");
    bytes32 private constant ACCOUNT_FACTORY_COMPONENT_ID = keccak256("Chainwall.AccountFactory");
    bytes32 private constant OK_ACCOUNT_COMPONENT_ID = keccak256("Chainwall.OKAccount");
    bytes32 private constant AUTH_ACCOUNT_FACTORY_COMPONENT_ID = keccak256("Chainwall.WebAuthnAuthAccountFactory");
    bytes32 private constant SAFE_FACTORY_COMPONENT_ID = keccak256("Chainwall.SafeFactory");
    bytes32 private constant OK_GUARD_COMPONENT_ID = keccak256("Chainwall.OKGuard");
    bytes32 private constant OK_MODULE_COMPONENT_ID = keccak256("Chainwall.OKModule");
    bytes32 private constant SAFE_CONFIGURATOR_COMPONENT_ID = keccak256("Chainwall.SafeConfigurator");

    error ReleaseTargetInvalid(address target);
    error ReleaseComponentInvalid(address target, bytes32 expected, bytes32 actual);
    error ReleasePointerChanged(address target, address expected, address actual);
    error ReleaseCodehashChanged(address target, bytes32 expected, bytes32 actual);
    error ReleaseNoChange(address target);
    error ReleaseSafeNotManaged(address safeFactory, address safe);
    error ReleaseSafeSingletonNotApproved(address safeFactory, address singleton);
    error ReleaseSafeSingletonChanged(address safe, address expected, address actual);
    error ReleaseSafeSingletonMigratorSetMismatch(address safeFactory, address guard, address module);
    error ReleaseProxyCreationCodeChanged(address proxyFactory, bytes32 expected, bytes32 actual);

    event EngineReplaced(address indexed target, address indexed previousEngine, address indexed newEngine);
    event AccountImplementationDefaultChanged(
        address indexed factory, address indexed previousImplementation, address indexed newImplementation
    );
    event AuthAccountImplementationDefaultChanged(
        address indexed factory, address indexed previousImplementation, address indexed newImplementation
    );
    event SafeProxyFactoryDefaultChanged(
        address indexed safeFactory, address indexed previousProxyFactory, address indexed newProxyFactory
    );
    event SafeSingletonDefaultChanged(
        address indexed safeFactory, address indexed previousSingleton, address indexed newSingleton
    );
    event SafeSingletonMigratorReplaced(
        address indexed safeFactory, address indexed previousMigrator, address indexed newMigrator
    );
    event SafeConfiguratorReplaced(
        address indexed safeFactory, address indexed previousConfigurator, address indexed newConfigurator
    );
    event SafeSingletonMigrated(
        address indexed safeFactory, address indexed safe, address indexed previousSingleton, address newSingleton
    );

    function replaceEngine(address target, address newEngine) external returns (bytes32 actionId) {
        _requireTimelockGovernor();
        bytes32 componentId = _readComponentId(target);
        if (
            componentId != MINISCRIPT_COMPONENT_ID && componentId != ACCOUNT_FACTORY_COMPONENT_ID
                && componentId != OK_ACCOUNT_COMPONENT_ID
        ) {
            revert ReleaseComponentInvalid(target, MINISCRIPT_COMPONENT_ID, componentId);
        }
        address current = IChainwallEngineHost(target).chainwallEngine();
        if (current == newEngine) revert ReleaseNoChange(target);
        bytes32 currentCodehash = _requireCode(current);
        bytes32 newCodehash = _requireCode(newEngine);
        bytes memory payload = abi.encodeCall(
            this._replaceEngineExecute, (target, componentId, current, currentCodehash, newEngine, newCodehash)
        );
        return _queueOrExecute(target, payload);
    }

    function setAccountImplementation(address factory, address newImplementation) external returns (bytes32 actionId) {
        _requireTimelockGovernor();
        _requireComponent(factory, ACCOUNT_FACTORY_COMPONENT_ID);
        address current = IChainwallAccountFactoryRelease(factory).chainwallAccountImplementation();
        if (current == newImplementation) revert ReleaseNoChange(factory);
        bytes32 currentCodehash = _requireCode(current);
        bytes32 recordedCodehash = IChainwallAccountFactoryRelease(factory).accountImplementationCodehash();
        if (recordedCodehash != currentCodehash) {
            revert ReleaseCodehashChanged(current, recordedCodehash, currentCodehash);
        }
        bytes32 newCodehash = _requireCode(newImplementation);
        bytes memory payload = abi.encodeCall(
            this._setAccountImplementationExecute, (factory, current, currentCodehash, newImplementation, newCodehash)
        );
        return _queueOrExecute(factory, payload);
    }

    function setAuthAccountImplementation(address factory, address newImplementation)
        external
        returns (bytes32 actionId)
    {
        _requireTimelockGovernor();
        _requireComponent(factory, AUTH_ACCOUNT_FACTORY_COMPONENT_ID);
        address current = IChainwallAuthAccountFactoryRelease(factory).chainwallAuthAccountImplementation();
        if (current == newImplementation) revert ReleaseNoChange(factory);
        bytes32 currentCodehash = _requireCode(current);
        bytes32 recordedCodehash =
            IChainwallAuthAccountFactoryRelease(factory).CHAINWALL_AUTH_ACCOUNT_IMPLEMENTATION_CODEHASH();
        if (recordedCodehash != currentCodehash) {
            revert ReleaseCodehashChanged(current, recordedCodehash, currentCodehash);
        }
        bytes32 newCodehash = _requireCode(newImplementation);
        bytes memory payload = abi.encodeCall(
            this._setAuthAccountImplementationExecute,
            (factory, current, currentCodehash, newImplementation, newCodehash)
        );
        return _queueOrExecute(factory, payload);
    }

    function setSafeProxyFactory(address safeFactory, address newProxyFactory) external returns (bytes32 actionId) {
        _requireTimelockGovernor();
        IChainwallSafeFactoryRelease factory = IChainwallSafeFactoryRelease(safeFactory);
        _requireComponent(safeFactory, SAFE_FACTORY_COMPONENT_ID);
        address current = factory.PROXY_FACTORY();
        if (current == newProxyFactory) revert ReleaseNoChange(safeFactory);
        bytes32 currentCodehash = _requireCode(current);
        bytes32 currentCreationCodehash = _safeProxyCreationCodehash(current);
        if (factory.SAFE_PROXY_FACTORY_CODEHASH() != currentCodehash) {
            revert ReleaseCodehashChanged(current, factory.SAFE_PROXY_FACTORY_CODEHASH(), currentCodehash);
        }
        if (factory.SAFE_PROXY_CREATION_CODEHASH() != currentCreationCodehash) {
            revert ReleaseProxyCreationCodeChanged(
                current, factory.SAFE_PROXY_CREATION_CODEHASH(), currentCreationCodehash
            );
        }
        bytes32 newCodehash = _requireCode(newProxyFactory);
        bytes32 creationCodehash = _safeProxyCreationCodehash(newProxyFactory);
        bytes memory payload = abi.encodeCall(
            this._setSafeProxyFactoryExecute,
            (
                safeFactory,
                current,
                currentCodehash,
                currentCreationCodehash,
                newProxyFactory,
                newCodehash,
                creationCodehash
            )
        );
        return _queueOrExecute(safeFactory, payload);
    }

    function setSafeSingleton(address safeFactory, address newSingleton) external returns (bytes32 actionId) {
        _requireTimelockGovernor();
        _requireComponent(safeFactory, SAFE_FACTORY_COMPONENT_ID);
        IChainwallSafeFactoryRelease factory = IChainwallSafeFactoryRelease(safeFactory);
        address current = factory.chainwallSafeSingleton();
        if (current == newSingleton) revert ReleaseNoChange(safeFactory);
        bytes32 currentCodehash = _requireCode(current);
        if (factory.SAFE_SINGLETON_CODEHASH() != currentCodehash) {
            revert ReleaseCodehashChanged(current, factory.SAFE_SINGLETON_CODEHASH(), currentCodehash);
        }
        bytes32 newCodehash = _requireCode(newSingleton);
        bytes memory payload = abi.encodeCall(
            this._setSafeSingletonExecute, (safeFactory, current, currentCodehash, newSingleton, newCodehash)
        );
        return _queueOrExecute(safeFactory, payload);
    }

    function replaceSafeSingletonMigrator(address safeFactory, address newMigrator)
        external
        returns (bytes32 actionId)
    {
        _requireTimelockGovernor();
        IChainwallSafeFactoryRelease factory = IChainwallSafeFactoryRelease(safeFactory);
        _requireComponent(safeFactory, SAFE_FACTORY_COMPONENT_ID);
        address guard = factory.GUARD_CONTRACT();
        address module = factory.MODULE_CONTRACT();
        _requireComponent(guard, OK_GUARD_COMPONENT_ID);
        _requireComponent(module, OK_MODULE_COMPONENT_ID);
        address current = factory.SAFE_SINGLETON_MIGRATOR();
        if (
            IChainwallSafeExtensionRelease(guard).SAFE_SINGLETON_MIGRATOR() != current
                || IChainwallSafeExtensionRelease(module).SAFE_SINGLETON_MIGRATOR() != current
        ) {
            revert ReleaseSafeSingletonMigratorSetMismatch(safeFactory, guard, module);
        }
        if (current == newMigrator) revert ReleaseNoChange(safeFactory);
        bytes32 currentCodehash = _requireCode(current);
        bytes32 newCodehash = _requireCode(newMigrator);
        bytes memory payload = abi.encodeCall(
            this._replaceSafeSingletonMigratorExecute,
            (safeFactory, guard, module, current, currentCodehash, newMigrator, newCodehash)
        );
        return _queueOrExecute(safeFactory, payload);
    }

    function replaceSafeConfigurator(address safeFactory, address newConfigurator) external returns (bytes32 actionId) {
        _requireTimelockGovernor();
        IChainwallSafeFactoryRelease factory = IChainwallSafeFactoryRelease(safeFactory);
        _requireComponent(safeFactory, SAFE_FACTORY_COMPONENT_ID);
        address current = factory.CONFIGURATOR();
        if (current == newConfigurator) revert ReleaseNoChange(safeFactory);
        bytes32 currentCodehash = _requireCode(current);
        _requireComponent(newConfigurator, SAFE_CONFIGURATOR_COMPONENT_ID);
        bytes32 newCodehash = _requireCode(newConfigurator);
        bytes memory payload = abi.encodeCall(
            this._replaceSafeConfiguratorExecute, (safeFactory, current, currentCodehash, newConfigurator, newCodehash)
        );
        return _queueOrExecute(safeFactory, payload);
    }

    /// @notice Migrate one module-managed Safe after its singleton release was approved.
    /// @dev Guard-only multisig Safes use an owner-signed delegatecall to the same
    ///      migration helper; the Registry does not bypass their Safe threshold.
    function migrateSafeSingleton(address safeFactory, address safe, address newSingleton)
        external
        returns (bytes32 actionId)
    {
        _requireTimelockGovernor();
        IChainwallSafeFactoryRelease factory = IChainwallSafeFactoryRelease(safeFactory);
        _requireComponent(safeFactory, SAFE_FACTORY_COMPONENT_ID);
        if (!factory.isSafe(safe)) revert ReleaseSafeNotManaged(safeFactory, safe);
        if (!factory.isSafeSingletonMigrationTarget(newSingleton)) {
            revert ReleaseSafeSingletonNotApproved(safeFactory, newSingleton);
        }
        address module = factory.MODULE_CONTRACT();
        _requireComponent(module, OK_MODULE_COMPONENT_ID);
        address current = IProxy(safe).masterCopy();
        if (current == newSingleton) revert ReleaseNoChange(safe);
        bytes32 currentCodehash = _requireCode(current);
        bytes32 newCodehash = _requireCode(newSingleton);
        bytes memory payload = abi.encodeCall(
            this._migrateSafeSingletonExecute,
            (safeFactory, module, safe, current, currentCodehash, newSingleton, newCodehash)
        );
        return _queueOrExecute(safe, payload);
    }

    function _replaceEngineExecute(
        address target,
        bytes32 componentId,
        address expectedCurrent,
        bytes32 expectedCurrentCodehash,
        address newEngine,
        bytes32 newCodehash
    ) external {
        _requireUpgradeContext(target);
        _requireComponent(target, componentId);
        _requirePointer(target, IChainwallEngineHost(target).chainwallEngine(), expectedCurrent);
        _requireCodehash(expectedCurrent, expectedCurrentCodehash);
        _requireCodehash(newEngine, newCodehash);
        IChainwallEngineHost(target).setChainwallEngine(newEngine);
        _requirePointer(target, IChainwallEngineHost(target).chainwallEngine(), newEngine);
        _finishRuntimeChange();
        // The scoped Registry self-call holds an exclusive execution context and checks the new pointer/hash before
        // emitting.
        // forge-lint: disable-next-line(reentrancy-events)
        emit EngineReplaced(target, expectedCurrent, newEngine);
    }

    function _setAccountImplementationExecute(
        address factory,
        address expectedCurrent,
        bytes32 expectedCurrentCodehash,
        address newImplementation,
        bytes32 newCodehash
    ) external {
        _requireUpgradeContext(factory);
        _requireComponent(factory, ACCOUNT_FACTORY_COMPONENT_ID);
        IChainwallAccountFactoryRelease target = IChainwallAccountFactoryRelease(factory);
        _requirePointer(factory, target.chainwallAccountImplementation(), expectedCurrent);
        _requireCodehash(expectedCurrent, expectedCurrentCodehash);
        bytes32 recordedCurrentCodehash = target.accountImplementationCodehash();
        if (recordedCurrentCodehash != expectedCurrentCodehash) {
            revert ReleaseCodehashChanged(expectedCurrent, recordedCurrentCodehash, expectedCurrentCodehash);
        }
        _requireCodehash(newImplementation, newCodehash);
        target.setChainwallAccountImplementation(newImplementation);
        _requirePointer(factory, target.chainwallAccountImplementation(), newImplementation);
        bytes32 recordedNewCodehash = target.accountImplementationCodehash();
        if (recordedNewCodehash != newCodehash) {
            revert ReleaseCodehashChanged(newImplementation, newCodehash, recordedNewCodehash);
        }
        _finishRuntimeChange();
        // The scoped Registry self-call holds an exclusive execution context and checks the new pointer/hash before
        // emitting.
        // forge-lint: disable-next-line(reentrancy-events)
        emit AccountImplementationDefaultChanged(factory, expectedCurrent, newImplementation);
    }

    function _setAuthAccountImplementationExecute(
        address factory,
        address expectedCurrent,
        bytes32 expectedCurrentCodehash,
        address newImplementation,
        bytes32 newCodehash
    ) external {
        _requireUpgradeContext(factory);
        _requireComponent(factory, AUTH_ACCOUNT_FACTORY_COMPONENT_ID);
        IChainwallAuthAccountFactoryRelease target = IChainwallAuthAccountFactoryRelease(factory);
        _requirePointer(factory, target.chainwallAuthAccountImplementation(), expectedCurrent);
        _requireCodehash(expectedCurrent, expectedCurrentCodehash);
        bytes32 recordedCurrentCodehash = target.CHAINWALL_AUTH_ACCOUNT_IMPLEMENTATION_CODEHASH();
        if (recordedCurrentCodehash != expectedCurrentCodehash) {
            revert ReleaseCodehashChanged(expectedCurrent, recordedCurrentCodehash, expectedCurrentCodehash);
        }
        _requireCodehash(newImplementation, newCodehash);
        target.setChainwallAuthAccountImplementation(newImplementation);
        _requirePointer(factory, target.chainwallAuthAccountImplementation(), newImplementation);
        bytes32 recordedNewCodehash = target.CHAINWALL_AUTH_ACCOUNT_IMPLEMENTATION_CODEHASH();
        if (recordedNewCodehash != newCodehash) {
            revert ReleaseCodehashChanged(newImplementation, newCodehash, recordedNewCodehash);
        }
        _finishRuntimeChange();
        // The scoped Registry self-call holds an exclusive execution context and checks the new pointer/hash before
        // emitting.
        // forge-lint: disable-next-line(reentrancy-events)
        emit AuthAccountImplementationDefaultChanged(factory, expectedCurrent, newImplementation);
    }

    function _setSafeProxyFactoryExecute(
        address safeFactory,
        address expectedCurrent,
        bytes32 expectedCurrentCodehash,
        bytes32 expectedCurrentCreationCodehash,
        address newProxyFactory,
        bytes32 newCodehash,
        bytes32 creationCodehash
    ) external {
        _requireUpgradeContext(safeFactory);
        _requireComponent(safeFactory, SAFE_FACTORY_COMPONENT_ID);
        IChainwallSafeFactoryRelease target = IChainwallSafeFactoryRelease(safeFactory);
        _requirePointer(safeFactory, target.PROXY_FACTORY(), expectedCurrent);
        _requireCodehash(expectedCurrent, expectedCurrentCodehash);
        if (target.SAFE_PROXY_FACTORY_CODEHASH() != expectedCurrentCodehash) {
            revert ReleaseCodehashChanged(
                expectedCurrent, expectedCurrentCodehash, target.SAFE_PROXY_FACTORY_CODEHASH()
            );
        }
        bytes32 actualCurrentCreationCodehash = _safeProxyCreationCodehash(expectedCurrent);
        if (actualCurrentCreationCodehash != expectedCurrentCreationCodehash) {
            revert ReleaseProxyCreationCodeChanged(
                expectedCurrent, expectedCurrentCreationCodehash, actualCurrentCreationCodehash
            );
        }
        if (target.SAFE_PROXY_CREATION_CODEHASH() != expectedCurrentCreationCodehash) {
            revert ReleaseProxyCreationCodeChanged(
                expectedCurrent, expectedCurrentCreationCodehash, target.SAFE_PROXY_CREATION_CODEHASH()
            );
        }
        _requireCodehash(newProxyFactory, newCodehash);
        bytes32 actualCreationCodehash = _safeProxyCreationCodehash(newProxyFactory);
        if (actualCreationCodehash != creationCodehash) {
            revert ReleaseProxyCreationCodeChanged(newProxyFactory, creationCodehash, actualCreationCodehash);
        }
        target.setChainwallSafeProxyFactory(newProxyFactory, creationCodehash);
        _requirePointer(safeFactory, target.PROXY_FACTORY(), newProxyFactory);
        if (target.SAFE_PROXY_FACTORY_CODEHASH() != newCodehash) {
            revert ReleaseCodehashChanged(newProxyFactory, newCodehash, target.SAFE_PROXY_FACTORY_CODEHASH());
        }
        if (target.SAFE_PROXY_CREATION_CODEHASH() != creationCodehash) {
            revert ReleaseProxyCreationCodeChanged(
                newProxyFactory, creationCodehash, target.SAFE_PROXY_CREATION_CODEHASH()
            );
        }
        _finishRuntimeChange();
        // The scoped Registry self-call holds an exclusive execution context and checks the new pointer/hash before
        // emitting.
        // forge-lint: disable-next-line(reentrancy-events)
        emit SafeProxyFactoryDefaultChanged(safeFactory, expectedCurrent, newProxyFactory);
    }

    function _setSafeSingletonExecute(
        address safeFactory,
        address expectedCurrent,
        bytes32 expectedCurrentCodehash,
        address newSingleton,
        bytes32 newCodehash
    ) external {
        _requireUpgradeContext(safeFactory);
        _requireComponent(safeFactory, SAFE_FACTORY_COMPONENT_ID);
        IChainwallSafeFactoryRelease target = IChainwallSafeFactoryRelease(safeFactory);
        _requirePointer(safeFactory, target.chainwallSafeSingleton(), expectedCurrent);
        _requireCodehash(expectedCurrent, expectedCurrentCodehash);
        if (target.SAFE_SINGLETON_CODEHASH() != expectedCurrentCodehash) {
            revert ReleaseCodehashChanged(expectedCurrent, expectedCurrentCodehash, target.SAFE_SINGLETON_CODEHASH());
        }
        _requireCodehash(newSingleton, newCodehash);
        target.setChainwallSafeSingleton(newSingleton);
        _requirePointer(safeFactory, target.chainwallSafeSingleton(), newSingleton);
        if (target.SAFE_SINGLETON_CODEHASH() != newCodehash) {
            revert ReleaseCodehashChanged(newSingleton, newCodehash, target.SAFE_SINGLETON_CODEHASH());
        }
        if (!target.isSafeSingletonMigrationTarget(newSingleton)) {
            revert ReleaseSafeSingletonNotApproved(safeFactory, newSingleton);
        }
        _finishRuntimeChange();
        // The scoped Registry self-call holds an exclusive execution context and checks the new pointer/hash before
        // emitting.
        // forge-lint: disable-next-line(reentrancy-events)
        emit SafeSingletonDefaultChanged(safeFactory, expectedCurrent, newSingleton);
    }

    function _replaceSafeSingletonMigratorExecute(
        address safeFactory,
        address guard,
        address module,
        address expectedCurrent,
        bytes32 expectedCurrentCodehash,
        address newMigrator,
        bytes32 newCodehash
    ) external {
        _requireUpgradeContext(safeFactory);
        IChainwallSafeFactoryRelease factory = IChainwallSafeFactoryRelease(safeFactory);
        _requireComponent(safeFactory, SAFE_FACTORY_COMPONENT_ID);
        _requireComponent(guard, OK_GUARD_COMPONENT_ID);
        _requireComponent(module, OK_MODULE_COMPONENT_ID);
        if (factory.GUARD_CONTRACT() != guard || factory.MODULE_CONTRACT() != module) {
            revert ReleaseSafeSingletonMigratorSetMismatch(safeFactory, guard, module);
        }
        _requirePointer(safeFactory, factory.SAFE_SINGLETON_MIGRATOR(), expectedCurrent);
        _requirePointer(guard, IChainwallSafeExtensionRelease(guard).SAFE_SINGLETON_MIGRATOR(), expectedCurrent);
        _requirePointer(module, IChainwallSafeExtensionRelease(module).SAFE_SINGLETON_MIGRATOR(), expectedCurrent);
        _requireCodehash(expectedCurrent, expectedCurrentCodehash);
        _requireCodehash(newMigrator, newCodehash);

        factory.setChainwallSafeSingletonMigrator(newMigrator);
        IChainwallSafeExtensionRelease(guard).setSafeSingletonMigrator(newMigrator);
        IChainwallSafeExtensionRelease(module).setSafeSingletonMigrator(newMigrator);

        _requirePointer(safeFactory, factory.SAFE_SINGLETON_MIGRATOR(), newMigrator);
        _requirePointer(guard, IChainwallSafeExtensionRelease(guard).SAFE_SINGLETON_MIGRATOR(), newMigrator);
        _requirePointer(module, IChainwallSafeExtensionRelease(module).SAFE_SINGLETON_MIGRATOR(), newMigrator);
        _finishRuntimeChange();
        // The scoped Registry self-call holds an exclusive execution context and checks the new pointer/hash before
        // emitting.
        // forge-lint: disable-next-line(reentrancy-events)
        emit SafeSingletonMigratorReplaced(safeFactory, expectedCurrent, newMigrator);
    }

    function _replaceSafeConfiguratorExecute(
        address safeFactory,
        address expectedCurrent,
        bytes32 expectedCurrentCodehash,
        address newConfigurator,
        bytes32 newCodehash
    ) external {
        _requireUpgradeContext(safeFactory);
        IChainwallSafeFactoryRelease factory = IChainwallSafeFactoryRelease(safeFactory);
        _requireComponent(safeFactory, SAFE_FACTORY_COMPONENT_ID);
        _requirePointer(safeFactory, factory.CONFIGURATOR(), expectedCurrent);
        _requireCodehash(expectedCurrent, expectedCurrentCodehash);
        _requireComponent(newConfigurator, SAFE_CONFIGURATOR_COMPONENT_ID);
        _requireCodehash(newConfigurator, newCodehash);
        factory.setChainwallConfigurator(newConfigurator);
        _requirePointer(safeFactory, factory.CONFIGURATOR(), newConfigurator);
        _finishRuntimeChange();
        // The scoped Registry self-call holds an exclusive execution context and checks the new pointer/hash before
        // emitting.
        // forge-lint: disable-next-line(reentrancy-events)
        emit SafeConfiguratorReplaced(safeFactory, expectedCurrent, newConfigurator);
    }

    function _migrateSafeSingletonExecute(
        address safeFactory,
        address module,
        address safe,
        address expectedCurrent,
        bytes32 expectedCurrentCodehash,
        address newSingleton,
        bytes32 newCodehash
    ) external {
        _requireUpgradeContext(safe);
        IChainwallSafeFactoryRelease factory = IChainwallSafeFactoryRelease(safeFactory);
        _requireComponent(safeFactory, SAFE_FACTORY_COMPONENT_ID);
        _requireComponent(module, OK_MODULE_COMPONENT_ID);
        if (factory.MODULE_CONTRACT() != module || !factory.isSafe(safe)) {
            revert ReleaseSafeNotManaged(safeFactory, safe);
        }
        if (!factory.isSafeSingletonMigrationTarget(newSingleton)) {
            revert ReleaseSafeSingletonNotApproved(safeFactory, newSingleton);
        }
        address current = IProxy(safe).masterCopy();
        if (current != expectedCurrent) revert ReleaseSafeSingletonChanged(safe, expectedCurrent, current);
        _requireCodehash(expectedCurrent, expectedCurrentCodehash);
        _requireCodehash(newSingleton, newCodehash);
        IChainwallSafeModuleMigration(module).migrateSafeSingleton(safeFactory, safe, newSingleton, newCodehash);
        address actual = IProxy(safe).masterCopy();
        if (actual != newSingleton) revert ReleaseSafeSingletonChanged(safe, newSingleton, actual);
        _finishRuntimeChange();
        // The scoped Registry self-call holds an exclusive execution context and checks the new pointer/hash before
        // emitting.
        // forge-lint: disable-next-line(reentrancy-events)
        emit SafeSingletonMigrated(safeFactory, safe, expectedCurrent, newSingleton);
    }

    function _queueOrExecute(address target, bytes memory payload) private returns (bytes32 actionId) {
        (bool executing, bytes32 queuedId) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryContract(),
                scope: _upgradeScopeKey(target),
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            payload
        );
        if (!executing) return queuedId;
        // Immediate actions use the exact replay selector and context checks as
        // delayed actions; only the queue wait is omitted.
        ExecutionContextLib.enter(bytes32(0), _msgSenderD(), TimelockLib.categoryContract(), _upgradeScopeKey(target));
        (bool success, bytes memory reason) = address(this).call(payload);
        if (!success) _revertBytes(reason);
        ExecutionContextLib.exit();
    }

    function _finishRuntimeChange() private {
        ExecutionCatalogStorage.bumpRuntime();
        TimelockLib.bumpActionSemanticsGeneration();
    }

    function _readComponentId(address target) private view returns (bytes32 componentId) {
        if (target.code.length == 0) revert ReleaseTargetInvalid(target);
        try IChainwallUpgradeable(target).chainwallComponentId() returns (bytes32 value) {
            componentId = value;
        } catch {
            revert ReleaseTargetInvalid(target);
        }
    }

    function _requireComponent(address target, bytes32 expected) private view {
        bytes32 actual = _readComponentId(target);
        if (actual != expected) revert ReleaseComponentInvalid(target, expected, actual);
    }

    function _requirePointer(address target, address actual, address expected) private pure {
        if (actual != expected) revert ReleasePointerChanged(target, expected, actual);
    }

    function _requireCode(address target) private view returns (bytes32 codehash_) {
        if (target.code.length == 0) revert ReleaseTargetInvalid(target);
        codehash_ = target.codehash;
    }

    function _requireCodehash(address target, bytes32 expected) private view {
        bytes32 actual = _requireCode(target);
        if (actual != expected) revert ReleaseCodehashChanged(target, expected, actual);
    }

    function _safeProxyCreationCodehash(address proxyFactory) private pure returns (bytes32) {
        bytes memory creationCode;
        try SafeProxyFactory(proxyFactory).proxyCreationCode() returns (bytes memory value) {
            creationCode = value;
        } catch {
            revert ReleaseTargetInvalid(proxyFactory);
        }
        if (creationCode.length == 0) revert ReleaseTargetInvalid(proxyFactory);
        bytes32 codehash_;
        assembly ("memory-safe") {
            codehash_ := keccak256(add(creationCode, 0x20), mload(creationCode))
        }
        return codehash_;
    }

    function _revertBytes(bytes memory reason) private pure {
        assembly ("memory-safe") {
            revert(add(reason, 0x20), mload(reason))
        }
    }
}
