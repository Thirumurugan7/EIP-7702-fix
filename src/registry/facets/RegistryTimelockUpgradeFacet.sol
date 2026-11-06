// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "../../Delegation7702.sol";
import {IChainwallUpgradeable} from "../../ChainwallUpgradeable.sol";
import {
    ExecutionContextLib,
    TimelockActionStatus,
    TimelockLib,
    TimelockRequest,
    TimelockStorage
} from "../../registry/TimelockLib.sol";
import {RegistryTransitionGuard} from "../RegistryTransitionGuard.sol";
import {RegistryTimelockReleaseFacet} from "./RegistryTimelockReleaseFacet.sol";
import {RegistryUpgradeFacetBase} from "./RegistryUpgradeFacetBase.sol";

/// @notice Exact implementation transition committed into a timelock payload.
/// @dev Binds both ends of the transition and their runtime code hashes.
struct ComponentUpgrade {
    address expectedCurrentImplementation;
    bytes32 expectedCurrentCodehash;
    address newImplementation;
    bytes32 newImplementationCodehash;
    bytes32 expectedBindingsHash;
}

interface IDiamondUpgrade {
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;
}

/// @title RegistryTimelockUpgradeFacet
/// @notice Registry-timelocked implementation upgrades for stable tenant identities.
contract RegistryTimelockUpgradeFacet is RegistryUpgradeFacetBase {
    uint256 public constant VERSION = 3;

    bytes32 private constant DIAMOND_SCOPE = keccak256("diamond.cut");
    bytes32 private constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    uint256 private constant UPGRADE_PROTOCOL_VERSION = 1;

    bytes32 private constant REGISTRY_COMPONENT_ID = keccak256("Chainwall.Registry");
    bytes32 private constant INTERACT_COMPONENT_ID = keccak256("Chainwall.Interact");
    bytes32 private constant MINISCRIPT_COMPONENT_ID = keccak256("Chainwall.MiniScript");
    bytes32 private constant AUTH_ACCOUNT_FACTORY_COMPONENT_ID = keccak256("Chainwall.WebAuthnAuthAccountFactory");
    bytes32 private constant AUTH_ACCOUNT_COMPONENT_ID = keccak256("Chainwall.WebAuthnAuthAccount");
    bytes32 private constant SAFE_FACTORY_COMPONENT_ID = keccak256("Chainwall.SafeFactory");
    bytes32 private constant ACCOUNT_FACTORY_COMPONENT_ID = keccak256("Chainwall.AccountFactory");
    bytes32 private constant OK_ACCOUNT_COMPONENT_ID = keccak256("Chainwall.OKAccount");
    bytes32 private constant OK_GUARD_COMPONENT_ID = keccak256("Chainwall.OKGuard");
    bytes32 private constant OK_MODULE_COMPONENT_ID = keccak256("Chainwall.OKModule");

    error TimelockActionUnknown(bytes32 actionId);
    error UpgradeTargetInvalid(address target);
    error UpgradeImplementationInvalid(address implementation);
    error UpgradeImplementationUnchanged(address implementation);
    error UpgradeIntrospectionFailed(address target);
    error UpgradeComponentMismatch(address target, bytes32 expected, bytes32 actual);
    error UpgradeProtocolMismatch(address target, uint256 expected, uint256 actual);
    error UpgradeCurrentImplementationChanged(address expected, address actual);
    error UpgradeCodehashChanged(address target, bytes32 expected, bytes32 actual);
    error UpgradeBindingsChanged(address target, bytes32 expected, bytes32 actual);
    error UpgradeSuccessorPathFailed(address target);
    error UpgradeDirectSurfaceEnabled(address target);
    error UpgradeAccountExecutionShapeInvalid(address target, bytes4 selector);
    error RegistryUpgradeDataNotEmpty();

    event ComponentUpgraded(
        address indexed target,
        bytes32 indexed componentId,
        address indexed previousImplementation,
        address newImplementation,
        bytes32 newImplementationCodehash
    );

    function upgradeRegistry(address newImplementation, bytes calldata data) external returns (bytes32 actionId) {
        _requireRegistryUpgradeDataEmpty(data);
        _requireTimelockGovernor();
        ComponentUpgrade memory upgrade = _snapshotUpgrade(address(this), newImplementation, REGISTRY_COMPONENT_ID);
        bytes memory payload = abi.encodeCall(this._upgradeRegistryExecute, (upgrade, data));
        (bool executing, bytes32 queuedId) = TimelockLib.enforceOrQueue(
            TimelockRequest({
                category: TimelockLib.categoryDiamond(),
                scope: DIAMOND_SCOPE,
                policyId: bytes32(0),
                delay: 0,
                gracePeriod: 0
            }),
            payload
        );
        if (!executing) return queuedId;
        _executeImmediatePayload(payload, TimelockLib.categoryDiamond(), DIAMOND_SCOPE);
    }

    function upgradeInteract(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32)
    {
        return _queueComponentUpgrade(
            target, newImplementation, data, INTERACT_COMPONENT_ID, this._upgradeInteractExecute.selector
        );
    }

    function upgradeMiniScript(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32)
    {
        return _queueComponentUpgrade(
            target, newImplementation, data, MINISCRIPT_COMPONENT_ID, this._upgradeMiniScriptExecute.selector
        );
    }

    function upgradeAuthAccountFactory(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32)
    {
        return _queueComponentUpgrade(
            target,
            newImplementation,
            data,
            AUTH_ACCOUNT_FACTORY_COMPONENT_ID,
            this._upgradeAuthAccountFactoryExecute.selector
        );
    }

    function upgradeAuthAccount(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32)
    {
        return _queueComponentUpgrade(
            target, newImplementation, data, AUTH_ACCOUNT_COMPONENT_ID, this._upgradeAuthAccountExecute.selector
        );
    }

    function upgradeSafeFactory(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32)
    {
        return _queueComponentUpgrade(
            target, newImplementation, data, SAFE_FACTORY_COMPONENT_ID, this._upgradeSafeFactoryExecute.selector
        );
    }

    function upgradeAccountFactory(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32)
    {
        return _queueComponentUpgrade(
            target, newImplementation, data, ACCOUNT_FACTORY_COMPONENT_ID, this._upgradeAccountFactoryExecute.selector
        );
    }

    function upgradeOkAccount(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32)
    {
        return _queueComponentUpgrade(
            target, newImplementation, data, OK_ACCOUNT_COMPONENT_ID, this._upgradeOkAccountExecute.selector
        );
    }

    function upgradeOkGuard(address target, address newImplementation, bytes calldata data) external returns (bytes32) {
        return _queueComponentUpgrade(
            target, newImplementation, data, OK_GUARD_COMPONENT_ID, this._upgradeOkGuardExecute.selector
        );
    }

    function upgradeOkModule(address target, address newImplementation, bytes calldata data)
        external
        returns (bytes32)
    {
        return _queueComponentUpgrade(
            target, newImplementation, data, OK_MODULE_COMPONENT_ID, this._upgradeOkModuleExecute.selector
        );
    }

    /// @notice Return the codehash committed for a queued implementation upgrade.
    function getActionUpgradeCodeHash(bytes32 actionId) external view returns (bytes32) {
        TimelockStorage.Action memory action = TimelockLib.action(actionId);
        if (action.status == TimelockActionStatus.None) revert TimelockActionUnknown(actionId);

        bytes memory payload = TimelockLib.payload(actionId);
        bytes4 selector = _payloadSelector(payload);
        if (selector == this._upgradeRegistryExecute.selector) return _payloadWord(payload, 3);
        if (_isComponentExecuteSelector(selector)) return _payloadWord(payload, 4);
        if (selector == RegistryTimelockReleaseFacet._replaceEngineExecute.selector) {
            return _payloadWord(payload, 5);
        }
        if (
            selector == RegistryTimelockReleaseFacet._setAccountImplementationExecute.selector
                || selector == RegistryTimelockReleaseFacet._setAuthAccountImplementationExecute.selector
                || selector == RegistryTimelockReleaseFacet._setSafeSingletonExecute.selector
                || selector == RegistryTimelockReleaseFacet._replaceSafeConfiguratorExecute.selector
        ) {
            return _payloadWord(payload, 4);
        }
        if (selector == RegistryTimelockReleaseFacet._setSafeProxyFactoryExecute.selector) {
            return _payloadWord(payload, 5);
        }
        if (
            selector == RegistryTimelockReleaseFacet._replaceSafeSingletonMigratorExecute.selector
                || selector == RegistryTimelockReleaseFacet._migrateSafeSingletonExecute.selector
        ) {
            return _payloadWord(payload, 6);
        }
        return bytes32(0);
    }

    function _upgradeRegistryExecute(ComponentUpgrade calldata upgrade, bytes calldata data) external {
        _requireRegistryUpgradeDataEmpty(data);
        if (!ExecutionContextLib.isActive()) revert TimelockContextRequired();
        ExecutionContextLib.ensure(TimelockLib.categoryDiamond(), DIAMOND_SCOPE);
        _requireTimelockGovernor();
        _performRegistryUpgrade(upgrade, data);
    }

    function _upgradeInteractExecute(address target, ComponentUpgrade calldata upgrade, bytes calldata data) external {
        _executeComponentUpgrade(target, upgrade, data, INTERACT_COMPONENT_ID);
    }

    function _upgradeMiniScriptExecute(address target, ComponentUpgrade calldata upgrade, bytes calldata data)
        external
    {
        _executeComponentUpgrade(target, upgrade, data, MINISCRIPT_COMPONENT_ID);
    }

    function _upgradeAuthAccountFactoryExecute(address target, ComponentUpgrade calldata upgrade, bytes calldata data)
        external
    {
        _executeComponentUpgrade(target, upgrade, data, AUTH_ACCOUNT_FACTORY_COMPONENT_ID);
    }

    function _upgradeAuthAccountExecute(address target, ComponentUpgrade calldata upgrade, bytes calldata data)
        external
    {
        _executeComponentUpgrade(target, upgrade, data, AUTH_ACCOUNT_COMPONENT_ID);
    }

    function _upgradeSafeFactoryExecute(address target, ComponentUpgrade calldata upgrade, bytes calldata data)
        external
    {
        _executeComponentUpgrade(target, upgrade, data, SAFE_FACTORY_COMPONENT_ID);
    }

    function _upgradeAccountFactoryExecute(address target, ComponentUpgrade calldata upgrade, bytes calldata data)
        external
    {
        _executeComponentUpgrade(target, upgrade, data, ACCOUNT_FACTORY_COMPONENT_ID);
    }

    function _upgradeOkAccountExecute(address target, ComponentUpgrade calldata upgrade, bytes calldata data) external {
        _executeComponentUpgrade(target, upgrade, data, OK_ACCOUNT_COMPONENT_ID);
    }

    function _upgradeOkGuardExecute(address target, ComponentUpgrade calldata upgrade, bytes calldata data) external {
        _executeComponentUpgrade(target, upgrade, data, OK_GUARD_COMPONENT_ID);
    }

    function _upgradeOkModuleExecute(address target, ComponentUpgrade calldata upgrade, bytes calldata data) external {
        _executeComponentUpgrade(target, upgrade, data, OK_MODULE_COMPONENT_ID);
    }

    function _queueComponentUpgrade(
        address target,
        address newImplementation,
        bytes calldata data,
        bytes32 componentId,
        bytes4 executeSelector
    ) private returns (bytes32 actionId) {
        _requireTimelockGovernor();
        ComponentUpgrade memory upgrade = _snapshotUpgrade(target, newImplementation, componentId);
        bytes memory payload = abi.encodeWithSelector(executeSelector, target, upgrade, data);
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
        _executeImmediatePayload(payload, TimelockLib.categoryContract(), _upgradeScopeKey(target));
    }

    function _executeComponentUpgrade(
        address target,
        ComponentUpgrade calldata upgrade,
        bytes calldata data,
        bytes32 componentId
    ) private {
        _requireUpgradeContext(target);
        _performComponentUpgrade(target, upgrade, data, componentId);
    }

    function _performComponentUpgrade(
        address target,
        ComponentUpgrade memory upgrade,
        bytes calldata data,
        bytes32 componentId
    ) private {
        RegistryTransitionGuard.Snapshot memory transitionBefore = RegistryTransitionGuard.snapshot();
        _validateUpgrade(target, upgrade, componentId);
        IChainwallUpgradeable(target).timelockUpgrade(upgrade.newImplementation, data);
        _requireCurrentImplementation(target, upgrade.newImplementation, upgrade.newImplementationCodehash);
        _requireComponent(target, componentId);
        _requireBindings(target, upgrade.expectedBindingsHash);
        if (componentId == AUTH_ACCOUNT_COMPONENT_ID) {
            _requireAuthAccountExecutionShape(target);
        } else {
            _requireComponentSuccessorPath(target, upgrade, componentId);
        }
        _requireDirectComponentUpgradeDisabled(target, upgrade.newImplementation);
        RegistryTransitionGuard.advanceFrom(transitionBefore);
        // The scoped upgrade holds an exclusive execution context and verifies implementation and security bindings
        // before emitting.
        // forge-lint: disable-start(reentrancy-events)
        emit ComponentUpgraded(
            target,
            componentId,
            upgrade.expectedCurrentImplementation,
            upgrade.newImplementation,
            upgrade.newImplementationCodehash
        );
        // forge-lint: disable-end(reentrancy-events)
    }

    function _performRegistryUpgrade(ComponentUpgrade memory upgrade, bytes calldata data) private {
        RegistryTransitionGuard.Snapshot memory transitionBefore = RegistryTransitionGuard.snapshot();
        _validateUpgrade(address(this), upgrade, REGISTRY_COMPONENT_ID);
        IDiamondUpgrade(address(this)).upgradeToAndCall(upgrade.newImplementation, data);
        _requireCurrentImplementation(address(this), upgrade.newImplementation, upgrade.newImplementationCodehash);
        _requireComponent(address(this), REGISTRY_COMPONENT_ID);
        _requireBindings(address(this), upgrade.expectedBindingsHash);
        _requireTimelockGovernor();
        _onlyRoleD(UPGRADER_ROLE);
        _requireRegistrySuccessorPath(upgrade);
        RegistryTransitionGuard.advanceFrom(transitionBefore);
        // The scoped upgrade holds an exclusive execution context and verifies implementation and security bindings
        // before emitting.
        // forge-lint: disable-start(reentrancy-events)
        emit ComponentUpgraded(
            address(this),
            REGISTRY_COMPONENT_ID,
            upgrade.expectedCurrentImplementation,
            upgrade.newImplementation,
            upgrade.newImplementationCodehash
        );
        // forge-lint: disable-end(reentrancy-events)
    }

    function _executeImmediatePayload(bytes memory payload, bytes32 category, bytes32 scope) private {
        ExecutionContextLib.enter(bytes32(0), _msgSenderD(), category, scope);
        (bool success, bytes memory reason) = address(this).call(payload);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(reason, 0x20), mload(reason))
            }
        }
        ExecutionContextLib.exit();
    }

    /// @dev Registry implementation changes are code-only in production v1. Storage changes require a separately
    ///      decoded, versioned timelock action with postconditions for the exact state transition.
    function _requireRegistryUpgradeDataEmpty(bytes calldata data) private pure {
        if (data.length != 0) revert RegistryUpgradeDataNotEmpty();
    }

    function _snapshotUpgrade(address target, address newImplementation, bytes32 componentId)
        private
        view
        returns (ComponentUpgrade memory upgrade)
    {
        if (!Delegation7702.hasContractCode(target)) revert UpgradeTargetInvalid(target);
        if (!Delegation7702.hasContractCode(newImplementation)) revert UpgradeImplementationInvalid(newImplementation);
        _requireComponent(target, componentId);
        _requireComponent(newImplementation, componentId);
        address current = _readCurrentImplementation(target);
        if (current == newImplementation) revert UpgradeImplementationUnchanged(newImplementation);
        upgrade = ComponentUpgrade({
            expectedCurrentImplementation: current,
            expectedCurrentCodehash: current.codehash,
            newImplementation: newImplementation,
            newImplementationCodehash: newImplementation.codehash,
            expectedBindingsHash: _readBindingsHash(target)
        });
    }

    function _validateUpgrade(address target, ComponentUpgrade memory upgrade, bytes32 componentId) private view {
        _requireCurrentImplementation(target, upgrade.expectedCurrentImplementation, upgrade.expectedCurrentCodehash);
        _requireCodehash(upgrade.newImplementation, upgrade.newImplementationCodehash);
        _requireComponent(target, componentId);
        _requireComponent(upgrade.newImplementation, componentId);
        _requireBindings(target, upgrade.expectedBindingsHash);
    }

    function _requireComponent(address target, bytes32 expected) private view {
        bytes32 actual = bytes32(0);
        try IChainwallUpgradeable(target).chainwallComponentId() returns (bytes32 value) {
            actual = value;
        } catch {
            revert UpgradeIntrospectionFailed(target);
        }
        if (actual != expected) revert UpgradeComponentMismatch(target, expected, actual);

        uint256 protocolVersion = 0;
        try IChainwallUpgradeable(target).chainwallUpgradeProtocolVersion() returns (uint256 value) {
            protocolVersion = value;
        } catch {
            revert UpgradeIntrospectionFailed(target);
        }
        if (protocolVersion != UPGRADE_PROTOCOL_VERSION) {
            revert UpgradeProtocolMismatch(target, UPGRADE_PROTOCOL_VERSION, protocolVersion);
        }
        _readBindingsHash(target);
    }

    function _readCurrentImplementation(address target) private view returns (address implementation) {
        try IChainwallUpgradeable(target).chainwallImplementation() returns (address value) {
            implementation = value;
        } catch {
            revert UpgradeIntrospectionFailed(target);
        }
        if (!Delegation7702.hasContractCode(implementation)) revert UpgradeImplementationInvalid(implementation);
    }

    function _requireCurrentImplementation(address target, address expected, bytes32 expectedCodehash) private view {
        address actual = _readCurrentImplementation(target);
        if (actual != expected) revert UpgradeCurrentImplementationChanged(expected, actual);
        _requireCodehash(actual, expectedCodehash);
        bytes32 reported = bytes32(0);
        try IChainwallUpgradeable(target).chainwallImplementationCodehash() returns (bytes32 value) {
            reported = value;
        } catch {
            revert UpgradeIntrospectionFailed(target);
        }
        if (reported != expectedCodehash) revert UpgradeCodehashChanged(target, expectedCodehash, reported);
    }

    function _requireCodehash(address target, bytes32 expected) private view {
        if (!Delegation7702.hasContractCode(target)) revert UpgradeImplementationInvalid(target);
        bytes32 actual = target.codehash;
        if (actual != expected) revert UpgradeCodehashChanged(target, expected, actual);
    }

    function _readBindingsHash(address target) private view returns (bytes32 bindingsHash) {
        try IChainwallUpgradeable(target).chainwallSecurityBindingsHash() returns (bytes32 value) {
            bindingsHash = value;
        } catch {
            revert UpgradeIntrospectionFailed(target);
        }
    }

    function _requireBindings(address target, bytes32 expected) private view {
        bytes32 actual = _readBindingsHash(target);
        if (actual != expected) revert UpgradeBindingsChanged(target, expected, actual);
    }

    /// @dev Round-trip through the previous reviewed implementation and back to the candidate. This proves the
    ///      candidate can exercise a real Registry-only rollback path in the proxy's storage context, rather than
    ///      merely accepting a no-op upgrade to itself.
    function _requireComponentSuccessorPath(address target, ComponentUpgrade memory upgrade, bytes32 componentId)
        private
    {
        try IChainwallUpgradeable(target).timelockUpgrade(upgrade.expectedCurrentImplementation, bytes("")) {}
        catch {
            revert UpgradeSuccessorPathFailed(target);
        }
        _requireCurrentImplementation(target, upgrade.expectedCurrentImplementation, upgrade.expectedCurrentCodehash);
        _requireComponent(target, componentId);
        _requireBindings(target, upgrade.expectedBindingsHash);

        try IChainwallUpgradeable(target).timelockUpgrade(upgrade.newImplementation, bytes("")) {}
        catch {
            revert UpgradeSuccessorPathFailed(target);
        }
        _requireCurrentImplementation(target, upgrade.newImplementation, upgrade.newImplementationCodehash);
        _requireComponent(target, componentId);
        _requireBindings(target, upgrade.expectedBindingsHash);
    }

    /// @dev The Registry dispatcher necessarily retains `upgradeToAndCall`. Round-trip through the previous reviewed
    ///      implementation while the exact diamond execution context remains active, then restore the candidate.
    function _requireRegistrySuccessorPath(ComponentUpgrade memory upgrade) private {
        try IDiamondUpgrade(address(this)).upgradeToAndCall(upgrade.expectedCurrentImplementation, bytes("")) {}
        catch {
            revert UpgradeSuccessorPathFailed(address(this));
        }
        _requireCurrentImplementation(
            address(this), upgrade.expectedCurrentImplementation, upgrade.expectedCurrentCodehash
        );
        _requireComponent(address(this), REGISTRY_COMPONENT_ID);
        _requireBindings(address(this), upgrade.expectedBindingsHash);
        _requireTimelockGovernor();
        _onlyRoleD(UPGRADER_ROLE);

        try IDiamondUpgrade(address(this)).upgradeToAndCall(upgrade.newImplementation, bytes("")) {}
        catch {
            revert UpgradeSuccessorPathFailed(address(this));
        }
        _requireCurrentImplementation(address(this), upgrade.newImplementation, upgrade.newImplementationCodehash);
        _requireComponent(address(this), REGISTRY_COMPONENT_ID);
        _requireBindings(address(this), upgrade.expectedBindingsHash);
        _requireTimelockGovernor();
        _onlyRoleD(UPGRADER_ROLE);
    }

    /// @dev Tenant components must expose only the Registry-specific upgrade route. A successful ordinary UUPS call
    ///      is an alternate authority surface and rolls back the entire candidate transition.
    function _requireDirectComponentUpgradeDisabled(address target, address implementation) private {
        (bool enabled,) = target.call(abi.encodeCall(IDiamondUpgrade.upgradeToAndCall, (implementation, bytes(""))));
        if (enabled) revert UpgradeDirectSurfaceEnabled(target);
    }

    /// @dev AuthAccount recovery lives in its permanent dispatcher. Exercise critical delegated views after installing
    ///      candidate logic so a nested proxy or non-account implementation cannot pass direct self-attestation and
    ///      then recurse or fail when reached through the dispatcher.
    function _requireAuthAccountExecutionShape(address target) private view {
        // ABI selectors are the leading four keccak256 bytes.
        // forge-lint: disable-next-line(unsafe-typecast)
        _requireWordResult(target, bytes4(keccak256("registry()")));
        // ABI selectors are the leading four keccak256 bytes.
        // forge-lint: disable-next-line(unsafe-typecast)
        _requireWordResult(target, bytes4(keccak256("interact()")));
        // ABI selectors are the leading four keccak256 bytes.
        // forge-lint: disable-next-line(unsafe-typecast)
        _requireWordResult(target, bytes4(keccak256("factory()")));
        // ABI selectors are the leading four keccak256 bytes.
        // forge-lint: disable-next-line(unsafe-typecast)
        _requireWordResult(target, bytes4(keccak256("entryPoint()")));
        // ABI selectors are the leading four keccak256 bytes.
        // forge-lint: disable-next-line(unsafe-typecast)
        _requireWordResult(target, bytes4(keccak256("activeCredentialCount()")));
    }

    function _requireWordResult(address target, bytes4 selector) private view {
        (bool ok, bytes memory result) = target.staticcall(abi.encodeWithSelector(selector));
        if (!ok || result.length != 32) revert UpgradeAccountExecutionShapeInvalid(target, selector);
    }

    function _isComponentExecuteSelector(bytes4 selector) private pure returns (bool) {
        return selector == RegistryTimelockUpgradeFacet._upgradeInteractExecute.selector
            || selector == RegistryTimelockUpgradeFacet._upgradeMiniScriptExecute.selector
            || selector == RegistryTimelockUpgradeFacet._upgradeAuthAccountFactoryExecute.selector
            || selector == RegistryTimelockUpgradeFacet._upgradeAuthAccountExecute.selector
            || selector == RegistryTimelockUpgradeFacet._upgradeSafeFactoryExecute.selector
            || selector == RegistryTimelockUpgradeFacet._upgradeAccountFactoryExecute.selector
            || selector == RegistryTimelockUpgradeFacet._upgradeOkAccountExecute.selector
            || selector == RegistryTimelockUpgradeFacet._upgradeOkGuardExecute.selector
            || selector == RegistryTimelockUpgradeFacet._upgradeOkModuleExecute.selector;
    }

    function _payloadSelector(bytes memory payload) private pure returns (bytes4 selector) {
        if (payload.length < 4) return bytes4(0);
        assembly ("memory-safe") {
            selector := mload(add(payload, 0x20))
        }
    }

    function _payloadWord(bytes memory payload, uint256 wordIndex) private pure returns (bytes32 word) {
        uint256 offset = 4 + (wordIndex + 1) * 32;
        if (payload.length < offset) return bytes32(0);
        assembly ("memory-safe") {
            word := mload(add(add(payload, 0x24), mul(wordIndex, 0x20)))
        }
    }
}
