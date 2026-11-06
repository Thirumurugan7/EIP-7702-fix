// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "./Delegation7702.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

import {ChainwallUpgradeHash} from "./ChainwallUpgradeable.sol";

interface IWebAuthnAuthAccountProxyFactory {
    function IMPLEMENTATION() external view returns (address);
    function REGISTRY() external view returns (address);
    function isAuthAccountImplementationApproved(address implementation) external view returns (bool);
}

interface IWebAuthnAuthAccountImplementation {
    function chainwallComponentId() external pure returns (bytes32);
    function chainwallUpgradeProtocolVersion() external pure returns (uint256);
}

/// @notice Namespaced state owned by the stable AuthAccount proxy rather than delegated account logic.
library WebAuthnAuthAccountProxyStorage {
    bytes32 internal constant FACTORY_SLOT = keccak256("chainwall.webauthn-auth-account.proxy.factory.v1");
    bytes32 internal constant AUTHORIZATION_REVISION_SLOT =
        keccak256("chainwall.webauthn-auth-account.proxy.authorization-revision.v1");
    bytes32 internal constant INITIAL_REVISION_DOMAIN =
        keccak256("ChainwallWebAuthnAuthAccountAuthorizationRevisionV1");

    function factory() internal view returns (address value) {
        bytes32 slot = FACTORY_SLOT;
        assembly ("memory-safe") {
            value := sload(slot)
        }
    }

    function authorizationRevision() internal view returns (bytes32 value) {
        bytes32 slot = AUTHORIZATION_REVISION_SLOT;
        assembly ("memory-safe") {
            value := sload(slot)
        }
        if (value == bytes32(0)) {
            address factory_ = factory();
            if (factory_ != address(0)) value = keccak256(abi.encode(INITIAL_REVISION_DOMAIN, factory_));
        }
    }
}

/// @dev Stable prefix of delegated AuthAccount storage. The dispatcher reads
///      only these security bindings; implementations may append state but may
///      not reorder this prefix without failing the post-upgrade binding check.
library WebAuthnAuthAccountStateStorage {
    struct Layout {
        address entryPoint;
        bytes32 rpIdHash;
        uint256 nextNonce;
        string origin;
    }

    function getLayout() internal pure returns (Layout storage l) {
        assembly ("memory-safe") {
            l.slot := 0
        }
    }
}

/// @title WebAuthnAuthAccountProxy
/// @notice Stable deterministic shell for a tenant WebAuthn protocol-user account.
/// @dev Upgrade authority lives in this proxy, so delegated account logic cannot accidentally remove it. The
///      factory and authorization revision use namespaced slots, while the implementation uses ERC-1967. Every
///      successful implementation transition changes the revision consumed by all passkey signature domains.
contract WebAuthnAuthAccountProxy {
    bytes32 private constant _CHAINWALL_COMPONENT_ID = keccak256("Chainwall.WebAuthnAuthAccount");
    uint256 private constant _CHAINWALL_UPGRADE_PROTOCOL_VERSION = 1;

    error FactoryInvalid(address factory);
    error ProxyAlreadyInitialized();
    error RegistryUnauthorized(address caller, address registry);
    error ImplementationInvalid(address implementation);
    error ImplementationComponentInvalid(address implementation, bytes32 componentId);
    error ImplementationProtocolInvalid(address implementation, uint256 protocolVersion);
    error ImplementationNotApproved(address implementation);
    error ProxyStateChanged();
    error DirectUpgradeDisabled();

    event Upgraded(address indexed implementation);
    event AuthorizationRevisionChanged(bytes32 indexed previousRevision, bytes32 indexed newRevision);

    /// @dev Lock the dispatcher instance itself. Account storage starts empty
    ///      because each account is an EIP-1167 clone that delegatecalls here.
    constructor() {
        bytes32 factorySlot = WebAuthnAuthAccountProxyStorage.FACTORY_SLOT;
        assembly ("memory-safe") {
            sstore(factorySlot, address())
        }
    }

    /// @notice Initialize one newly deployed account clone with its tenant factory's selected release.
    /// @dev The factory invokes this atomically after CREATE2 clone deployment. Keeping the outer account at the
    ///      45-byte EIP-1167 runtime is required for counterfactual deployment below ERC-7562's verification-gas
    ///      ceiling, while this immutable dispatcher keeps the Registry-only upgrade selector permanently present.
    function initializeProxy(address expectedImplementation, bytes32 expectedImplementationCodehash) external {
        if (WebAuthnAuthAccountProxyStorage.factory() != address(0)) revert ProxyAlreadyInitialized();
        address factory_ = msg.sender;
        if (!Delegation7702.hasContractCode(factory_)) revert FactoryInvalid(factory_);
        address implementation = IWebAuthnAuthAccountProxyFactory(factory_).IMPLEMENTATION();
        if (implementation != expectedImplementation || implementation.codehash != expectedImplementationCodehash) {
            revert ImplementationInvalid(expectedImplementation);
        }
        _requireAccountImplementation(implementation);
        address registry = IWebAuthnAuthAccountProxyFactory(factory_).REGISTRY();
        if (registry == address(0) || !Delegation7702.hasContractCode(registry)) revert FactoryInvalid(factory_);

        bytes32 factorySlot = WebAuthnAuthAccountProxyStorage.FACTORY_SLOT;
        assembly ("memory-safe") {
            sstore(factorySlot, factory_)
        }
        // The initial revision is derived from the permanently bound factory
        // until the first upgrade. Avoiding a redundant deployment SSTORE keeps
        // counterfactual creation within EntryPoint's verification-gas ceiling.
        ERC1967Utils.upgradeToAndCall(implementation, bytes(""));
    }

    function chainwallFactory() external view returns (address) {
        return WebAuthnAuthAccountProxyStorage.factory();
    }

    function chainwallComponentId() external pure returns (bytes32) {
        return _CHAINWALL_COMPONENT_ID;
    }

    function chainwallUpgradeProtocolVersion() external pure returns (uint256) {
        return _CHAINWALL_UPGRADE_PROTOCOL_VERSION;
    }

    function chainwallImplementation() external view returns (address) {
        return ERC1967Utils.getImplementation();
    }

    function chainwallImplementationCodehash() external view returns (bytes32) {
        return ERC1967Utils.getImplementation().codehash;
    }

    /// @notice Hash the stable factory/Registry authority and account-local authentication domain.
    /// @dev The implementation cannot override this selector because it is implemented by the permanent dispatcher.
    function chainwallSecurityBindingsHash() external view returns (bytes32) {
        address factory_ = WebAuthnAuthAccountProxyStorage.factory();
        address registry = factory_ == address(0) ? address(0) : IWebAuthnAuthAccountProxyFactory(factory_).REGISTRY();
        return ChainwallUpgradeHash.hash(abi.encode(factory_, registry, _accountBindingsHash()));
    }

    function chainwallAuthorizationRevision() external view returns (bytes32) {
        return WebAuthnAuthAccountProxyStorage.authorizationRevision();
    }

    /// @notice Install one account implementation under the bound tenant Registry.
    /// @dev This selector lives in the stable dispatcher, so delegated account
    ///      logic cannot remove the Registry-authorized upgrade route.
    function timelockUpgrade(address newImplementation, bytes calldata data) external {
        address factory_ = WebAuthnAuthAccountProxyStorage.factory();
        address registry = IWebAuthnAuthAccountProxyFactory(factory_).REGISTRY();
        if (msg.sender != registry) revert RegistryUnauthorized(msg.sender, registry);
        _requireAccountImplementation(newImplementation);
        if (!IWebAuthnAuthAccountProxyFactory(factory_).isAuthAccountImplementationApproved(newImplementation)) {
            revert ImplementationNotApproved(newImplementation);
        }

        bytes32 accountBindings = _accountBindingsHash();
        bytes32 previousRevision = WebAuthnAuthAccountProxyStorage.authorizationRevision();
        bytes32 newRevision = _authorizationRevision(previousRevision, newImplementation, newImplementation.codehash);
        bytes32 revisionSlot = WebAuthnAuthAccountProxyStorage.AUTHORIZATION_REVISION_SLOT;
        assembly ("memory-safe") {
            sstore(revisionSlot, newRevision)
        }
        ERC1967Utils.upgradeToAndCall(newImplementation, data);

        if (
            WebAuthnAuthAccountProxyStorage.factory() != factory_
                || WebAuthnAuthAccountProxyStorage.authorizationRevision() != newRevision
                || ERC1967Utils.getImplementation() != newImplementation
                || IWebAuthnAuthAccountProxyFactory(factory_).REGISTRY() != registry
                || _accountBindingsHash() != accountBindings
        ) {
            revert ProxyStateChanged();
        }
        // Only the bound Registry can upgrade; postconditions verify implementation, factory, bindings, and
        // revision before emitting. Nested self-calls cannot impersonate the Registry.
        // forge-lint: disable-next-line(reentrancy-events)
        emit Upgraded(newImplementation);
        // Only the bound Registry can upgrade; postconditions verify implementation, factory, bindings, and
        // revision before emitting. Nested self-calls cannot impersonate the Registry.
        // forge-lint: disable-next-line(reentrancy-events)
        emit AuthorizationRevisionChanged(previousRevision, newRevision);
    }

    /// @notice Reject the ordinary UUPS selector even if delegated logic happens to expose it.
    function upgradeToAndCall(address, bytes calldata) external payable {
        revert DirectUpgradeDisabled();
    }

    fallback() external payable {
        _delegate();
    }

    receive() external payable {
        _delegate();
    }

    function _requireAccountImplementation(address implementation) private view {
        if (!Delegation7702.hasContractCode(implementation)) revert ImplementationInvalid(implementation);
        bytes32 componentId;
        try IWebAuthnAuthAccountImplementation(implementation).chainwallComponentId() returns (bytes32 value) {
            componentId = value;
        } catch {
            revert ImplementationComponentInvalid(implementation, bytes32(0));
        }
        // The successful try branch assigns this value; the catch reverts before it can be read.
        // forge-lint: disable-next-line(uninitialized-local)
        if (componentId != _CHAINWALL_COMPONENT_ID) {
            revert ImplementationComponentInvalid(implementation, componentId);
        }
        uint256 protocolVersion;
        try IWebAuthnAuthAccountImplementation(implementation).chainwallUpgradeProtocolVersion() returns (
            uint256 value
        ) {
            protocolVersion = value;
        } catch {
            revert ImplementationProtocolInvalid(implementation, 0);
        }
        // The successful try branch assigns this value; the catch reverts before it can be read.
        // forge-lint: disable-next-line(uninitialized-local)
        if (protocolVersion != _CHAINWALL_UPGRADE_PROTOCOL_VERSION) {
            revert ImplementationProtocolInvalid(implementation, protocolVersion);
        }
    }

    /// @dev Preserve authentication and tenant trust roots while allowing the
    ///      candidate migration to transform credentials, scopes, nonces, and
    ///      newly appended implementation state. Tenant authority is derived
    ///      exclusively from the permanently bound factory.
    function _accountBindingsHash() private view returns (bytes32 bindingsHash) {
        WebAuthnAuthAccountStateStorage.Layout storage account = WebAuthnAuthAccountStateStorage.getLayout();
        address entryPoint = account.entryPoint;
        bytes32 rpIdHash = account.rpIdHash;
        bytes memory originBytes = bytes(account.origin);
        bytes32 originHash;
        assembly ("memory-safe") {
            originHash := keccak256(add(originBytes, 0x20), mload(originBytes))
            let ptr := mload(0x40)
            let addressMask := 0xffffffffffffffffffffffffffffffffffffffff
            mstore(ptr, and(entryPoint, addressMask))
            mstore(add(ptr, 0x20), rpIdHash)
            mstore(add(ptr, 0x40), originHash)
            bindingsHash := keccak256(ptr, 0x60)
        }
    }

    function _authorizationRevision(bytes32 previous, address implementation, bytes32 codehash_)
        private
        pure
        returns (bytes32 revision)
    {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, previous)
            mstore(add(ptr, 0x20), and(implementation, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(ptr, 0x40), codehash_)
            revision := keccak256(ptr, 0x60)
        }
    }

    function _delegate() private {
        address implementation = ERC1967Utils.getImplementation();
        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
