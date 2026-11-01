// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AccountFactory} from "./AccountFactory.sol";
import {Interact} from "./Interact.sol";
import {IMiniScript} from "./MiniScript.sol";
import {OKFactoryConfig} from "./OKFactoryConfig.sol";
import {OKFactoryDeploymentKey} from "./OKFactoryDeploymentKey.sol";
import {RegistryDiamond} from "./RegistryDiamond.sol";
import {SafeFactoryWithCreate2} from "./SafeFactory.sol";
import {TimelockPolicyProgramRunner} from "./TimelockPolicyProgramRunner.sol";
import {WebAuthnAuthAccountFactory} from "./WebAuthnAuthAccountFactory.sol";
import {IRegistry} from "./registry/RegistryShared.sol";

/// @title OKFactoryAddressDerivation
/// @notice Shared deterministic address derivation helpers for the OKFactory tenant stack.
/// @dev Mirrors the factory's CREATE2 salts and constructor/init payloads so off-chain tooling and the on-chain
///      predictor can derive the same addresses without duplicating that logic in multiple contracts.
library OKFactoryAddressDerivation {
    /// @dev Component ids select the domain-separated deployment-key salt for each tenant component.
    uint8 internal constant COMP_REGISTRY = 1;
    uint8 internal constant COMP_MINISCRIPT = 2;
    uint8 internal constant COMP_INTERACT = 3;
    uint8 internal constant COMP_SAFE_FACTORY = 4;
    uint8 internal constant COMP_ACCOUNT_FACTORY = 5;
    uint8 internal constant COMP_AUTH_ACCOUNT_FACTORY = 8;
    uint8 internal constant COMP_TIMELOCK_POLICY_RUNNER = 9;
    /// @dev Bit 0 enables indexing on the derived Interact, SafeFactory, and AccountFactory instances.
    uint8 internal constant INSTANCE_FLAG_INDEXING = 0x01;
    /// @dev Bit 1 deploys and trusts a WebAuthn AuthAccount factory for the tenant.
    uint8 internal constant INSTANCE_FLAG_AUTH_ACCOUNT_FACTORY = 0x02;

    /// @notice Predicted component addresses for a single tenant deployment.
    struct InstanceAddresses {
        /// @notice Predicted registry proxy address.
        address registry;
        /// @notice Predicted MiniScript proxy address.
        address miniScript;
        /// @notice Predicted Interact proxy address.
        address interact;
        /// @notice Predicted SafeFactoryWithCreate2 address.
        address safeFactory;
        /// @notice Predicted AccountFactory proxy address.
        address accountFactory;
        /// @notice Predicted WebAuthn AuthAccount factory address, or zero when disabled.
        address authAccountFactory;
        /// @notice Predicted registry-bound timelock policy program runner address.
        address timelockPolicyRunner;
    }

    /// @notice Predicted addresses for the components still deployed during stage 2.
    struct Stage2Addresses {
        /// @notice Predicted MiniScript proxy address.
        address miniScript;
        /// @notice Predicted Interact proxy address.
        address interact;
        /// @notice Predicted SafeFactoryWithCreate2 address.
        address safeFactory;
        /// @notice Predicted AccountFactory proxy address.
        address accountFactory;
    }

    /// @notice Predict an index-independent tenant stack from the same user inputs accepted by the factory.
    function predictDeterministicInstanceAddresses(
        OKFactoryConfig config,
        address factoryAddr,
        bytes32 userSalt,
        address instanceOwner,
        uint8 flags
    ) internal view returns (InstanceAddresses memory addrs) {
        bytes32 deploymentKey = OKFactoryDeploymentKey.derive(userSalt, instanceOwner, flags);
        return _predictInstanceAddresses(config, factoryAddr, deploymentKey, flags);
    }

    function _predictInstanceAddresses(OKFactoryConfig config, address factoryAddr, bytes32 deploymentKey, uint8 flags)
        private
        view
        returns (InstanceAddresses memory addrs)
    {
        bytes memory registryCode = _registryCreationCode(config);
        bytes32 registrySalt = _deploymentSalt(COMP_REGISTRY, deploymentKey);
        bytes32 registryHash = _hashBytes(registryCode);
        addrs.registry = _computeCreate2(factoryAddr, registrySalt, registryHash);

        Stage2Addresses memory stage2 =
            _predictStage2Addresses(config, factoryAddr, addrs.registry, deploymentKey, flags);
        addrs.miniScript = stage2.miniScript;
        addrs.interact = stage2.interact;
        addrs.safeFactory = stage2.safeFactory;
        addrs.accountFactory = stage2.accountFactory;
        addrs.authAccountFactory = (flags & INSTANCE_FLAG_AUTH_ACCOUNT_FACTORY) != 0
            ? _predictAuthAccountFactoryAddress(
                config, factoryAddr, addrs.registry, addrs.interact, addrs.safeFactory, deploymentKey
            )
            : address(0);
        addrs.timelockPolicyRunner =
            _predictTimelockPolicyRunnerAddress(config, factoryAddr, addrs.registry, deploymentKey);
    }

    /// @notice Predict deterministic stage-2 addresses from an already-derived deployment key.
    function predictStage2AddressesForDeploymentKey(
        OKFactoryConfig config,
        address factoryAddr,
        address registryAddr,
        bytes32 deploymentKey,
        uint8 flags
    ) internal view returns (Stage2Addresses memory addrs) {
        return _predictStage2Addresses(config, factoryAddr, registryAddr, deploymentKey, flags);
    }

    function _predictStage2Addresses(
        OKFactoryConfig config,
        address factoryAddr,
        address registryAddr,
        bytes32 deploymentKey,
        uint8 flags
    ) private view returns (Stage2Addresses memory addrs) {
        bool indexingEnabled = (flags & INSTANCE_FLAG_INDEXING) != 0;

        addrs.miniScript = _predictMiniScriptAddress(config, factoryAddr, deploymentKey);
        addrs.interact = _predictInteractAddress(
            config, factoryAddr, registryAddr, addrs.miniScript, deploymentKey, indexingEnabled
        );
        addrs.safeFactory =
            _predictSafeFactoryAddress(config, factoryAddr, addrs.interact, deploymentKey, indexingEnabled);
        addrs.accountFactory =
            _predictAccountFactoryAddress(config, factoryAddr, addrs.interact, deploymentKey, indexingEnabled);
    }

    function _predictTimelockPolicyRunnerAddress(
        OKFactoryConfig config,
        address factoryAddr,
        address registryAddr,
        bytes32 deploymentKey
    ) private view returns (address runner) {
        bytes memory runnerCode = _timelockPolicyRunnerCreationCode(config, registryAddr);
        runner = _computeCreate2(
            factoryAddr, _deploymentSalt(COMP_TIMELOCK_POLICY_RUNNER, deploymentKey), _hashBytes(runnerCode)
        );
    }

    /// @notice Compute the stage-2 deployment commitment used by the factory from a full preview.
    /// @dev This commits the remaining stage-2 addresses in order:
    ///      `miniScript`, `interact`, `safeFactory`, `accountFactory`.
    function stage2Commitment(InstanceAddresses memory addrs) internal pure returns (bytes32 hash) {
        assembly ("memory-safe") {
            hash := keccak256(add(addrs, 0x20), 0x80)
        }
    }

    /// @notice Compute the stage-2 deployment commitment used by the factory from the reduced binding set.
    /// @dev This commits the remaining stage-2 addresses in order:
    ///      `miniScript`, `interact`, `safeFactory`, `accountFactory`.
    function stage2Commitment(Stage2Addresses memory addrs) internal pure returns (bytes32 hash) {
        assembly ("memory-safe") {
            hash := keccak256(addrs, 0x80)
        }
    }

    /// @dev Mirrors the registry proxy creation code used by the factory.
    function _registryCreationCode(OKFactoryConfig config) private view returns (bytes memory) {
        bytes memory initData = abi.encodeCall(RegistryDiamond.initialize, ());
        // CREATE2 initcode is fixed creation bytecode followed by ABI-encoded constructor arguments, with no ambiguous boundary.
        // forge-lint: disable-next-line(encode-packed-collision)
        return abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(config.REGISTRY_IMPL(), initData));
    }

    /// @dev Mirrors the MiniScript proxy creation code used by the factory.
    function _miniCreationCode(OKFactoryConfig config) private view returns (bytes memory) {
        // CREATE2 initcode is fixed creation bytecode followed by ABI-encoded constructor arguments, with no ambiguous boundary.
        // forge-lint: disable-next-line(encode-packed-collision)
        return abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(config.MINISCRIPT_IMPL(), bytes("")));
    }

    function _predictMiniScriptAddress(OKFactoryConfig config, address factoryAddr, bytes32 deploymentKey)
        private
        view
        returns (address)
    {
        bytes memory miniCode = _miniCreationCode(config);
        return _computeCreate2(factoryAddr, _deploymentSalt(COMP_MINISCRIPT, deploymentKey), _hashBytes(miniCode));
    }

    /// @dev Mirrors the Interact proxy init payload used by the factory.
    function _interactCreationCode(OKFactoryConfig config, address registry, address mini, bool indexingEnabled)
        private
        view
        returns (bytes memory)
    {
        bytes memory initData =
            abi.encodeCall(Interact.initialize, (IRegistry(registry), IMiniScript(mini), indexingEnabled));
        // CREATE2 initcode is fixed creation bytecode followed by ABI-encoded constructor arguments, with no ambiguous boundary.
        // forge-lint: disable-next-line(encode-packed-collision)
        return abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(config.INTERACT_IMPL(), initData));
    }

    function _predictInteractAddress(
        OKFactoryConfig config,
        address factoryAddr,
        address registry,
        address mini,
        bytes32 deploymentKey,
        bool indexingEnabled
    ) private view returns (address) {
        bytes memory interactCode = _interactCreationCode(config, registry, mini, indexingEnabled);
        return _computeCreate2(factoryAddr, _deploymentSalt(COMP_INTERACT, deploymentKey), _hashBytes(interactCode));
    }

    /// @dev Mirrors the SafeFactoryWithCreate2 proxy init payload used by the factory.
    function _safeFactoryCreationCode(OKFactoryConfig config, address interactAddr, bool indexingEnabled)
        private
        view
        returns (bytes memory)
    {
        bytes memory initData = abi.encodeCall(
            SafeFactoryWithCreate2.initialize,
            (config.SAFE_SINGLETON(), config.SAFE_PROXY_FACTORY(), Interact(interactAddr), indexingEnabled)
        );
        // CREATE2 initcode is fixed creation bytecode followed by ABI-encoded constructor arguments, with no ambiguous boundary.
        // forge-lint: disable-next-line(encode-packed-collision)
        return abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(config.SAFE_FACTORY_IMPL(), initData));
    }

    function _predictSafeFactoryAddress(
        OKFactoryConfig config,
        address factoryAddr,
        address interactAddr,
        bytes32 deploymentKey,
        bool indexingEnabled
    ) private view returns (address) {
        bytes memory safeCode = _safeFactoryCreationCode(config, interactAddr, indexingEnabled);
        return _computeCreate2(factoryAddr, _deploymentSalt(COMP_SAFE_FACTORY, deploymentKey), _hashBytes(safeCode));
    }

    /// @dev Mirrors the AccountFactory proxy creation payload used by the factory.
    function _accountFactoryCreationCode(OKFactoryConfig config, address interactAddr, bool indexingEnabled)
        private
        view
        returns (bytes memory)
    {
        bytes memory initData = abi.encodeCall(
            AccountFactory.initialize,
            (Interact(interactAddr), config.ACCOUNT_ENGINE(), config.OK_ACCOUNT_IMPL(), indexingEnabled)
        );
        // CREATE2 initcode is fixed creation bytecode followed by ABI-encoded constructor arguments, with no ambiguous boundary.
        // forge-lint: disable-next-line(encode-packed-collision)
        return abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(config.ACCOUNT_FACTORY_IMPL(), initData));
    }

    function _predictAccountFactoryAddress(
        OKFactoryConfig config,
        address factoryAddr,
        address interactAddr,
        bytes32 deploymentKey,
        bool indexingEnabled
    ) private view returns (address) {
        bytes memory accountCode = _accountFactoryCreationCode(config, interactAddr, indexingEnabled);
        return
            _computeCreate2(factoryAddr, _deploymentSalt(COMP_ACCOUNT_FACTORY, deploymentKey), _hashBytes(accountCode));
    }

    /// @dev Mirrors the registry-bound timelock policy runner constructor payload used during stage-1 finalization.
    function _timelockPolicyRunnerCreationCode(OKFactoryConfig config, address registryAddr)
        private
        view
        returns (bytes memory)
    {
        // CREATE2 initcode is fixed creation bytecode followed by ABI-encoded constructor arguments, with no ambiguous boundary.
        // forge-lint: disable-start(encode-packed-collision)
        return abi.encodePacked(
            type(TimelockPolicyProgramRunner).creationCode, abi.encode(registryAddr, config.ACCOUNT_ENGINE())
        );
        // forge-lint: disable-end(encode-packed-collision)
    }

    /// @dev Mirrors the WebAuthnAuthAccountFactory proxy init payload used by the factory.
    function _authAccountFactoryCreationCode(
        OKFactoryConfig config,
        address registryAddr,
        address interactAddr,
        address safeFactoryAddr
    ) private view returns (bytes memory) {
        bytes memory initData = abi.encodeCall(
            WebAuthnAuthAccountFactory.initialize,
            (
                registryAddr,
                interactAddr,
                safeFactoryAddr,
                config.WEB_AUTHN_ENTRY_POINT(),
                config.WEB_AUTHN_ACCOUNT_IMPL(),
                config.WEB_AUTHN_RP_ID_HASH(),
                config.WEB_AUTHN_ORIGIN(),
                config.WEB_AUTHN_REQUIRE_USER_VERIFICATION()
            )
        );
        // CREATE2 initcode is fixed creation bytecode followed by ABI-encoded constructor arguments, with no ambiguous boundary.
        // forge-lint: disable-next-line(encode-packed-collision)
        return abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(config.WEB_AUTHN_FACTORY_IMPL(), initData));
    }

    function _predictAuthAccountFactoryAddress(
        OKFactoryConfig config,
        address factoryAddr,
        address registryAddr,
        address interactAddr,
        address safeFactoryAddr,
        bytes32 deploymentKey
    ) private view returns (address) {
        bytes memory factoryCode = _authAccountFactoryCreationCode(config, registryAddr, interactAddr, safeFactoryAddr);
        return _computeCreate2(
            factoryAddr, _deploymentSalt(COMP_AUTH_ACCOUNT_FACTORY, deploymentKey), _hashBytes(factoryCode)
        );
    }

    function _deploymentSalt(uint8 component, bytes32 deploymentKey) private pure returns (bytes32) {
        return OKFactoryDeploymentKey.componentSalt(component, deploymentKey);
    }

    /// @dev Efficient bytes hashing helper.
    function _hashBytes(bytes memory data) private pure returns (bytes32 hash) {
        assembly ("memory-safe") {
            hash := keccak256(add(data, 0x20), mload(data))
        }
    }

    /// @dev Standard CREATE2 preimage hashing helper used to compute the final address.
    function _computeCreate2(address deployer, bytes32 salt, bytes32 initCodeHash) private pure returns (address addr) {
        bytes32 hash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore8(ptr, 0xff)
            mstore(add(ptr, 1), shl(96, deployer))
            mstore(add(ptr, 21), salt)
            mstore(add(ptr, 53), initCodeHash)
            hash := keccak256(ptr, 85)
        }
        addr = address(uint160(uint256(hash)));
    }
}
