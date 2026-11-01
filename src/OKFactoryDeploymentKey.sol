// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @title OKFactoryDeploymentKey
/// @notice Domain-separated keys and CREATE2 salts for index-independent tenant deployments.
/// @dev The deployment key binds every caller-selectable input that affects tenant semantics. Anyone may submit the
///      same deployment on another party's behalf, but changing the owner, flags, or user salt creates a different
///      key and address family. Each component salt binds the full deployment key.
library OKFactoryDeploymentKey {
    bytes32 internal constant INSTANCE_KEY_DOMAIN = keccak256("chainwall.okfactory.instance.v1");
    bytes32 internal constant COMPONENT_SALT_DOMAIN = keccak256("chainwall.okfactory.component.v1");

    /// @notice Derive the stable identity for one deterministic tenant deployment.
    function derive(bytes32 userSalt, address instanceOwner, uint8 flags) internal pure returns (bytes32) {
        return keccak256(abi.encode(INSTANCE_KEY_DOMAIN, userSalt, instanceOwner, flags));
    }

    /// @notice Derive a collision-resistant CREATE2 salt for one component in a deterministic tenant family.
    function componentSalt(uint8 component, bytes32 deploymentKey) internal pure returns (bytes32) {
        return keccak256(abi.encode(COMPONENT_SALT_DOMAIN, component, deploymentKey));
    }
}
