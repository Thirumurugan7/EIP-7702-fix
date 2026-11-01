// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @notice Common introspection implemented by every Registry-controlled UUPS component.
interface IChainwallUpgradeable {
    function chainwallComponentId() external pure returns (bytes32);
    function chainwallImplementation() external view returns (address);
    function chainwallImplementationCodehash() external view returns (bytes32);
    function chainwallUpgradeProtocolVersion() external pure returns (uint256);
    function chainwallSecurityBindingsHash() external view returns (bytes32);
    function timelockUpgrade(address newImplementation, bytes calldata data) external;
}
