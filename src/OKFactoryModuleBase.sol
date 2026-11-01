// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {OKFactoryDeploymentKey} from "./OKFactoryDeploymentKey.sol";
import {OKFactoryErrors} from "./OKFactoryErrors.sol";
import {OKFactoryState} from "./OKFactoryState.sol";

/// @title OKFactoryModuleBase
/// @notice Shared delegatecall guard for OKFactory stage modules.
/// @dev The modules are immutable helper contracts whose code executes in the factory context via delegatecall.
///      Direct calls must fail so canonical CREATE2 deployments always remain anchored at the factory address.
abstract contract OKFactoryModuleBase is OKFactoryState {
    /// @notice Reverts when a stage module is called directly instead of through delegatecall.
    modifier onlyDelegateCall() {
        _onlyDelegateCall();
        _;
    }

    /// @dev Stage modules are not standalone deployment entrypoints.
    ///      Every state write and CREATE2 deployment must happen in the factory's
    ///      storage and address context, so direct calls are always rejected.
    function _onlyDelegateCall() internal view {
        if (address(this) != _factorySelf) revert OKFactoryErrors.DirectModuleCallUnsupported();
    }

    /// @dev Domain-separate every component from the deployment key committed at stage-1 bootstrap.
    function _deploymentSalt(uint8 component, bytes32 deploymentKey) internal pure returns (bytes32) {
        return OKFactoryDeploymentKey.componentSalt(component, deploymentKey);
    }
}
