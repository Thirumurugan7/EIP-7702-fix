// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {IAccessRegistry} from "./IAccessRegistry.sol";
import {IRegistry} from "./IRegistry.sol";

/// @notice Registry surface for contracts governed by Chainwall.
/// @dev Authenticate a particular managed vault as well as its current admission.
///      Admission alone does not authorize every managed account to administer an asset.
interface IChainwallRegistry is IAccessRegistry, IRegistry {
    /// @notice Return whether the Registry is contained by its native pause lifecycle.
    /// @dev Integrations choose which asset operations must stop during containment.
    function paused() external view returns (bool);
}
