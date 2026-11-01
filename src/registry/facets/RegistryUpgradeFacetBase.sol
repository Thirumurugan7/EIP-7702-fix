// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {CapabilitiesLib, CapabilityIds} from "../../registry/Capabilities.sol";
import {ExecutionContextLib, TimelockLib} from "../../registry/TimelockLib.sol";
import {FacetGuard} from "../diamond/DiamondGuards.sol";

/// @notice Shared authority and scope checks for the two tenant upgrade facets.
abstract contract RegistryUpgradeFacetBase is FacetGuard {
    error TimelockContextRequired();

    function _requireUpgradeContext(address target) internal view {
        if (!ExecutionContextLib.isActive()) revert TimelockContextRequired();
        ExecutionContextLib.ensure(TimelockLib.categoryContract(), _upgradeScopeKey(target));
        _requireTimelockGovernor();
    }

    function _upgradeScopeKey(address target) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(target)));
    }

    /// @dev The bootstrap owner may configure a new tenant. Afterwards the
    ///      TIMELOCK_GOVERNOR capability is the normal upgrade authority.
    function _requireTimelockGovernor() internal view {
        address actor = _msgSenderD();
        if (_isBootstrapOwnerD(actor)) return;
        if (CapabilitiesLib.hasCapability(actor, CapabilityIds.TIMELOCK_GOVERNOR)) return;
        revert OwnableUnauthorizedAccount(actor);
    }
}
