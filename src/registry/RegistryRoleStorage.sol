// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @title RegistryRoleStorage
/// @notice Narrow access to the Registry's OpenZeppelin AccessControl storage.
/// @dev The slot and RoleData shape exactly mirror AccessControlUpgradeable's
///      ERC-7201 layout. Emergency, constitutional recovery, and self-renunciation
///      paths use these helpers after their own authorization checks.
library RegistryRoleStorage {
    struct RoleData {
        mapping(address account => bool) hasRole;
        bytes32 adminRole;
    }

    struct Layout {
        mapping(bytes32 role => RoleData) roles;
    }

    bytes32 internal constant SLOT = 0x02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800;

    function state() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly ("memory-safe") {
            l.slot := slot
        }
    }

    function grantRole(bytes32 role, address account) internal returns (bool granted) {
        Layout storage l = state();
        if (l.roles[role].hasRole[account]) return false;
        l.roles[role].hasRole[account] = true;
        return true;
    }

    function revokeRole(bytes32 role, address account) internal returns (bool revoked) {
        Layout storage l = state();
        if (!l.roles[role].hasRole[account]) return false;
        l.roles[role].hasRole[account] = false;
        return true;
    }
}
