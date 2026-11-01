// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {GroupGovernanceLib} from "../GroupGovernanceLib.sol";

/// @notice Fixed membership-governance implementation deployed by the users facet.
/// @dev No selectors are installed for this module. The facet pins its address in immutable
///      code and delegates only after its ordinary user/group authorization and validation.
contract RegistryGroupGovernanceModule {
    address private immutable SELF = address(this);
    error DirectModuleCallUnsupported();

    function enforceOrQueue(
        bytes32 category,
        bytes32 scope,
        bytes32[] memory groupIds,
        bool adding,
        bytes memory payload
    ) external returns (bool) {
        if (address(this) == SELF) revert DirectModuleCallUnsupported();
        return GroupGovernanceLib.enforceOrQueue(category, scope, groupIds, adding, payload);
    }
}
