// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {ExecutionContextLib} from "../TimelockLib.sol";
import {DiamondAdminStorage} from "./DiamondAdminStorage.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/// @title IPausableView
/// @notice Minimal paused-state view used by `FacetGuard`.
interface IPausableView {
    function paused() external view returns (bool);
}

/// @title IOwnableView
/// @notice Minimal owner view used by `FacetGuard`.
interface IOwnableView {
    function owner() external view returns (address);
}

/// @title ReentrancyGuardDStorage
/// @notice Diamond-safe reentrancy guard storage shared by facets.
/// @dev Facets cannot inherit OZ's standard reentrancy guard independently because
///      they all execute against the same registry storage. This helper provides a
///      namespaced replacement.
library ReentrancyGuardDStorage {
    /// @dev Namespace key for the shared diamond reentrancy guard state.
    bytes32 internal constant SLOT = keccak256("okc.storage.diamond.reentrancy");
    uint256 internal constant NOT_ENTERED = 1;
    uint256 internal constant ENTERED = 2;

    /// @notice Reentrancy guard layout stored in the registry.
    struct Layout {
        /// @notice Current reentrancy status.
        uint256 status;
    }

    /// @notice Return the reentrancy-guard layout for the active registry instance.
    /// @dev Foundry fmt parser can choke on `layout()`; use `state()` here.
    function state() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }

    /// @notice Enter the shared non-reentrant section.
    function enter() internal {
        Layout storage l = state();
        if (l.status == ENTERED) revert("ReentrancyGuard: reentrant call");
        l.status = ENTERED;
    }

    /// @notice Exit the shared non-reentrant section.
    function exit() internal {
        state().status = NOT_ENTERED;
    }
}

/// @title FacetGuard
/// @notice Common access-control, pause, owner, and reentrancy helpers for registry facets.
/// @dev Every mutating facet uses this base so authorization semantics stay
///      consistent whether the call originates directly from an admin or from a
///      timelock replay carrying a logical actor in `ExecutionContextLib`.
abstract contract FacetGuard {
    // Use the standard OpenZeppelin authorization error signatures
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);
    error EnforcedPause();
    error ExpectedPause();
    error OwnableUnauthorizedAccount(address account);

    /// @notice Require that the logical actor holds `role`.
    modifier onlyRoleD(bytes32 role) {
        _onlyRoleD(role);
        _;
    }

    /// @dev Resolve the logical actor and check the registry's access-control table.
    function _onlyRoleD(bytes32 role) internal view {
        address actor = _msgSenderD();
        if (!IAccessControl(address(this)).hasRole(role, actor)) {
            revert AccessControlUnauthorizedAccount(actor, role);
        }
    }

    /// @notice Require that the registry is not paused.
    modifier whenNotPausedD() {
        _whenNotPausedD();
        _;
    }

    /// @dev Revert with the same shape as OZ's pause guard when the registry is paused.
    function _whenNotPausedD() internal view {
        if (IPausableView(address(this)).paused()) revert EnforcedPause();
    }

    /// @notice Require that the registry is paused.
    modifier whenPausedD() {
        _whenPausedD();
        _;
    }

    /// @dev Revert when the registry is not paused.
    function _whenPausedD() internal view {
        if (!IPausableView(address(this)).paused()) revert ExpectedPause();
    }

    /// @notice Enter the shared facet reentrancy guard for the duration of the call.
    modifier nonReentrantD() {
        ReentrancyGuardDStorage.enter();
        _;
        ReentrancyGuardDStorage.exit();
    }

    /// @notice Return the current registry owner.
    function _ownerD() internal view returns (address) {
        return IOwnableView(address(this)).owner();
    }

    /// @notice Return whether `actor` still has temporary owner-derived governance authority.
    function _isBootstrapOwnerD(address actor) internal view returns (bool) {
        return !DiamondAdminStorage.state().ownerBootstrapFinalized && actor == _ownerD();
    }

    /// @notice Return the logical actor for the current facet call.
    /// @dev Timelock replays may set this to something other than `msg.sender`.
    function _msgSenderD() internal view returns (address) {
        return ExecutionContextLib.actorOrSender();
    }

    /// @notice Require that the logical actor is the current registry owner.
    modifier onlyOwnerD() {
        _onlyOwnerD();
        _;
    }

    /// @dev Owner check that respects timelock execution context.
    function _onlyOwnerD() internal view {
        address actor = _msgSenderD();
        if (actor != _ownerD()) {
            revert OwnableUnauthorizedAccount(actor);
        }
    }
}
