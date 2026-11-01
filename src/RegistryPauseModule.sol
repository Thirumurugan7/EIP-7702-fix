// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {CapabilitiesLib, CapabilityIds} from "./registry/Capabilities.sol";
import {RegistryContainmentSelectors} from "./registry/RegistryContainmentSelectors.sol";
import {RegistryRoleStorage} from "./registry/RegistryRoleStorage.sol";
import {ExecutionCatalogStorage} from "./registry/RegistryShared.sol";
import {ExecutionContextLib} from "./registry/TimelockLib.sol";
import {DiamondAdminStorage} from "./registry/diamond/DiamondAdminStorage.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/// @title RegistryPauseModule
/// @notice Fixed delegatecall implementation for the Registry pause lifecycle.
/// @dev RegistryDiamond keeps the direct pause, batching, and authority-helper selectors and
///      delegates their implementation here. Delegatecall preserves the Registry storage domain,
///      caller, execution context, and event emitter while keeping this logic out of
///      the EIP-170-constrained dispatcher runtime.
///      OpenZeppelin bases contribute namespaced storage, events, and internal
///      helpers; this fixed module has no proxy or upgrade entrypoint of its own.
///      It has no address-valued immutable so admission can authenticate its exact
///      runtime. Direct calls fail because the module has no Registry AccessControl
///      surface; the original explicit error is retained at that boundary.
contract RegistryPauseModule is PausableUpgradeable, Ownable2StepUpgradeable {
    bytes32 private constant _ADMIN_ROLE = keccak256("ADMIN_ROLE");

    error DirectModuleCallUnsupported();
    error MulticallFailed();
    error OwnerBootstrapNotFinalized();

    /// @notice Fixed selector policy; unknown routed calls fail closed while paused.
    function containmentPolicy(bytes4 selector) external pure returns (uint8) {
        return RegistryContainmentSelectors.policy(selector);
    }

    event RoleGovernanceEnabled(address indexed operator);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    /// @notice One-way governed-role switch using the same logical actor as the dispatcher.
    function enableRoleGovernance() external {
        _requireNotPaused();
        address actor = _msgSender();
        if (!_hasRegistryRole(_ADMIN_ROLE, actor)) {
            revert IAccessControl.AccessControlUnauthorizedAccount(actor, _ADMIN_ROLE);
        }
        DiamondAdminStorage.Layout storage admin = DiamondAdminStorage.state();
        if (!admin.roleGovernanceEnabled) {
            admin.roleGovernanceEnabled = true;
            ExecutionCatalogStorage.bumpSemantics();
            // Role checks are read-only; role and revision updates are internal storage operations before this
            // event.
            // forge-lint: disable-next-line(reentrancy-events)
            emit RoleGovernanceEnabled(actor);
        }
    }

    /// @notice Preserve AccessControl self-confirmation and idempotence under delegatecall.
    function renounceRole(bytes32 role, address callerConfirmation) external {
        address actor = _msgSender();
        if (callerConfirmation != actor) revert IAccessControl.AccessControlBadConfirmation();
        if (!_hasRegistryRole(role, actor)) return;
        RegistryRoleStorage.revokeRole(role, actor);
        // Role checks are read-only; role and revision updates are internal storage operations before this event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit RoleRevoked(role, actor, actor);
        ExecutionCatalogStorage.bumpSemantics();
    }

    /// @notice Ownership is renounceable only after its bootstrap authority is retired.
    function renounceOwnership() public override onlyOwner {
        if (!DiamondAdminStorage.state().ownerBootstrapFinalized) revert OwnerBootstrapNotFinalized();
        super.renounceOwnership();
        ExecutionCatalogStorage.bumpSemantics();
    }

    /**
     * @notice Executes a batch of calls against the diamond using delegatecall.
     * @dev Preserves msg.sender and ExecutionContextLib actor across subcalls so existing guards still apply.
     * @param calls Encoded function calls to execute sequentially.
     * @return results ABI-encoded return data per call.
     */
    function multicall(bytes[] calldata calls) external returns (bytes[] memory results) {
        uint256 len = calls.length;
        results = new bytes[](len);
        for (uint256 i = 0; i < len;) {
            // Caller-supplied multicall delegates only to this diamond; each subcall retains its own authorization
            // and all failures roll back.
            // forge-lint: disable-next-line(calls-loop)
            (bool ok, bytes memory ret) = address(this).delegatecall(calls[i]);
            if (!ok) {
                if (ret.length != 0) {
                    assembly {
                        // Multicall is atomic and preserves each subcall authorization; a failed subcall must roll
                        // back the batch.
                        // forge-lint: disable-next-line(require-revert-in-loop)
                        revert(add(ret, 0x20), mload(ret))
                    }
                }
                // Multicall is atomic and preserves each subcall authorization; a failed subcall must roll back the
                // batch.
                // forge-lint: disable-next-line(require-revert-in-loop)
                revert MulticallFailed();
            }
            results[i] = ret;
            unchecked {
                ++i;
            }
        }
    }

    function pause() external {
        _requirePauseAuthority(false);
        _pause();
        ExecutionCatalogStorage.bumpSemantics();
    }

    function unpause() external {
        _requirePauseAuthority(true);
        _unpause();
        ExecutionCatalogStorage.bumpSemantics();
    }

    function _requirePauseAuthority(bool unpausing) private view {
        address actor = _msgSender();
        bool admin = _hasRegistryRole(_ADMIN_ROLE, actor);
        if (admin) return;
        if (!unpausing && CapabilitiesLib.hasCapability(actor, CapabilityIds.PAUSE_OPERATOR)) return;
        revert IAccessControl.AccessControlUnauthorizedAccount(actor, _ADMIN_ROLE);
    }

    function _hasRegistryRole(bytes32 role, address actor) private view returns (bool) {
        try IAccessControl(address(this)).hasRole(role, actor) returns (bool granted) {
            return granted;
        } catch {
            revert DirectModuleCallUnsupported();
        }
    }

    function _msgSender() internal view override(ContextUpgradeable) returns (address) {
        return ExecutionContextLib.actorOrSender();
    }
}
