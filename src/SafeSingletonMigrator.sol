// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "./Delegation7702.sol";
interface ISafeFactoryMigrationRegistry {
    function INTERACT_CONTRACT() external view returns (address);
    function isSafe(address safe) external view returns (bool);
    function isSafeSingletonMigrationTarget(address singleton) external view returns (bool);
    function validateManagedSafe(address safe) external view;
}

/// @title SafeSingletonMigrator
/// @notice One-purpose delegatecall target for Registry-approved Safe singleton migrations.
/// @dev The Safe guard and module expose this contract as the only maintenance
///      delegatecall surface. It writes only Safe slot zero, then revalidates the
///      complete managed-Safe topology through the tenant factory before returning.
contract SafeSingletonMigrator {
    bytes32 public constant CHAINWALL_COMPONENT_ID = keccak256("Chainwall.SafeSingletonMigrator");

    /// @notice Tenant Interact address used to authenticate the factory binding.
    address public immutable INTERACT;
    /// @notice Exact tenant SafeFactory whose managed Safes may use migration mode.
    address public immutable SAFE_FACTORY;

    error InteractZero();
    error SafeFactoryZero();
    error SafeFactoryInvalid(address safeFactory);
    error SafeNotManaged(address safeFactory, address safe);
    error SafeSingletonNotApproved(address safeFactory, address singleton);
    error SafeSingletonCodehashMismatch(address singleton, bytes32 expected, bytes32 actual);
    error SafeSingletonUnchanged(address safe, address singleton);

    event ChangedMasterCopy(address singleton);

    constructor(address interact, address safeFactory) {
        if (interact == address(0)) revert InteractZero();
        if (safeFactory == address(0)) revert SafeFactoryZero();
        INTERACT = interact;
        SAFE_FACTORY = safeFactory;
    }

    function chainwallComponentId() external pure returns (bytes32) {
        return CHAINWALL_COMPONENT_ID;
    }

    /// @notice Replace the singleton of the Safe executing this delegatecall.
    /// @dev Both owner-signed guarded transactions and Registry-authorized module
    ///      migrations require an exact singleton approved by the tenant factory.
    function migrateSafeSingleton(address newSingleton, bytes32 expectedCodehash) external {
        address safe = address(this);
        address safeFactory = SAFE_FACTORY;
        if (!Delegation7702.hasContractCode(safeFactory)) revert SafeFactoryInvalid(safeFactory);
        ISafeFactoryMigrationRegistry factory = ISafeFactoryMigrationRegistry(safeFactory);
        try factory.INTERACT_CONTRACT() returns (address interact) {
            if (interact != INTERACT) revert SafeFactoryInvalid(safeFactory);
        } catch {
            revert SafeFactoryInvalid(safeFactory);
        }
        if (!factory.isSafe(safe)) revert SafeNotManaged(safeFactory, safe);
        if (!factory.isSafeSingletonMigrationTarget(newSingleton)) {
            revert SafeSingletonNotApproved(safeFactory, newSingleton);
        }
        bytes32 actualCodehash = newSingleton.codehash;
        if (!Delegation7702.hasContractCode(newSingleton) || actualCodehash != expectedCodehash) {
            revert SafeSingletonCodehashMismatch(newSingleton, expectedCodehash, actualCodehash);
        }
        address current;
        assembly ("memory-safe") {
            current := sload(0)
        }
        if (current == newSingleton) revert SafeSingletonUnchanged(safe, newSingleton);
        assembly ("memory-safe") {
            sstore(0, newSingleton)
        }
        // Exercise the new singleton before committing. An incompatible storage
        // layout or topology rolls slot zero back with the complete transaction.
        factory.validateManagedSafe(safe);
        // The post-migration factory validation is a view STATICCALL and cannot reorder this slot-zero transition.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ChangedMasterCopy(newSingleton);
    }
}
