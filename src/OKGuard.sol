// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {BaseTransactionGuard, ITransactionGuard} from "@gnosis.pm/safe-contracts/base/GuardManager.sol";
import {Enum} from "@gnosis.pm/safe-contracts/libraries/Enum.sol";

import {ChainwallUUPSUpgradeable} from "./ChainwallUpgradeable.sol";
import {Interact} from "./Interact.sol";
import {SafeSingletonMigrator} from "./SafeSingletonMigrator.sol";

/// @title OKGuard
/// @notice Gnosis Safe guard that narrows the Safe transaction surface to Chainwall-approved execution paths.
/// @dev The guard is the wallet-layer half of Chainwall's "allowed world" model.
///      Even if Safe owners have enough signatures, the Safe must still route
///      execution through:
///      - `Interact` for direct or approval-based interaction execution, or
///      - `SafeSingletonMigrator` for an approved singleton migration
///
///      This means a tenant Safe cannot quietly send arbitrary transactions to
///      unregistered contracts. The registry and policy engine remain the only
///      way value can move through the protected wallet.
contract OKGuard is ITransactionGuard, BaseTransactionGuard, ChainwallUUPSUpgradeable {
    bytes32 public constant CHAINWALL_COMPONENT_ID = keccak256("Chainwall.OKGuard");
    bytes32 private constant SAFE_SINGLETON_MIGRATOR_COMPONENT_ID = keccak256("Chainwall.SafeSingletonMigrator");

    error GuardRefundParametersUnsupported();
    error GuardExecutionFailed();
    error GuardInteractZero();
    error GuardSafeSingletonMigratorInvalid(address migrator);
    error GuardSafeSingletonMigratorInteractMismatch(address expectedInteract, address actualInteract);
    error GuardOnlyRegistry();

    /// @notice Shared `Interact` instance that guarded Safes are allowed to call.
    Interact public INTERACTION;
    /// @notice One-purpose singleton migrator guarded Safes may delegatecall.
    SafeSingletonMigrator public SAFE_SINGLETON_MIGRATOR;

    event SafeSingletonMigratorChanged(address indexed previousMigrator, address indexed newMigrator);

    /// @notice Create a guard bound to one tenant's execution runtime.
    /// @param _interact Interact contract allowed for Safe CALL execution.
    /// @param _migrator Singleton migrator allowed for Safe DELEGATECALL execution.
    /// @dev The `(0, 0)` pair is reserved for a locked, shared implementation
    ///      whose tenant bindings are written only in proxy storage by {initialize}.
    constructor(Interact _interact, SafeSingletonMigrator _migrator) {
        if (address(_interact) != address(0) || address(_migrator) != address(0)) {
            _setBindings(_interact, _migrator);
        }
        _disableInitializers();
    }

    /// @notice Atomically bind a newly deployed guard proxy to one tenant runtime.
    function initialize(Interact interact_, SafeSingletonMigrator migrator_) external initializer {
        _setBindings(interact_, migrator_);
        __UUPSUpgradeable_init();
    }

    /// @notice Stable logical type used by Registry upgrade verification.
    function chainwallComponentId() external pure override returns (bytes32) {
        return CHAINWALL_COMPONENT_ID;
    }

    /// @notice Upgrade this installed guard without changing the address held by its Safes.
    function timelockUpgrade(address newImplementation, bytes calldata data) external {
        _requireRegistry();
        _upgradePreservingBindings(newImplementation, data);
    }

    /// @notice Disable the ordinary UUPS surface so all persistent upgrades use the Registry timelock.
    function upgradeToAndCall(address, bytes memory) public payable override {
        revert("OKGuard: use timelockUpgrade");
    }

    /// @notice Replace singleton-migration code while retaining this installed guard address.
    /// @dev RegistryTimelockReleaseFacet updates the factory, guard, and module in one atomic action.
    function setSafeSingletonMigrator(SafeSingletonMigrator newMigrator) external {
        _requireRegistry();
        _requireSafeSingletonMigrator(INTERACTION, newMigrator);
        address previous = address(SAFE_SINGLETON_MIGRATOR);
        SAFE_SINGLETON_MIGRATOR = newMigrator;
        emit SafeSingletonMigratorChanged(previous, address(newMigrator));
    }

    function _authorizeUpgrade(address) internal view override {
        _requireRegistry();
    }

    /// @dev A code-only guard upgrade cannot change the only permitted Interact or singleton migrator. The
    ///      coordinated migrator release action changes the latter across factory, guard, and module atomically.
    function _chainwallSecurityBindingsHash() internal view override returns (bytes32) {
        // Shared implementations are unbound. Bound proxies authenticate their
        // singleton migrator before committing its address to the security hash.
        if (address(INTERACTION) != address(0) || address(SAFE_SINGLETON_MIGRATOR) != address(0)) {
            _requireSafeSingletonMigrator(INTERACTION, SAFE_SINGLETON_MIGRATOR);
        }
        return _hashSecurityBindings(abi.encode(address(INTERACTION), address(SAFE_SINGLETON_MIGRATOR)));
    }

    function _setBindings(Interact interact_, SafeSingletonMigrator migrator_) private {
        if (address(interact_) == address(0)) revert GuardInteractZero();
        _requireSafeSingletonMigrator(interact_, migrator_);
        INTERACTION = interact_;
        SAFE_SINGLETON_MIGRATOR = migrator_;
    }

    function _requireSafeSingletonMigrator(Interact interact_, SafeSingletonMigrator migrator_) private view {
        address migrator = address(migrator_);
        if (migrator.code.length == 0) revert GuardSafeSingletonMigratorInvalid(migrator);
        try migrator_.chainwallComponentId() returns (bytes32 componentId) {
            if (componentId != SAFE_SINGLETON_MIGRATOR_COMPONENT_ID) {
                revert GuardSafeSingletonMigratorInvalid(migrator);
            }
        } catch {
            revert GuardSafeSingletonMigratorInvalid(migrator);
        }
        address actualInteract = address(0);
        try migrator_.INTERACT() returns (address value) {
            actualInteract = value;
        } catch {
            revert GuardSafeSingletonMigratorInvalid(migrator);
        }
        if (actualInteract != address(interact_)) {
            revert GuardSafeSingletonMigratorInteractMismatch(address(interact_), actualInteract);
        }
    }

    function _requireRegistry() private view {
        if (msg.sender != address(INTERACTION.registry())) revert GuardOnlyRegistry();
    }

    /// @notice Validate Safe transactions before execution.
    /// @dev Allows (A) CALLs to Interact execution methods and (B) one singleton-migration delegatecall.
    ///      If the Safe forwards on behalf of a different actor in directExecute paths, the actor must provide a signature.
    function checkTransaction(
        address to,
        uint256,
        bytes memory data,
        Enum.Operation operation,
        uint256,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory,
        address
    ) external view override {
        // Safe reimbursements are an independent value-transfer channel. In
        // particular, ERC20 refunds use the caller-supplied gasPrice without a
        // tx.gasprice cap. Chainwall transactions therefore use no Safe-level
        // refund; relayer compensation must be policy-bound elsewhere.
        if (baseGas != 0 || gasPrice != 0 || gasToken != address(0) || refundReceiver != address(0)) {
            revert GuardRefundParametersUnsupported();
        }

        if (operation == Enum.Operation.Call) {
            require(to == address(INTERACTION), "Guard: wrong target");
            require(data.length >= 4, "Guard: malformed data");

            bytes4 selector;
            assembly ("memory-safe") {
                selector := mload(add(data, 0x20))
            }
            if (selector == Interact.directExecute.selector || selector == Interact.directExecutePrivate.selector) {
                (bytes32 policyId, address actor, bytes memory sig) = _decodeDirectPayload(data);
                _validateDirectExecute(policyId, actor, sig);
                return;
            }
            if (
                selector == Interact.execute.selector || selector == Interact.executePrivate.selector
                    || selector == Interact.approveAndExecute.selector
                    || selector == Interact.approveAndExecutePrivate.selector
            ) {
                return;
            }
            revert("Guard: unsupported selector");
        }

        if (operation == Enum.Operation.DelegateCall) {
            require(to == address(SAFE_SINGLETON_MIGRATOR), "Guard: wrong target");
            require(data.length >= 4, "Guard: malformed data");
            bytes4 selector;
            assembly ("memory-safe") {
                selector := mload(add(data, 0x20))
            }
            require(selector == SafeSingletonMigrator.migrateSafeSingleton.selector, "Guard: unsupported selector");
            return;
        }

        revert("Guard: unsupported operation");
    }

    /// @notice Safe post-hook required by the guard interface.
    /// @dev A Safe transaction with nonzero `safeTxGas` can report a failed target
    ///      call without reverting. Rejecting failure here ensures the operation,
    ///      any payment, and all preceding effects roll back atomically.
    function checkAfterExecution(
        bytes32,
        /*hash*/
        bool success
    )
        external
        pure
        override
    {
        if (!success) revert GuardExecutionFailed();
    }

    /// @dev Decode the `(policyId, actor, actorSignature)` tuple from direct-execution calldata.
    function _decodeDirectPayload(bytes memory data)
        internal
        pure
        returns (bytes32 policyId, address actor, bytes memory sig)
    {
        require(data.length >= 4, "Guard: malformed data");
        bytes memory payload = new bytes(data.length - 4);
        assembly ("memory-safe") {
            let len := mload(payload)
            let src := add(data, 0x24)
            let dst := add(payload, 0x20)
            let end := add(dst, len)
            for {} lt(dst, end) {
                dst := add(dst, 0x20)
                src := add(src, 0x20)
            } { mstore(dst, mload(src)) }
        }
        (policyId,,,,,, actor, sig) =
            abi.decode(payload, (bytes32, bytes32, uint256[], uint256, uint256, uint256, address, bytes));
    }

    /// @dev Enforce the same direct-execution actor assumptions the rest of the
    ///      runtime expects before the Safe actually sends the transaction.
    function _validateDirectExecute(bytes32 policyId, address actor, bytes memory sig) internal view {
        require(actor != address(0), "Guard: actor=0");
        require(INTERACTION.canUserSatisfyPolicy(policyId, actor), "Guard: actor cannot satisfy policy");
        // If the Safe is forwarding on behalf of a different actor, a signature must be present.
        if (actor != msg.sender) {
            require(sig.length != 0, "Guard: missing actor signature");
        } else {
            // direct calls from an owner should not include a signature when going through the Safe
            require(sig.length == 0, "Guard: unexpected signature");
        }
    }
}
