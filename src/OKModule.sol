// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Safe} from "@gnosis.pm/safe-contracts/Safe.sol";
import {Enum} from "@gnosis.pm/safe-contracts/libraries/Enum.sol";
import {IProxy} from "@gnosis.pm/safe-contracts/proxies/SafeProxy.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {ChainwallUUPSUpgradeable} from "./ChainwallUpgradeable.sol";
import {Interact} from "./Interact.sol";
import {StoredBundleRevealPayload as RevealPayload} from "./RegistryTypes.sol";
import {SafeSingletonMigrator} from "./SafeSingletonMigrator.sol";
import {SignedActorTrailer} from "./SignedActorTrailer.sol";

/**
 * @title OKModule
 * @notice Safe module that lets approved Interact operations execute without requiring Safe owner signatures.
 *         The module is shared across Safes inside a tenant; a Safe must explicitly enable it before use.
 * @dev Module calls execute via Safe's module pathway and do not consume the Safe nonce.
 *      In the common flow from the tests:
 *      1. `Interact.propose` records an operation for a specific Safe.
 *      2. Safe owners approve through the registry policy flow.
 *      3. A relayer calls this enabled module, which asks the Safe to forward the final call to
 *         `Interact` after validating the required actor authorization.
 */
contract OKModule is ReentrancyGuard, ChainwallUUPSUpgradeable {
    bytes32 public constant CHAINWALL_COMPONENT_ID = keccak256("Chainwall.OKModule");
    bytes32 private constant SAFE_SINGLETON_MIGRATOR_COMPONENT_ID = keccak256("Chainwall.SafeSingletonMigrator");

    /// @notice Safe extension policy used for both modules and fallback handlers.
    /// @dev The zero value is intentionally the strict production default.
    enum ExtensionPolicy {
        Strict,
        Permissive,
        Allowlist
    }

    /// @notice Tenant-local Interact instance that validates and runs interactions.
    Interact public INTERACTION;
    /// @notice One-purpose delegatecall target used for singleton migrations.
    SafeSingletonMigrator public SAFE_SINGLETON_MIGRATOR;
    address private constant SENTINEL_MODULES = address(0x1);
    uint256 private constant MODULE_PAGE_SIZE = 16;
    uint256 private constant MODULE_PAGE_LIMIT = 16;
    bytes32 private constant FALLBACK_HANDLER_STORAGE_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    bytes32 private constant MODULE_GUARD_STORAGE_SLOT =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    mapping(address => ExtensionPolicy) private _modulePolicy;
    mapping(address => ExtensionPolicy) private _fallbackPolicy;
    mapping(address => address[]) private _allowedModuleList;
    mapping(address => address[]) private _allowedFallbackHandlerList;
    mapping(address => mapping(address => bool)) private _allowedModules;
    mapping(address => mapping(address => bool)) private _allowedFallbackHandlers;
    error ModuleSafeOnly(address caller, address safe);
    error ModuleInvalidPolicy(uint8 policy);
    error ModulePolicyNotStrict(address safe);
    error ModuleExtensionNotAllowed(address safe, address module);
    error ModuleFallbackNotAllowed(address safe, address handler);
    error ModuleGuardNotAllowed(address safe, address moduleGuard);
    error ModulePaginationLimit(address safe);
    error ModuleOwnerConfigNotAllowed(address safe, uint256 ownerCount, uint256 threshold);
    error ModuleActorAmbiguous();
    error ModuleActorSignatureRequired();
    error ModuleActorDeadlineRequired();
    error ModuleSafeSingletonMigratorInvalid(address migrator);
    error ModuleSafeSingletonMigratorInteractMismatch(address expectedInteract, address actualInteract);
    error ModuleOnlyRegistry();
    error ModuleSafeSingletonInvalid(address singleton, bytes32 expectedCodehash, bytes32 actualCodehash);
    error ModuleSafeSingletonUnchanged(address safe, address singleton);
    error ModuleSafeSingletonMigrationFailed(address safe, bytes32 reasonHash);
    error ModuleSafeSingletonMismatch(address safe, address expected, address actual);
    error ModuleSafeFactoryMismatch(address expected, address actual);
    error ModuleExecutionGatewayMissing(address safe, address gateway);

    /// @notice Emitted after a queued interaction runs through a Safe module call.
    event ModuleInteractionExecuted(
        address indexed safe, uint256 indexed operationId, bytes32 indexed interactionId, uint256 stackTop
    );
    /// @notice Emitted after a direct-execute path runs through a Safe module call.
    event ModuleDirectExecuted(address indexed safe, bytes32 indexed interactionId, uint256 stackTop);
    /// @notice Emitted when a Safe opts into a non-default extension policy.
    event SafeExtensionPolicyConfigured(
        address indexed safe, ExtensionPolicy modulePolicy, ExtensionPolicy fallbackPolicy
    );
    event SafeSingletonMigratorChanged(address indexed previousMigrator, address indexed newMigrator);
    event SafeSingletonMigrated(
        address indexed safe, address indexed previousSingleton, address indexed newSingleton, bytes32 newCodehash
    );

    /// @notice Deploy the module for a specific tenant runtime.
    /// @param interact Interact instance that owns the operation queue and execution checks.
    /// @param migrator Delegatecall target used for Safe singleton migrations.
    /// @dev The `(0, 0)` pair is reserved for a locked, shared implementation
    ///      whose tenant bindings are written only in proxy storage by {initialize}.
    constructor(Interact interact, SafeSingletonMigrator migrator) {
        if (address(interact) != address(0) || address(migrator) != address(0)) {
            _setBindings(interact, migrator);
        }
        _disableInitializers();
    }

    /// @notice Atomically bind a newly deployed module proxy to one tenant runtime.
    function initialize(Interact interact, SafeSingletonMigrator migrator) external initializer {
        _setBindings(interact, migrator);
        __UUPSUpgradeable_init();
        // The non-upgradeable ReentrancyGuard stores zero in a proxy until the
        // first call; zero is unlocked and that call normalizes it to NOT_ENTERED.
    }

    /// @notice Stable logical type used by Registry upgrade verification.
    function chainwallComponentId() external pure override returns (bytes32) {
        return CHAINWALL_COMPONENT_ID;
    }

    /// @notice Upgrade this installed module without changing the address enabled by its Safes.
    function timelockUpgrade(address newImplementation, bytes calldata data) external {
        _requireRegistry();
        _upgradePreservingBindings(newImplementation, data);
    }

    /// @notice Disable the ordinary UUPS surface so all persistent upgrades use the Registry timelock.
    function upgradeToAndCall(address, bytes memory) public payable override {
        revert("OKModule: use timelockUpgrade");
    }

    /// @notice Replace singleton-migration code while retaining this enabled module address.
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

    /// @dev An enabled module is a persistent Safe authority. Its Interact and singleton migrator therefore cannot be
    ///      redirected by implementation migration data; migrator changes use the coordinated release action.
    function _chainwallSecurityBindingsHash() internal view override returns (bytes32) {
        // Shared implementations are unbound. Bound proxies authenticate their
        // singleton migrator before committing its address to the security hash.
        if (address(INTERACTION) != address(0) || address(SAFE_SINGLETON_MIGRATOR) != address(0)) {
            _requireSafeSingletonMigrator(INTERACTION, SAFE_SINGLETON_MIGRATOR);
        }
        return _hashSecurityBindings(abi.encode(address(INTERACTION), address(SAFE_SINGLETON_MIGRATOR)));
    }

    function _setBindings(Interact interact, SafeSingletonMigrator migrator) private {
        require(address(interact) != address(0), "Module: interact=0x0");
        _requireSafeSingletonMigrator(interact, migrator);
        INTERACTION = interact;
        SAFE_SINGLETON_MIGRATOR = migrator;
    }

    function _requireSafeSingletonMigrator(Interact interact, SafeSingletonMigrator migrator) private view {
        address migratorAddress = address(migrator);
        if (migratorAddress.code.length == 0) revert ModuleSafeSingletonMigratorInvalid(migratorAddress);
        try migrator.chainwallComponentId() returns (bytes32 componentId) {
            if (componentId != SAFE_SINGLETON_MIGRATOR_COMPONENT_ID) {
                revert ModuleSafeSingletonMigratorInvalid(migratorAddress);
            }
        } catch {
            revert ModuleSafeSingletonMigratorInvalid(migratorAddress);
        }
        address actualInteract = address(0);
        try migrator.INTERACT() returns (address value) {
            actualInteract = value;
        } catch {
            revert ModuleSafeSingletonMigratorInvalid(migratorAddress);
        }
        if (actualInteract != address(interact)) {
            revert ModuleSafeSingletonMigratorInteractMismatch(address(interact), actualInteract);
        }
    }

    function _requireRegistry() private view {
        if (msg.sender != address(INTERACTION.registry())) revert ModuleOnlyRegistry();
    }

    /// @notice Migrate one enabled managed Safe to an exact singleton release.
    /// @dev The Registry upgrade facet calls this through a timelock. The Safe itself authorizes this module through
    ///      its module list; strict extension and 1-of-1 checks are revalidated before touching slot zero.
    function migrateSafeSingleton(address safeFactory, address safe, address newSingleton, bytes32 expectedCodehash)
        external
        nonReentrant
    {
        _requireRegistry();
        address expectedSafeFactory = SAFE_SINGLETON_MIGRATOR.SAFE_FACTORY();
        if (safeFactory != expectedSafeFactory) {
            revert ModuleSafeFactoryMismatch(expectedSafeFactory, safeFactory);
        }
        Safe targetSafe = _checkedSafe(safe);
        bytes32 actualCodehash = newSingleton.codehash;
        if (newSingleton.code.length == 0 || actualCodehash != expectedCodehash) {
            revert ModuleSafeSingletonInvalid(newSingleton, expectedCodehash, actualCodehash);
        }
        address previousSingleton = IProxy(safe).masterCopy();
        if (previousSingleton == newSingleton) revert ModuleSafeSingletonUnchanged(safe, newSingleton);

        bytes memory data = abi.encodeCall(SafeSingletonMigrator.migrateSafeSingleton, (newSingleton, expectedCodehash));
        // Every caller of this Safe execution path holds the same nonReentrant guard through the post-call checks.
        // forge-lint: disable-start(reentrancy-no-eth)
        (bool success, bytes memory returnData) = targetSafe.execTransactionFromModuleReturnData(
            address(SAFE_SINGLETON_MIGRATOR), 0, data, Enum.Operation.DelegateCall
        );
        // forge-lint: disable-end(reentrancy-no-eth)
        if (!success) revert ModuleSafeSingletonMigrationFailed(safe, keccak256(returnData));

        address installed = IProxy(safe).masterCopy();
        if (installed != newSingleton) revert ModuleSafeSingletonMismatch(safe, newSingleton, installed);
        // The Safe execution entrypoint holds nonReentrant through result validation and this completion event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit SafeSingletonMigrated(safe, previousSingleton, newSingleton, expectedCodehash);
    }

    /// @notice Configure extension policy for one Safe.
    /// @dev Must be called by the Safe itself, e.g. through setup/import delegatecall or an approved Safe action.
    function configureSafeExtensions(
        address safe,
        ExtensionPolicy modulePolicy,
        address[] calldata allowedModules,
        ExtensionPolicy fallbackPolicy,
        address[] calldata allowedFallbackHandlers
    ) external {
        require(safe != address(0), "Module: safe=0x0");
        if (msg.sender != safe) {
            revert ModuleSafeOnly(msg.sender, safe);
        }
        _setPolicy(safe, modulePolicy, fallbackPolicy);
        _replaceAllowedModules(safe, allowedModules);
        _replaceAllowedFallbackHandlers(safe, allowedFallbackHandlers);
        _enforceSafeExtensions(Safe(payable(safe)), safe);
        emit SafeExtensionPolicyConfigured(safe, modulePolicy, fallbackPolicy);
    }

    /// @notice Validate the current Safe extension state against the configured policy.
    function validateSafeExtensions(address safe) external view {
        require(safe != address(0), "Module: safe=0x0");
        Safe targetSafe = Safe(payable(safe));
        _enforceSafeExtensions(targetSafe, safe);
    }

    /// @notice Validate legacy imports without leaving a non-strict policy active for later execution.
    /// @dev The legacy signed payload cannot reset policy. Reject both Permissive and Allowlist policies,
    ///      even if the current extension list happens to satisfy Strict.
    function validateStrictSafeExtensions(address safe) external view {
        require(safe != address(0), "Module: safe=0x0");
        if (_modulePolicy[safe] != ExtensionPolicy.Strict || _fallbackPolicy[safe] != ExtensionPolicy.Strict) {
            revert ModulePolicyNotStrict(safe);
        }
        _enforceSafeExtensions(Safe(payable(safe)), safe);
    }

    /// @notice Whether other enabled modules are checked for this Safe. Unconfigured Safes default to true.
    /// @dev Allowlist policy still checks every module; only Permissive skips the module list check.
    function moduleCheckEnabled(address safe) external view returns (bool) {
        return _modulePolicy[safe] != ExtensionPolicy.Permissive;
    }

    /// @notice Execute an approved Interact operation via a Safe module call.
    /// @param safe Address of the Safe that enabled this module.
    /// @param operationId Operation identifier created in Interact.
    /// @param interactionId MiniScript interaction identifier.
    /// @param args Arguments forwarded to the MiniScript interpreter.
    /// @param maxSteps Interpreter iteration cap.
    /// @param nativeValue ETH value the Safe should forward to Interact.
    /// @dev Reverts if the module is not enabled or `nativeValue` mismatches the stored operation value.
    function executeInteraction(
        address safe,
        uint256 operationId,
        bytes32 interactionId,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 nativeValue
    ) external nonReentrant returns (uint256 stackTop) {
        Safe targetSafe = _checkedSafe(safe);

        address operationSafe = INTERACTION.getOperationSafe(operationId);
        require(operationSafe == safe, "Module:safe-mismatch");

        uint256 expectedNativeValue = INTERACTION.getOperationNativeValue(operationId);
        require(nativeValue == expectedNativeValue, "Module:native-mismatch");

        bytes memory data =
            abi.encodeWithSelector(Interact.execute.selector, operationId, interactionId, args, maxSteps);
        bytes memory forwarded = _maybeAppendActorTrailer(data);

        // Every caller of this Safe execution path holds the same nonReentrant guard through the post-call checks.
        // forge-lint: disable-start(reentrancy-no-eth)
        (bool success, bytes memory ret) = targetSafe.execTransactionFromModuleReturnData(
            address(INTERACTION), nativeValue, forwarded, Enum.Operation.Call
        );
        // forge-lint: disable-end(reentrancy-no-eth)

        if (!success) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }

        stackTop = abi.decode(ret, (uint256));
        // The Safe execution entrypoint holds nonReentrant through result validation and this completion event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ModuleInteractionExecuted(safe, operationId, interactionId, stackTop);
    }

    /// @notice Execute an approved private interaction via a Safe module call.
    function executeInteractionPrivate(
        address safe,
        uint256 operationId,
        bytes32 interactionId,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 nativeValue,
        RevealPayload calldata reveal
    ) external nonReentrant returns (uint256 stackTop) {
        Safe targetSafe = _checkedSafe(safe);

        address operationSafe = INTERACTION.getOperationSafe(operationId);
        require(operationSafe == safe, "Module:safe-mismatch");

        uint256 expectedNativeValue = INTERACTION.getOperationNativeValue(operationId);
        require(nativeValue == expectedNativeValue, "Module:native-mismatch");

        bytes memory data = abi.encodeWithSelector(
            Interact.executePrivate.selector, operationId, interactionId, args, maxSteps, reveal
        );
        bytes memory forwarded = _maybeAppendActorTrailer(data);

        // Every caller of this Safe execution path holds the same nonReentrant guard through the post-call checks.
        // forge-lint: disable-start(reentrancy-no-eth)
        (bool success, bytes memory ret) = targetSafe.execTransactionFromModuleReturnData(
            address(INTERACTION), nativeValue, forwarded, Enum.Operation.Call
        );
        // forge-lint: disable-end(reentrancy-no-eth)

        if (!success) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }

        stackTop = abi.decode(ret, (uint256));
        // The Safe execution entrypoint holds nonReentrant through result validation and this completion event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ModuleInteractionExecuted(safe, operationId, interactionId, stackTop);
    }

    /// @notice Approve and execute an Interact operation via a Safe module call.
    /// @dev Useful when the current Safe owner is the last approval needed by the bound policy.
    function approveAndExecuteInteraction(
        address safe,
        uint256 operationId,
        bytes32 interactionId,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 nativeValue
    ) external nonReentrant returns (uint256 stackTop) {
        Safe targetSafe = _checkedSafe(safe);

        address operationSafe = INTERACTION.getOperationSafe(operationId);
        require(operationSafe == safe, "Module:safe-mismatch");

        uint256 expectedNativeValue = INTERACTION.getOperationNativeValue(operationId);
        require(nativeValue == expectedNativeValue, "Module:native-mismatch");

        bytes memory data =
            abi.encodeWithSelector(Interact.approveAndExecute.selector, operationId, interactionId, args, maxSteps);
        bytes memory forwarded = _maybeAppendActorTrailer(data);

        // Every caller of this Safe execution path holds the same nonReentrant guard through the post-call checks.
        // forge-lint: disable-start(reentrancy-no-eth)
        (bool success, bytes memory ret) = targetSafe.execTransactionFromModuleReturnData(
            address(INTERACTION), nativeValue, forwarded, Enum.Operation.Call
        );
        // forge-lint: disable-end(reentrancy-no-eth)

        if (!success) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }

        stackTop = abi.decode(ret, (uint256));
        // The Safe execution entrypoint holds nonReentrant through result validation and this completion event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ModuleInteractionExecuted(safe, operationId, interactionId, stackTop);
    }

    /// @notice Approve and execute a private interaction via a Safe module call.
    function approveAndExecuteInteractionPrivate(
        address safe,
        uint256 operationId,
        bytes32 interactionId,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 nativeValue,
        RevealPayload calldata reveal
    ) external nonReentrant returns (uint256 stackTop) {
        Safe targetSafe = _checkedSafe(safe);

        address operationSafe = INTERACTION.getOperationSafe(operationId);
        require(operationSafe == safe, "Module:safe-mismatch");

        uint256 expectedNativeValue = INTERACTION.getOperationNativeValue(operationId);
        require(nativeValue == expectedNativeValue, "Module:native-mismatch");

        bytes memory data = abi.encodeWithSelector(
            Interact.approveAndExecutePrivate.selector, operationId, interactionId, args, maxSteps, reveal
        );
        bytes memory forwarded = _maybeAppendActorTrailer(data);

        // Every caller of this Safe execution path holds the same nonReentrant guard through the post-call checks.
        // forge-lint: disable-start(reentrancy-no-eth)
        (bool success, bytes memory ret) = targetSafe.execTransactionFromModuleReturnData(
            address(INTERACTION), nativeValue, forwarded, Enum.Operation.Call
        );
        // forge-lint: disable-end(reentrancy-no-eth)

        if (!success) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }

        stackTop = abi.decode(ret, (uint256));
        // The Safe execution entrypoint holds nonReentrant through result validation and this completion event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ModuleInteractionExecuted(safe, operationId, interactionId, stackTop);
    }

    /// @notice Direct execute an interaction via a Safe module call.
    /// @dev Skips the queued-operation path when the supplied signed actor alone satisfies the target policy.
    ///      Permissionless module callers cannot use the unsigned Safe self-call convention reserved for
    ///      owner-authorized Safe transactions.
    function directExecuteInteraction(
        address safe,
        bytes32 policyId,
        bytes32 interactionId,
        uint256[] calldata args,
        uint256 maxSteps,
        address actor,
        bytes calldata actorSignature,
        uint256 nativeValue,
        uint256 deadline
    ) external nonReentrant returns (uint256 stackTop) {
        Safe targetSafe = _checkedSafe(safe);

        (address resolvedActor, bytes memory resolvedSignature) = _resolveActor(actor, actorSignature);
        _requireDirectActorProof(resolvedSignature, deadline);
        bytes memory data = abi.encodeWithSelector(
            Interact.directExecute.selector,
            policyId,
            interactionId,
            args,
            maxSteps,
            nativeValue,
            deadline,
            resolvedActor,
            resolvedSignature
        );

        (
            bool success,
            bytes memory ret
            // Every caller of this Safe execution path holds the same nonReentrant guard through the post-call
            // checks.
            // forge-lint: disable-next-line(reentrancy-no-eth)
        ) = targetSafe.execTransactionFromModuleReturnData(address(INTERACTION), nativeValue, data, Enum.Operation.Call);

        if (!success) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }

        stackTop = abi.decode(ret, (uint256));
        // The Safe execution entrypoint holds nonReentrant through result validation and this completion event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ModuleDirectExecuted(safe, interactionId, stackTop);
    }

    /// @notice Direct execute a private interaction via a Safe module call.
    /// @dev Requires the same finite, signed actor authorization as the public direct path.
    function directExecuteInteractionPrivate(
        address safe,
        bytes32 policyId,
        bytes32 interactionId,
        uint256[] calldata args,
        uint256 maxSteps,
        address actor,
        bytes calldata actorSignature,
        uint256 nativeValue,
        uint256 deadline,
        RevealPayload calldata reveal
    ) external nonReentrant returns (uint256 stackTop) {
        Safe targetSafe = _checkedSafe(safe);

        (address resolvedActor, bytes memory resolvedSignature) = _resolveActor(actor, actorSignature);
        _requireDirectActorProof(resolvedSignature, deadline);
        bytes memory data = abi.encodeWithSelector(
            Interact.directExecutePrivate.selector,
            policyId,
            interactionId,
            args,
            maxSteps,
            nativeValue,
            deadline,
            resolvedActor,
            resolvedSignature,
            reveal
        );

        (
            bool success,
            bytes memory ret
            // Every caller of this Safe execution path holds the same nonReentrant guard through the post-call
            // checks.
            // forge-lint: disable-next-line(reentrancy-no-eth)
        ) = targetSafe.execTransactionFromModuleReturnData(address(INTERACTION), nativeValue, data, Enum.Operation.Call);

        if (!success) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }

        stackTop = abi.decode(ret, (uint256));
        // The Safe execution entrypoint holds nonReentrant through result validation and this completion event.
        // forge-lint: disable-next-line(reentrancy-events)
        emit ModuleDirectExecuted(safe, interactionId, stackTop);
    }

    /// @notice Preserve an optional versioned signed-actor trailer when forwarding through the Safe.
    /// @dev Dynamic trailers support both 65-byte EOA signatures and ERC-1271/WebAuthn payloads.
    function _maybeAppendActorTrailer(bytes memory data) internal pure returns (bytes memory) {
        (bool present, address actor, bytes memory signature) = SignedActorTrailer.decode(msg.data);
        return present ? SignedActorTrailer.append(data, actor, signature) : data;
    }

    /// @dev Direct calls retain their original ABI, but a caller may instead
    ///      provide the actor in the shared trailer.
    ///      Rejecting both forms together prevents conflicting authorities.
    function _resolveActor(address explicitActor, bytes calldata explicitSignature)
        private
        pure
        returns (address actor, bytes memory signature)
    {
        (bool present, address trailerActor, bytes memory trailerSignature) = SignedActorTrailer.decode(msg.data);
        if (!present) return (explicitActor, explicitSignature);
        if (explicitActor != address(0) || explicitSignature.length != 0) revert ModuleActorAmbiguous();
        return (trailerActor, trailerSignature);
    }

    /// @dev Module calls are permissionless transports. Unlike an owner-authorized
    ///      Safe transaction, they must never inherit the Safe's self-call shortcut.
    function _requireDirectActorProof(bytes memory actorSignature, uint256 deadline) private pure {
        if (actorSignature.length == 0) revert ModuleActorSignatureRequired();
        if (deadline == 0) revert ModuleActorDeadlineRequired();
    }

    function _checkedSafe(address safe) internal view returns (Safe targetSafe) {
        require(safe != address(0), "Module: safe=0x0");
        targetSafe = Safe(payable(safe));
        require(targetSafe.isModuleEnabled(address(this)), "Module: disabled");
        _enforceSafeExtensions(targetSafe, safe);
    }

    function _setPolicy(address safe, ExtensionPolicy modulePolicy, ExtensionPolicy fallbackPolicy) private {
        _requireKnownPolicy(modulePolicy);
        _requireKnownPolicy(fallbackPolicy);
        _modulePolicy[safe] = modulePolicy;
        _fallbackPolicy[safe] = fallbackPolicy;
    }

    function _requireKnownPolicy(ExtensionPolicy policy) private pure {
        if (uint8(policy) > uint8(ExtensionPolicy.Allowlist)) {
            revert ModuleInvalidPolicy(uint8(policy));
        }
    }

    function _replaceAllowedModules(address safe, address[] calldata allowedModules) private {
        address[] storage existing = _allowedModuleList[safe];
        for (uint256 i; i < existing.length; ++i) {
            delete _allowedModules[safe][existing[i]];
        }
        delete _allowedModuleList[safe];
        for (uint256 i; i < allowedModules.length; ++i) {
            address module = allowedModules[i];
            // Every installed module must satisfy the extension policy; pagination failure cannot authorize an
            // unchecked remainder.
            // forge-lint: disable-next-line(require-revert-in-loop)
            require(module != address(0) && module != SENTINEL_MODULES, "Module: bad module");
            if (module == address(this) || _allowedModules[safe][module]) {
                continue;
            }
            _allowedModules[safe][module] = true;
            _allowedModuleList[safe].push(module);
        }
    }

    function _replaceAllowedFallbackHandlers(address safe, address[] calldata allowedHandlers) private {
        address[] storage existing = _allowedFallbackHandlerList[safe];
        for (uint256 i; i < existing.length; ++i) {
            delete _allowedFallbackHandlers[safe][existing[i]];
        }
        delete _allowedFallbackHandlerList[safe];
        for (uint256 i; i < allowedHandlers.length; ++i) {
            address handler = allowedHandlers[i];
            if (handler == address(0) || _allowedFallbackHandlers[safe][handler]) {
                continue;
            }
            _allowedFallbackHandlers[safe][handler] = true;
            _allowedFallbackHandlerList[safe].push(handler);
        }
    }

    function _enforceSafeExtensions(Safe targetSafe, address safe) private view {
        address gateway = address(INTERACTION);
        if (!targetSafe.isModuleEnabled(gateway)) {
            revert ModuleExecutionGatewayMissing(safe, gateway);
        }
        if (targetSafe.isModuleEnabled(address(this))) {
            _enforceSingleOwnerThreshold(targetSafe, safe);
        }
        _enforceModulePolicy(targetSafe, safe);
        _enforceFallbackPolicy(targetSafe, safe);
        _enforceNoModuleGuard(targetSafe, safe);
    }

    function _enforceSingleOwnerThreshold(Safe targetSafe, address safe) private view {
        uint256 ownerCount = targetSafe.getOwners().length;
        uint256 threshold = targetSafe.getThreshold();
        if (ownerCount != 1 || threshold != 1) {
            revert ModuleOwnerConfigNotAllowed(safe, ownerCount, threshold);
        }
    }

    function _enforceModulePolicy(Safe targetSafe, address safe) private view {
        ExtensionPolicy policy = _modulePolicy[safe];
        if (policy == ExtensionPolicy.Permissive) {
            return;
        }

        address start = SENTINEL_MODULES;
        for (uint256 page; page < MODULE_PAGE_LIMIT; ++page) {
            // Module pagination is bounded by MODULE_PAGE_LIMIT and uses STATICCALL; every returned module must be
            // checked.
            // forge-lint: disable-next-line(calls-loop)
            (address[] memory modules, address next) = targetSafe.getModulesPaginated(start, MODULE_PAGE_SIZE);
            for (uint256 i; i < modules.length; ++i) {
                address module = modules[i];
                if (module == address(this) || module == address(INTERACTION)) {
                    continue;
                }
                if (policy != ExtensionPolicy.Allowlist || !_allowedModules[safe][module]) {
                    // Every installed module must satisfy the extension policy; pagination failure cannot authorize
                    // an unchecked remainder.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert ModuleExtensionNotAllowed(safe, module);
                }
            }
            if (next == SENTINEL_MODULES) {
                return;
            }
            // Safe versions before 1.4 return the first unreturned module as
            // `next`, while newer versions return the last returned module.
            // The last returned module is an exclusive cursor for both.
            if (modules.length == 0) {
                // Every installed module must satisfy the extension policy; pagination failure cannot authorize an
                // unchecked remainder.
                // forge-lint: disable-next-line(require-revert-in-loop)
                revert ModulePaginationLimit(safe);
            }
            start = modules[modules.length - 1];
        }
        revert ModulePaginationLimit(safe);
    }

    function _enforceFallbackPolicy(Safe targetSafe, address safe) private view {
        ExtensionPolicy policy = _fallbackPolicy[safe];
        if (policy == ExtensionPolicy.Permissive) {
            return;
        }

        address handler = _fallbackHandler(targetSafe);
        if (handler == address(0)) {
            return;
        }
        if (policy != ExtensionPolicy.Allowlist || !_allowedFallbackHandlers[safe][handler]) {
            revert ModuleFallbackNotAllowed(safe, handler);
        }
    }

    function _fallbackHandler(Safe targetSafe) private view returns (address handler) {
        bytes memory value = targetSafe.getStorageAt(uint256(FALLBACK_HANDLER_STORAGE_SLOT), 1);
        handler = abi.decode(value, (address));
    }

    /// @dev Safe 1.4+ module guards can veto this module after all Chainwall checks pass.
    ///      No module-guard compatibility policy exists yet, so managed module Safes require the slot to stay empty.
    function _enforceNoModuleGuard(Safe targetSafe, address safe) private view {
        bytes memory value = targetSafe.getStorageAt(uint256(MODULE_GUARD_STORAGE_SLOT), 1);
        address moduleGuard = abi.decode(value, (address));
        if (moduleGuard != address(0)) revert ModuleGuardNotAllowed(safe, moduleGuard);
    }
}
