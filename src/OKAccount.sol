// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "./Delegation7702.sol";
import {IMiniScript} from "@chainwall/interfaces/IMiniScript.sol";

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {ChainwallUUPSUpgradeable} from "./ChainwallUpgradeable.sol";
import {InteractionFlags} from "./InteractionFlags.sol";
import {MiniScriptEngine} from "./MiniScriptEngine.sol";
import {ProtocolCodehashes} from "./ProtocolCodehashes.sol";
import {IRegistry} from "./registry/RegistryShared.sol";

interface IAccountInteract {
    function registry() external view returns (IRegistry);
}

/// @title OKAccount
/// @notice Minimal tenant-native account that executes registry interactions only through `Interact`.
/// @dev `OKAccount` is the account-mode counterpart to a guarded Safe:
///      - it is deployed as an atomically initialized ERC-1967 proxy bound to one
///        `Interact`, one registry, and one `MiniScriptEngine`
///      - it accepts ETH directly so it can hold execution balances
///      - it refuses all execution unless the caller is the bound `Interact`
///      - its stable vault address can be upgraded only by that tenant Registry
///
///      Example:
///      1. A user deploys an account through `AccountFactory`.
///      2. The user proposes or directly executes an interaction through `Interact`.
///      3. `Interact` calls {executeInteraction} on the account.
///      4. The account loads the script from the registry and runs it through the
///         shared engine with `address(this)` as the execution vault.
contract OKAccount is Initializable, ChainwallUUPSUpgradeable {
    bytes32 public constant CHAINWALL_COMPONENT_ID = keccak256("Chainwall.OKAccount");

    /// @notice `Interact` instance that is allowed to trigger execution.
    address public INTERACT;
    /// @notice Registry used to resolve interaction scripts.
    address public REGISTRY;
    /// @notice Shared MiniScript engine used through delegatecall.
    address public ENGINE;

    /// @notice Thrown when anyone other than the bound `Interact` calls {executeInteraction}.
    error InteractOnly();
    /// @notice Thrown when the registry address is zero during initialization.
    error RegistryZero();
    /// @notice Thrown when the engine address is zero during initialization.
    error EngineZero();
    /// @notice Thrown when the interact address is zero during initialization.
    error InteractZero();
    /// @notice Thrown when the requested interaction is deactivated in the registry.
    error InteractionInactive(bytes32 interactionId);
    /// @notice Thrown when the interact address has no deployed code during initialization.
    error InteractNotContract(address interact);
    /// @notice Thrown when the registry address has no deployed code during initialization.
    error RegistryNotContract(address registry);
    /// @notice Thrown when the engine address has no deployed code during initialization.
    error EngineNotContract(address engine);
    /// @notice Thrown when the engine runtime is not a canonical MiniScript engine.
    error EngineNotCanonical(address engine);
    /// @notice Thrown when the supplied `Interact` points at a different registry.
    error InteractRegistryMismatch(address expectedRegistry, address actualRegistry);
    /// @notice Thrown when an implementation change is attempted outside the tenant Registry.
    error OnlyRegistryUpgrade();

    event EngineChanged(address indexed previousEngine, address indexed newEngine);

    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize an account proxy bound to a single tenant execution environment.
    /// @param interact `Interact` instance allowed to trigger execution.
    /// @param registry Registry used for script lookup.
    /// @param engine Shared MiniScript engine.
    function initialize(address interact, address registry, address engine) external initializer {
        if (interact == address(0)) revert InteractZero();
        if (registry == address(0)) revert RegistryZero();
        if (engine == address(0)) revert EngineZero();
        if (!Delegation7702.hasContractCode(interact)) revert InteractNotContract(interact);
        if (!Delegation7702.hasContractCode(registry)) revert RegistryNotContract(registry);
        if (!Delegation7702.hasContractCode(engine)) revert EngineNotContract(engine);
        if (!ProtocolCodehashes.isAcceptedMiniScriptDeployment(engine)) {
            revert EngineNotCanonical(engine);
        }
        address interactRegistry = address(IAccountInteract(interact).registry());
        if (interactRegistry != registry) {
            revert InteractRegistryMismatch(registry, interactRegistry);
        }
        INTERACT = interact;
        REGISTRY = registry;
        ENGINE = engine;
        __UUPSUpgradeable_init();
    }

    /// @notice Stable logical type used by Registry upgrade verification.
    function chainwallComponentId() external pure override returns (bytes32) {
        return CHAINWALL_COMPONENT_ID;
    }

    /// @notice Upgrade entry point reserved for the tenant Registry timelock.
    function timelockUpgrade(address newImplementation, bytes calldata data) external {
        if (msg.sender != REGISTRY) revert OnlyRegistryUpgrade();
        _upgradePreservingBindings(newImplementation, data);
    }

    /// @notice Disable the ordinary UUPS surface so callers must use {timelockUpgrade}.
    function upgradeToAndCall(address, bytes memory) public payable override {
        revert("OKAccount: use timelockUpgrade");
    }

    function _authorizeUpgrade(address) internal view override {
        if (msg.sender != REGISTRY) revert OnlyRegistryUpgrade();
    }

    /// @dev These three pointers define the only execution path for account-held assets. Engine replacement is a
    ///      separate Registry action; implementation migration data may not change any tenant trust root.
    function _chainwallSecurityBindingsHash() internal view override returns (bytes32) {
        return _hashSecurityBindings(abi.encode(INTERACT, REGISTRY, ENGINE));
    }

    /// @notice Return the engine currently executing this vault's interactions.
    function chainwallEngine() external view returns (address) {
        return ENGINE;
    }

    /// @notice Adopt a canonical engine through the separately scoped Registry action.
    function setChainwallEngine(address newEngine) external {
        if (msg.sender != REGISTRY) revert OnlyRegistryUpgrade();
        if (newEngine == address(0)) revert EngineZero();
        if (!Delegation7702.hasContractCode(newEngine)) revert EngineNotContract(newEngine);
        if (!ProtocolCodehashes.isAcceptedMiniScriptDeployment(newEngine)) {
            revert EngineNotCanonical(newEngine);
        }
        address previous = ENGINE;
        ENGINE = newEngine;
        emit EngineChanged(previous, newEngine);
    }

    /// @notice Accept ETH so the account can fund native-value executions.
    receive() external payable {}

    /// @notice Canonical host authentication surface used by linked execution.
    /// @return engine Canonical immutable MiniScript engine.
    /// @return registry Registry whose catalog is authoritative for this account.
    function miniScriptHostConfig() external view returns (address engine, address registry) {
        return (ENGINE, REGISTRY);
    }

    /// @notice Execute an interaction by id in the account context.
    /// @dev The account itself becomes the execution vault and caller context
    ///      seen by downstream Safe/account-aware scripts.
    /// @param interactionId Registry interaction identifier.
    /// @param args Initial stack arguments forwarded to MiniScript.
    /// @param maxSteps Interpreter step cap enforced by the engine.
    /// @param maxNativeValue Maximum native value the script is allowed to spend.
    /// @param actor Authenticated policy actor exposed through subject context.
    /// @param policyId Policy selected for this execution.
    /// @return stackTop Final value left on top of the MiniScript stack.
    function executeInteraction(
        bytes32 interactionId,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 maxNativeValue,
        address actor,
        bytes32 policyId
    ) external returns (uint256 stackTop) {
        if (msg.sender != INTERACT) revert InteractOnly();
        uint256 flags = IRegistry(REGISTRY).getInteractionFlags(interactionId);
        if (InteractionFlags.isInactive(flags)) {
            revert InteractionInactive(interactionId);
        }
        bytes memory script = IRegistry(REGISTRY).getInteractionScript(interactionId);
        require(script.length != 0, "interaction:not-found");
        IMiniScript.SubjectContext memory subject = IMiniScript.SubjectContext({
            version: 2,
            interactionId: interactionId,
            nativeValue: maxNativeValue,
            actor: actor,
            vault: address(this),
            policyId: policyId,
            interactionArgs: args
        });
        bytes memory data = abi.encodeWithSelector(
            MiniScriptEngine.runSubject.selector, script, args, maxSteps, REGISTRY, subject, maxNativeValue, ENGINE
        );
        // Only INTERACT can execute; initialization and Registry-only engine updates require the canonical
        // deployment.
        // forge-lint: disable-next-line(controlled-delegatecall)
        (bool ok, bytes memory ret) = ENGINE.delegatecall(data);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        stackTop = abi.decode(ret, (uint256));
    }
}
