// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "./Delegation7702.sol";
import {IMiniScript} from "@chainwall/interfaces/IMiniScript.sol";

import {MiniScriptEngine} from "./MiniScriptEngine.sol";
import {ProtocolCodehashes} from "./ProtocolCodehashes.sol";

interface ITimelockPolicyProgramRunner {
    function runPolicyProgram(bytes calldata script, uint256[] calldata args, uint256 maxSteps)
        external
        returns (uint256 stackTop);
}

/// @title TimelockPolicyProgramRunner
/// @notice Non-upgradeable MiniScript runner dedicated to timelock policy programs.
/// @dev The registry calls {runPolicyProgram} after opening policy-state authority for this runner. The runner has no owner,
///      no upgrade path, and no mutable configuration after construction. It executes through a canonical
///      MiniScriptEngine using the registry as both the authorized caller and MiniScript actor, matching the
///      previous `MiniScript`-proxy runner shape without inheriting proxy upgrade risk. The registry validates this
///      runtime and the engine runtime to prevent a spoofed runner from returning success without executing MiniScript,
///      or from delegatecalling into custom engine code while policy-state authority is open.
contract TimelockPolicyProgramRunner {
    /// @notice Registry whose timelock facet may invoke {runPolicyProgram}.
    address public registry;
    /// @notice Caller authorized to invoke {run}; equal to {registry}.
    address public authorizedCaller;
    /// @notice Canonical MiniScriptEngine used through delegatecall.
    address public engine;

    error RegistryZero();
    error OnlyAuthorizedCaller();
    error EngineZero();
    error EngineNotContract(address engine);
    error EngineNotCanonical(address engine);

    event EngineInitialized(address indexed engine);

    /// @notice Create a runner bound to one registry and one canonical engine.
    /// @param registry_ Registry dispatcher that may execute policy programs through this runner.
    /// @param engine_ Canonical MiniScriptEngine used through delegatecall.
    // _requireCanonicalEngine rejects zero and noncanonical code before storing the engine.
    // forge-lint: disable-next-line(missing-zero-check)
    constructor(address registry_, address engine_) {
        if (registry_ == address(0)) revert RegistryZero();
        _requireCanonicalEngine(engine_);
        registry = registry_;
        authorizedCaller = registry_;
        engine = engine_;
        emit EngineInitialized(engine_);
    }

    function _requireCanonicalEngine(address engine_) private view {
        if (engine_ == address(0)) revert EngineZero();
        if (!Delegation7702.hasContractCode(engine_)) revert EngineNotContract(engine_);
        if (!ProtocolCodehashes.isAcceptedMiniScriptDeployment(engine_)) {
            revert EngineNotCanonical(engine_);
        }
    }

    /// @notice Canonical MiniScript host configuration used by the engine.
    /// @return engine_ Canonical immutable MiniScript engine.
    /// @return registry_ Registry whose policy and catalog state is authoritative.
    function miniScriptHostConfig() external view returns (address engine_, address registry_) {
        return (engine, registry);
    }

    /// @notice Execute a timelock policy MiniScript program.
    /// @param script MiniScript bytecode stored on the live policy.
    /// @param args Timelock execution context words supplied by the registry.
    /// @param maxSteps Interpreter step cap.
    /// @return stackTop Final value left on top of the MiniScript stack.
    function runPolicyProgram(bytes calldata script, uint256[] calldata args, uint256 maxSteps)
        external
        returns (uint256 stackTop)
    {
        if (msg.sender != authorizedCaller) revert OnlyAuthorizedCaller();
        address engine_ = engine;
        if (engine_ == address(0)) revert EngineZero();
        IMiniScript.SubjectContext memory subject = IMiniScript.SubjectContext({
            version: 2,
            interactionId: bytes32(args[2]),
            nativeValue: 0,
            actor: msg.sender,
            vault: registry,
            policyId: bytes32(args[1]),
            interactionArgs: args
        });
        bytes memory data = abi.encodeWithSelector(
            MiniScriptEngine.runSubject.selector, script, args, maxSteps, registry, subject, 0, engine_
        );
        // Only the bound Registry can execute; the constructor validates the canonical engine and there is no
        // engine setter.
        // forge-lint: disable-next-line(controlled-delegatecall)
        (bool ok, bytes memory ret) = engine_.delegatecall(data);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        stackTop = abi.decode(ret, (uint256));
    }
}
