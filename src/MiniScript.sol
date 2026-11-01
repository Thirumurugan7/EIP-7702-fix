// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {IMiniScript} from "@chainwall/interfaces/IMiniScript.sol";

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {ChainwallUUPSUpgradeable} from "./ChainwallUpgradeable.sol";
import {MiniScriptBytecode} from "./MiniScriptBytecode.sol";
import {MiniScriptEngine} from "./MiniScriptEngine.sol";
import {ProtocolCodehashes} from "./ProtocolCodehashes.sol";
import {IRegistry} from "./registry/RegistryShared.sol";

/// @title MiniScript - a minimal on-chain scripting interpreter
/// @notice Shared zero-value execution host for Registry policy programs.
/// @dev Vault interactions run the canonical engine directly in their vault context.
///      This host exists only so Interact can evaluate policy MiniScript without
///      giving policy programs the vault's ambient authority or native balance.
///
///      MiniScriptEngine implements opcode execution; MiniScriptBytecode decodes instructions.
/// @author Henri Binsztok
/// @dev Runtime calls use `authorizedCaller`; upgrades require the Registry.
contract MiniScript is Initializable, ReentrancyGuardUpgradeable, ChainwallUUPSUpgradeable {
    bytes32 public constant CHAINWALL_COMPONENT_ID = keccak256("Chainwall.MiniScript");

    IRegistry public registry;
    address public trustedForwarder;
    address public authorizedCaller;
    address public engine;

    /// @notice Emitted when a proxy binds its canonical execution engine.
    event EngineInitialized(address indexed engine);
    event EngineChanged(address indexed previousEngine, address indexed newEngine);

    /// @notice Lock the implementation contract against direct initialization.
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize a tenant MiniScript proxy with a predeployed canonical engine.
    /// @param registry_ Registry used to resolve contract hashes and interactions.
    /// @param authorizedCaller_ Contract permitted to invoke {run} (typically Interact).
    /// @param trustedForwarder_ Optional EIP-2771 trusted forwarder used for caller resolution.
    /// @param engine_ Canonical MiniScriptEngine used through delegatecall.
    function initializeWithEngine(
        IRegistry registry_,
        address authorizedCaller_,
        address trustedForwarder_,
        address engine_
    ) external initializer {
        _initialize(registry_, authorizedCaller_, trustedForwarder_, engine_);
    }

    /// @notice Thrown when a Registry-only operation is called by another address.
    error OnlyRegistry();
    /// @notice Thrown when script execution is requested by an address other than Interact.
    error OnlyAuthorizedCaller();
    /// @notice Thrown when no execution engine is configured.
    error EngineZero();
    /// @notice Thrown when the configured engine address has no code.
    error EngineNotContract(address engine);
    /// @notice Thrown when the engine runtime hash is not protocol-approved.
    error EngineNotCanonical(address engine);
    /// @notice Thrown when the engine's deterministic analyzer address has no code.
    error AnalyzerNotContract(address analyzer);
    /// @notice Thrown when the analyzer runtime hash is not protocol-approved.
    error AnalyzerNotCanonical(address analyzer);
    /// @notice Thrown when the engine's deterministic recursive ABI encoder has no code.
    error ABIEncoderNotContract(address encoder);
    /// @notice Thrown when the recursive ABI encoder runtime hash is not protocol-approved.
    error ABIEncoderNotCanonical(address encoder);
    /// @notice Thrown when dependency analysis exceeds its static-reference bound.
    error StaticReferenceLimitExceeded();
    /// @notice Engine error forwarded unchanged by the execution host.
    error FailWord(bytes6 word);

    /// @notice Upgrade entry point reserved for the registry timelock.
    /// @param newImplementation New MiniScript implementation.
    /// @param data Optional initialization calldata executed after upgrade.
    function timelockUpgrade(address newImplementation, bytes calldata data) external {
        if (msg.sender != address(registry)) revert OnlyRegistry();
        _performUpgrade(newImplementation, data);
    }

    function upgradeToAndCall(address, bytes memory) public payable override {
        revert("MiniScript: use timelockUpgrade");
    }

    function _performUpgrade(address newImplementation, bytes calldata data) internal {
        require(newImplementation != address(0), "upgrade:impl=0");
        _upgradePreservingBindings(newImplementation, data);
    }

    function _initialize(IRegistry registry_, address authorizedCaller_, address trustedForwarder_, address engine_)
        private
    {
        require(address(registry_) != address(0), "MiniScript: registry=0");
        require(authorizedCaller_ != address(0), "MiniScript: authorized=0");
        _requireCanonicalEngine(engine_);
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        registry = registry_;
        authorizedCaller = authorizedCaller_;
        trustedForwarder = trustedForwarder_;
        engine = engine_;
        // Canonical engine introspection uses STATICCALL and this one-shot initializer makes no state-changing
        // dependency call.
        // forge-lint: disable-next-line(reentrancy-events)
        emit EngineInitialized(engine_);
    }

    function _requireCanonicalEngine(address engine_) private view {
        if (engine_ == address(0)) revert EngineZero();
        if (engine_.code.length == 0) revert EngineNotContract(engine_);
        if (!ProtocolCodehashes.isAcceptedMiniScriptEngineCodehash(engine_.codehash)) {
            revert EngineNotCanonical(engine_);
        }
        address analyzer_ = address(MiniScriptEngine(engine_).analyzer());
        if (analyzer_.code.length == 0) revert AnalyzerNotContract(analyzer_);
        if (!ProtocolCodehashes.isAcceptedMiniScriptAnalyzerCodehash(analyzer_.codehash)) {
            revert AnalyzerNotCanonical(analyzer_);
        }
        address encoder_ = address(MiniScriptEngine(engine_).abiEncoder());
        if (encoder_.code.length == 0) revert ABIEncoderNotContract(encoder_);
        if (!ProtocolCodehashes.isAcceptedMiniScriptABIEncoderCodehash(encoder_.codehash)) {
            revert ABIEncoderNotCanonical(encoder_);
        }
        if (!ProtocolCodehashes.isAcceptedMiniScriptDeployment(engine_)) {
            revert EngineNotCanonical(engine_);
        }
    }

    function _authorizeUpgrade(address) internal view override {
        if (msg.sender != address(registry)) revert OnlyRegistry();
    }

    /// @notice Return the delegatecall engine selected by this execution host.
    function chainwallEngine() external view returns (address) {
        return engine;
    }

    /// @notice Adopt a canonical engine through the separately scoped Registry action.
    // _requireCanonicalEngine rejects zero and noncanonical code before storing the engine.
    // forge-lint: disable-next-line(missing-zero-check)
    function setChainwallEngine(address newEngine) external {
        if (msg.sender != address(registry)) revert OnlyRegistry();
        _requireCanonicalEngine(newEngine);
        address previous = engine;
        engine = newEngine;
        emit EngineChanged(previous, newEngine);
    }

    /// @notice Canonical host authentication surface used by linked execution.
    /// @return engine_ Canonical engine configured by this host.
    /// @return registry_ Registry whose catalog is authoritative for this host.
    function miniScriptHostConfig() external view returns (address engine_, address registry_) {
        return (engine, address(registry));
    }

    function chainwallComponentId() external pure override returns (bytes32) {
        return CHAINWALL_COMPONENT_ID;
    }

    /// @dev The Registry, authorized execution caller, trusted forwarder, and engine are separately governed
    ///      bindings. A MiniScript code upgrade may not silently redirect any of them through migration calldata.
    function _chainwallSecurityBindingsHash() internal view override returns (bytes32) {
        return _hashSecurityBindings(abi.encode(address(registry), authorizedCaller, trustedForwarder, engine));
    }

    function _resolveCaller(address trustedFwd) private view returns (address real) {
        real = msg.sender;
        if (trustedFwd == address(0) || real != trustedFwd) return real;
        uint256 cds = msg.data.length;
        if (cds >= 24 && (cds - 4) % 32 == 20) {
            assembly ("memory-safe") {
                real := shr(96, calldataload(sub(cds, 20)))
            }
        }
    }

    /// @notice Hash the exact public catalog state reachable by an interaction.
    /// @dev Public scripts bind only their own CALLI graph and PUSH32-resolved
    ///      targets, avoiding a tenant-wide approval DoS from unrelated catalog
    ///      authors. Private roots and public graphs with a private/missing child
    ///      return zero because their dependencies are hidden; Interact then
    ///      falls back to the full catalog revision.
    /// @param interactionId Public interaction whose dependency graph is analyzed.
    /// @return bindingHash Exact dependency hash, or zero for an incomplete/private graph.
    function getExecutionDependencyHash(bytes32 interactionId) external view returns (bytes32 bindingHash) {
        address engine_ = engine;
        if (engine_ == address(0)) revert EngineZero();
        return
            MiniScriptEngine(engine_).analyzer().getExecutionDependencyHash(address(registry), engine_, interactionId);
    }

    /// @notice Hash catalog dependencies reachable from an inline policy program.
    /// @param program Policy MiniScript bytecode.
    /// @param subjectInteractionId Interaction whose linked namespace is visible to the program.
    /// @return dependencyHash Exact dependency binding, or zero when analysis is incomplete.
    /// @return complete True when every reachable dependency was public and structurally analyzable.
    function getProgramDependencyHash(bytes calldata program, bytes32 subjectInteractionId)
        external
        view
        returns (bytes32 dependencyHash, bool complete)
    {
        address engine_ = engine;
        if (engine_ == address(0)) revert EngineZero();
        return MiniScriptEngine(engine_)
            .analyzer()
            .getProgramDependencyHash(address(registry), engine_, program, subjectInteractionId);
    }

    /// @notice Execute raw MiniScript from the configured authorized caller.
    /// @dev No post-run asset forwarding occurs. The caller must set
    ///      the native-value budget exactly and is responsible for any residuals.
    function run(bytes calldata script, uint256[] calldata args, uint256 maxSteps)
        external
        payable
        nonReentrant
        returns (uint256 stackTop)
    {
        if (msg.sender != authorizedCaller) revert OnlyAuthorizedCaller();
        address engine_ = engine;
        if (engine_ == address(0)) revert EngineZero();
        uint256[] memory emptySubject = new uint256[](0);
        bytes memory data = abi.encodeWithSelector(
            MiniScriptEngine.runSub.selector,
            script,
            args,
            maxSteps,
            0,
            msg.value,
            address(registry),
            _resolveCaller(trustedForwarder),
            engine_,
            emptySubject,
            0,
            0
        );
        // Only authorizedCaller can execute; engine selection is Registry-only and validates the complete canonical
        // deployment.
        // forge-lint: disable-next-line(controlled-delegatecall)
        (bool ok, bytes memory ret) = engine_.delegatecall(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        stackTop = abi.decode(ret, (uint256));
    }

    /// @notice Execute a policy program with immutable authenticated interaction context.
    /// @dev Policy programs receive the interaction's authenticated subject for
    ///      inspection, but execute in this dedicated host with a zero native-value budget.
    /// @param script Byte-encoded MiniScript program.
    /// @param args Initial frame arguments.
    /// @param maxSteps Maximum opcodes across the execution tree.
    /// @param subject Authenticated root interaction, actor, vault, value, and arguments.
    /// @return stackTop Final word returned by the root frame.
    function runPolicyProgram(
        bytes calldata script,
        uint256[] calldata args,
        uint256 maxSteps,
        IMiniScript.SubjectContext calldata subject
    ) external nonReentrant returns (uint256 stackTop) {
        if (msg.sender != authorizedCaller) {
            revert OnlyAuthorizedCaller();
        }
        bytes memory scriptMem = script;
        uint256[] memory argsMem = args;
        address engine_ = engine;
        if (engine_ == address(0)) revert EngineZero();
        bytes memory data = abi.encodeWithSelector(
            MiniScriptEngine.runSubject.selector, scriptMem, argsMem, maxSteps, address(registry), subject, 0, engine_
        );
        // Only authorizedCaller can execute; engine selection is Registry-only and validates the complete canonical
        // deployment.
        // forge-lint: disable-next-line(controlled-delegatecall)
        (bool ok, bytes memory ret) = engine_.delegatecall(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        stackTop = abi.decode(ret, (uint256));
    }
}

/// @notice Development helper for assembling MiniScript bytecode in tests and Foundry scripts.
/// @dev Not intended for on-chain use. This uses repeated bytes.concat (O(n^2)).
library MiniAssembler {
    /// @notice Assemble a script from opcode and immediate streams.
    /// @dev  op[i] is the opcode byte. PUSH, PUSHDATA32, jump, RATIO, KECCAK, STATICLINK, VALUEUSD, and recursive ABI
    ///       instructions consume their framed immediate from `imm[j]`.
    ///       The caller is responsible for pairing them correctly.
    function assemble(uint8[] memory op, bytes[] memory imm) internal pure returns (bytes memory out) {
        uint256 k = 0; // index into immediates
        for (uint256 i; i < op.length; ++i) {
            out = bytes.concat(out, bytes1(op[i]));
            if (op[i] == 0x01) {
                // PUSH1 consumes one immediate byte.
                out = bytes.concat(out, imm[k]);
                unchecked {
                    ++k;
                }
            } else if (op[i] == 0x03) {
                // PUSH8 consumes one big-endian uint64 immediate.
                out = bytes.concat(out, imm[k]);
                unchecked {
                    ++k;
                }
            } else if (op[i] == 0x02) {
                // PUSH32 consumes one complete word immediate.
                out = bytes.concat(out, imm[k]);
                unchecked {
                    ++k;
                }
            } else if (op[i] == 0x04) {
                // PUSHDATA32 consumes one non-reference word immediate.
                bytes memory dataWord = imm[k];
                // Each immediate belongs to one instruction; rejecting a malformed frame prevents emitting an
                // invalid script.
                // forge-lint: disable-next-line(require-revert-in-loop)
                require(dataWord.length == 32, "imm/ops mismatch: data word needs 32 bytes");
                out = bytes.concat(out, dataWord);
                unchecked {
                    ++k;
                }
            } else if (op[i] == 0x30 || op[i] == 0x31) {
                // JUMPI and JMP consume one two-byte relative offset.
                bytes memory j = imm[k];
                // Each immediate belongs to one instruction; rejecting a malformed frame prevents emitting an
                // invalid script.
                // forge-lint: disable-next-line(require-revert-in-loop)
                require(j.length == 2, "imm/ops mismatch: jump needs 2 bytes");
                out = bytes.concat(out, j);
                unchecked {
                    ++k;
                }
            } else if (op[i] == 0x1A) {
                // RATIO consumes factor-count and denominator-mask metadata.
                bytes memory ratio = imm[k];
                // Each immediate belongs to one instruction; rejecting a malformed frame prevents emitting an
                // invalid script.
                // forge-lint: disable-next-line(require-revert-in-loop)
                require(ratio.length == 3, "imm/ops mismatch: ratio needs 3 bytes");
                out = bytes.concat(out, ratio);
                unchecked {
                    ++k;
                }
            } else if (op[i] == 0x1B) {
                // KECCAK consumes one word-count byte.
                bytes memory wordCount = imm[k];
                // Each immediate belongs to one instruction; rejecting a malformed frame prevents emitting an
                // invalid script.
                // forge-lint: disable-next-line(require-revert-in-loop)
                require(wordCount.length == 1, "imm/ops mismatch: keccak needs 1 byte");
                out = bytes.concat(out, wordCount);
                unchecked {
                    ++k;
                }
            } else if (op[i] == 0x2F) {
                // STATICLINK consumes one linked-artifact relation.
                bytes memory relation = imm[k];
                // Each immediate belongs to one instruction; rejecting a malformed frame prevents emitting an
                // invalid script.
                // forge-lint: disable-next-line(require-revert-in-loop)
                require(relation.length == 32, "imm/ops mismatch: static link needs 32 bytes");
                out = bytes.concat(out, relation);
                unchecked {
                    ++k;
                }
            } else if (op[i] == 0x33) {
                // VALUEUSD consumes an asset hash and four-byte freshness bound.
                bytes memory valueUsd = imm[k];
                // Each immediate belongs to one instruction; rejecting a malformed frame prevents emitting an
                // invalid script.
                // forge-lint: disable-next-line(require-revert-in-loop)
                require(valueUsd.length == 36, "imm/ops mismatch: value usd needs 36 bytes");
                out = bytes.concat(out, valueUsd);
                unchecked {
                    ++k;
                }
            } else if (op[i] == 0x38) {
                // READWORDS adds a bounded return-word selection before the ABI
                // descriptor. Use the canonical decoder for the complete frame.
                bytes memory readWords = bytes.concat(hex"38", imm[k]);
                MiniScriptBytecode.decode(readWords);
                uint256 descriptorLength = (uint256(uint8(imm[k][0])) << 8) | uint256(uint8(imm[k][1]));
                // Each immediate belongs to one instruction; rejecting a malformed frame prevents emitting an
                // invalid script.
                // forge-lint: disable-start(require-revert-in-loop)
                require(
                    readWords.length == 41 + 2 * uint256(uint8(imm[k][39])) + descriptorLength,
                    "imm/ops mismatch: read words length"
                );
                // forge-lint: disable-end(require-revert-in-loop)
                out = bytes.concat(out, imm[k]);
                unchecked {
                    ++k;
                }
            } else if (op[i] >= 0x35 && op[i] <= 0x37) {
                // Recursive ABI immediate excludes the opcode and includes:
                // descriptor length, tape source, target, selector, and descriptor.
                bytes memory abiCall = imm[k];
                // Each immediate belongs to one instruction; rejecting a malformed frame prevents emitting an
                // invalid script.
                // forge-lint: disable-next-line(require-revert-in-loop)
                require(abiCall.length >= 43, "imm/ops mismatch: abi call too short");
                uint256 descriptorLength = (uint256(uint8(abiCall[0])) << 8) | uint256(uint8(abiCall[1]));
                // Each immediate belongs to one instruction; rejecting a malformed frame prevents emitting an
                // invalid script.
                // forge-lint: disable-next-line(require-revert-in-loop)
                require(descriptorLength >= 4 && descriptorLength <= 1024, "imm/ops mismatch: abi descriptor");
                // Each immediate belongs to one instruction; rejecting a malformed frame prevents emitting an
                // invalid script.
                // forge-lint: disable-next-line(require-revert-in-loop)
                require(uint8(abiCall[2]) <= 1, "imm/ops mismatch: abi tape source");
                // Each immediate belongs to one instruction; rejecting a malformed frame prevents emitting an
                // invalid script.
                // forge-lint: disable-next-line(require-revert-in-loop)
                require(abiCall.length == 39 + descriptorLength, "imm/ops mismatch: abi call length");
                uint8 descriptorVersion = uint8(abiCall[39]);
                // Each immediate belongs to one instruction; rejecting a malformed frame prevents emitting an
                // invalid script.
                // forge-lint: disable-next-line(require-revert-in-loop)
                require(descriptorVersion == 1 || descriptorVersion == 2, "imm/ops mismatch: abi descriptor version");
                out = bytes.concat(out, abiCall);
                unchecked {
                    ++k;
                }
            }
        }
        // Each immediate belongs to one instruction; rejecting a malformed frame prevents emitting an invalid
        // script.
        // forge-lint: disable-next-line(require-revert-in-loop)
        require(k == imm.length, "imm/ops mismatch");
    }
}
