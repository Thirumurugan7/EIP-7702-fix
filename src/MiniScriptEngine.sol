// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {IMiniScript} from "@chainwall/interfaces/IMiniScript.sol";

import {MiniScriptABIEncoder} from "./MiniScriptABIEncoder.sol";
import {MiniScriptAnalyzer} from "./MiniScriptAnalyzer.sol";
import {MiniScriptBytecode} from "./MiniScriptBytecode.sol";
import {MiniScriptLimits} from "./MiniScriptLimits.sol";
import {ProductRatioMath} from "./ProductRatioMath.sol";
import {IRegistry} from "./registry/RegistryShared.sol";

/// @title MiniScriptEngine
/// @notice Stateless MiniScript interpreter intended to run by delegatecall inside an authenticated host.
/// @dev Uses explicit actor + registry parameters and enforces an optional native value cap.
///      This is the low-level execution core behind Safe- and account-mode interactions:
///      - `registry` resolves contract and token ids referenced by the script.
///      - `actor` powers `CALLER` outside subject-aware interaction execution.
///      - subject-aware `CALLER` is the governed vault; `SUBJECT 3` exposes its actor.
///      - `maxNativeValue` bounds the total ETH a script may spend through write opcodes.
contract MiniScriptEngine {
    /// @dev Complete frame-local input plus the shared execution context carried across recursion.
    struct FrameInput {
        /// @dev Bytecode executed by this frame.
        bytes script;
        /// @dev Initial argument array read by `ARG` in this frame.
        uint256[] args;
        /// @dev Shared maximum opcode count for the complete execution tree.
        uint256 maxSteps;
        /// @dev Steps already consumed before this frame starts.
        uint256 stepsUsed;
        /// @dev Native value budget remaining for mutable execution.
        uint256 remainingValue;
        /// @dev Registry used for catalog and price reads.
        address registry;
        /// @dev Logical actor used by raw, non-subject-aware execution.
        address actor;
        /// @dev Canonical engine used for mutable delegatecall recursion.
        address engine;
        /// @dev Validated versioned root-subject envelope, or an empty array.
        uint256[] subjectEnvelope;
        /// @dev True after execution crosses into the read-only linked-script path.
        bool readOnly;
        /// @dev Authenticated MiniScript, Safe, or account host preserved across static frames.
        address logicalHost;
        /// @dev Static references already consumed by ancestor frames.
        uint256 referencesUsed;
        /// @dev Number of nested CALLI and STATICLINK frames below the root.
        uint256 recursionDepth;
        /// @dev Active linked and CALLI frame keys used for cycle detection.
        bytes32[] activeFrames;
    }

    /// @notice Error raised by the assembly interpreter with a compact 6-byte tag.
    error FailWord(bytes6 word);
    /// @notice Thrown when an engine entrypoint is called outside its required host or recursion context.
    error DelegatecallContextRequired();
    /// @notice Thrown when one execution tree exceeds the static-reference bound.
    error StaticReferenceLimitExceeded();
    // Solidity-level error tags

    bytes6 constant ERR_00 = "ERR_00"; // short or malformed return data
    bytes6 constant ERR_01 = "ERR_01"; // REQUIRE opcode failed
    bytes6 constant ERR_02 = "ERR_02"; // registry lookup/allowlist failed
    bytes6 constant ERR_03 = "ERR_03"; // max steps exceeded
    bytes6 constant ERR_04 = "ERR_04"; // external call failed
    bytes6 constant ERR_05 = "ERR_05"; // invalid opcode
    bytes6 constant ERR_06 = "ERR_06"; // stack under-flow
    bytes6 constant ERR_07 = "ERR_07"; // program counter OOB
    bytes6 constant ERR_08 = "ERR_08"; // stack overflow
    bytes6 constant ERR_09 = "ERR_09"; // native value cap exceeded
    bytes6 constant ERR_10 = "ERR_10"; // invalid exact ratio, zero denominator, or overflowing result
    bytes6 constant ERR_11 = "ERR_11"; // state-changing opcode reached in read-only mode
    bytes6 constant ERR_12 = "ERR_12"; // recursive ABI descriptor or authenticated value tape is invalid
    bytes6 constant ERR_13 = "ERR_13"; // policy attempted native spending or a privileged Registry mutation

    uint256 private constant MAX_PREFETCH = 128; // defensive cap on PUSH32 prefetches
    bytes4 private constant _GET_SCRIPT_SELECTOR = IRegistry.getInteractionScript.selector;
    uint256 private constant _GET_INTERACTION_FLAGS_SELECTOR = 0xcd5685d6;
    // Historical PLAN_ONLY (bit 0) and current INACTIVE (bit 1) are both
    // unavailable. New Registry writes reject bit 0, while old records fail closed.
    uint256 private constant _INTERACTION_UNAVAILABLE_FLAGS = (1 << 0) | (1 << 1);
    uint256 private constant _RUN_SUB_SELECTOR = 0x56f528e0;
    uint256 private constant _GET_TOKEN_PRICE_FRESH_SELECTOR = 0x599faa2a;
    uint256 private constant _GET_TOKEN_VALUE_USD18_SELECTOR = 0xef0da766;
    uint256 private constant _GET_NATIVE_VALUE_USD18_SELECTOR = 0x3bb77715;
    uint256 private constant _RUN_LINKED_SELECTOR = 0xb5fffe64;
    uint256 private constant _RUN_LINKED_NESTED_SELECTOR = 0x93758c06;
    uint256 private constant _RUN_READ_ONLY_CALLI_SELECTOR = 0x31ed9d3c;
    // bytes4(keccak256("execute(address,address,bytes4,uint8,uint256,uint256,bytes,uint256[])"));
    // kept numeric because inline assembly accepts only direct-number constants.
    uint256 private constant _EXECUTE_ABI_SELECTOR = 0xd844834c;
    // bytes4(keccak256("tryProductRatio(uint256,uint256[])")); kept numeric
    // because inline assembly accepts only direct-number constants.
    uint256 private constant _TRY_PRODUCT_RATIO_SELECTOR = 0xa1d98c4c;

    /// @dev Expected runtime hash of this deployment's second CREATE child.
    ///      The embedded hash makes an accepted engine runtime reject a
    ///      constructor-time child substitution even when its own bytecode was
    ///      cloned exactly.
    bytes32 private immutable _ABI_ENCODER_CODEHASH;

    /// @notice Deploy the canonical analyzer as the engine's first CREATE child.
    constructor() {
        new MiniScriptAnalyzer();
        MiniScriptABIEncoder encoder_ = new MiniScriptABIEncoder();
        _ABI_ENCODER_CODEHASH = address(encoder_).codehash;
    }

    /// @notice Canonical analyzer deployed beside this engine.
    /// @dev Its deterministic first-child address avoids storing mutable engine configuration.
    /// @return Analyzer whose decoder and dependency rules match this engine.
    function analyzer() public view returns (MiniScriptAnalyzer) {
        // The analyzer is the engine's first CREATE child. Deriving that address
        // keeps the execution runtime stateless and its codehash deployment-independent.
        return _analyzer(address(this));
    }

    function _analyzer(address engine_) private pure returns (MiniScriptAnalyzer) {
        return MiniScriptAnalyzer(address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", engine_, hex"01"))))));
    }

    /// @notice Canonical recursive ABI encoder deployed beside this engine.
    /// @dev The encoder is the engine's second CREATE child. It remains a separate
    ///      stateless runtime so the execution engine stays below EIP-170.
    /// @return Encoder whose descriptor and tape rules match this engine.
    function abiEncoder() public view returns (MiniScriptABIEncoder) {
        return _abiEncoder(address(this));
    }

    /// @dev Resolve the second CREATE child for an explicit engine address.
    ///      Execution runs through delegatecall, where `address(this)` is the
    ///      governed host rather than the engine deployment.
    function _abiEncoder(address engine_) private pure returns (MiniScriptABIEncoder) {
        return MiniScriptABIEncoder(address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", engine_, hex"02"))))));
    }

    /// @notice Execute a mutable root with an authenticated interaction subject.
    /// @dev The subject is encoded once and remains immutable across CALLI and linked recursion.
    /// @param script MiniScript bytecode for the root frame.
    /// @param args Initial root-frame arguments.
    /// @param maxSteps Shared execution-tree step cap.
    /// @param registry Registry dispatcher address.
    /// @param subject Authenticated interaction, actor, vault, value, and argument context.
    /// @param maxNativeValue Maximum native value mutable opcodes may spend.
    /// @param engine Address of this canonical engine.
    /// @return stackTop Final word returned by the root frame.
    function runSubject(
        bytes calldata script,
        uint256[] calldata args,
        uint256 maxSteps,
        address registry,
        IMiniScript.SubjectContext calldata subject,
        uint256 maxNativeValue,
        address engine
    ) external payable returns (uint256 stackTop) {
        bool safeHost = _requireDelegatecallContext(engine, registry);
        if (safeHost && subject.vault != address(this)) revert DelegatecallContextRequired();
        uint256[] memory envelope = _subjectEnvelope(subject);
        bytes32[] memory emptyActiveFrames = new bytes32[](0);
        (stackTop,,,,) = _runFrame(
            FrameInput({
                script: script,
                args: args,
                maxSteps: maxSteps,
                stepsUsed: 0,
                remainingValue: maxNativeValue,
                registry: registry,
                actor: subject.actor,
                engine: engine,
                subjectEnvelope: envelope,
                readOnly: false,
                logicalHost: address(this),
                referencesUsed: 0,
                recursionDepth: 0,
                activeFrames: emptyActiveFrames
            })
        );
    }

    /// @notice Mutable execution entry used for raw roots and CALLI recursion.
    /// @dev A raw root supplies zero for the accumulated counters and recursion depth.
    ///      CALLI shares the step, value, reference, and recursion budgets with its parent.
    /// @param script Child interaction bytecode.
    /// @param args Arguments supplied to the child interaction.
    /// @param maxSteps Shared execution-tree step cap.
    /// @param stepsUsed Steps consumed before entering the child.
    /// @param remainingValue Native value budget remaining in the parent.
    /// @param registry Registry dispatcher address.
    /// @param actor Logical actor used by raw execution.
    /// @param engine Address of this canonical engine.
    /// @param subjectEnvelope Immutable root-subject envelope, or an empty array.
    /// @param referencesUsed Static references consumed before entering the child.
    /// @param recursionDepth Number of nested frames including this child.
    /// @return stackTop Final child result.
    /// @return stepsUsedOut Updated shared step count.
    /// @return remainingValueOut Updated native value budget.
    /// @return referencesUsedOut Updated static-reference count.
    function runSub(
        bytes calldata script,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 stepsUsed,
        uint256 remainingValue,
        address registry,
        address actor,
        address engine,
        uint256[] calldata subjectEnvelope,
        uint256 referencesUsed,
        uint256 recursionDepth
    )
        external
        payable
        returns (uint256 stackTop, uint256 stepsUsedOut, uint256 remainingValueOut, uint256 referencesUsedOut)
    {
        bool safeHost = _requireDelegatecallContext(engine, registry);
        if (recursionDepth > MiniScriptLimits.MAX_RECURSION_DEPTH) {
            revert FailWord(ERR_02);
        }
        uint256[] memory subjectMem = subjectEnvelope;
        bytes32[] memory emptyActiveFrames = new bytes32[](0);
        if (subjectMem.length != 0) _validateSubjectEnvelope(subjectMem);
        // Subject-envelope validation rejects address words above uint160 before execution.
        // forge-lint: disable-next-line(unsafe-typecast)
        if (safeHost && (subjectMem.length == 0 || address(uint160(subjectMem[4])) != address(this))) {
            revert DelegatecallContextRequired();
        }
        (stackTop, stepsUsedOut, remainingValueOut, referencesUsedOut,) = _runFrame(
            FrameInput({
                script: script,
                args: args,
                maxSteps: maxSteps,
                stepsUsed: stepsUsed,
                remainingValue: remainingValue,
                registry: registry,
                actor: actor,
                engine: engine,
                subjectEnvelope: subjectMem,
                readOnly: false,
                logicalHost: address(this),
                referencesUsed: referencesUsed,
                recursionDepth: recursionDepth,
                activeFrames: emptyActiveFrames
            })
        );
    }

    /// @notice First mutable-to-read-only transition for a linked artifact.
    /// @dev The caller is authenticated as a configured MiniScript host. Calls
    ///      made without STATICCALL are still constrained by explicit read-only mode.
    /// @param relation Base-scoped linked-artifact relation to execute.
    /// @param subjectEnvelope Validated root-subject envelope.
    /// @param maxSteps Shared execution-tree step cap.
    /// @param stepsUsed Steps consumed before the transition.
    /// @param referencesUsed Static references consumed before the transition.
    /// @param registryAddr Registry authenticated by the mutable execution authority.
    /// @param executionAuthority Interact authority that admitted a Safe-hosted root.
    /// @param recursionDepth Number of nested frames including this linked frame.
    /// @return result Single word returned by the linked artifact.
    /// @return stepsUsedOut Updated shared step count.
    /// @return referencesUsedOut Updated static-reference count.
    function runLinked(
        bytes32 relation,
        uint256[] calldata subjectEnvelope,
        uint256 maxSteps,
        uint256 stepsUsed,
        uint256 referencesUsed,
        address registryAddr,
        address executionAuthority,
        uint256 recursionDepth
    ) external returns (uint256 result, uint256 stepsUsedOut, uint256 referencesUsedOut) {
        address logicalHost = msg.sender;
        bool safeHost = _requireExecutionContext(logicalHost, address(this), registryAddr, executionAuthority);
        if (recursionDepth == 0 || recursionDepth > MiniScriptLimits.MAX_RECURSION_DEPTH) {
            revert FailWord(ERR_02);
        }
        uint256[] memory envelope = subjectEnvelope;
        _validateSubjectEnvelope(envelope);
        // Subject-envelope validation rejects address words above uint160 before execution.
        // forge-lint: disable-next-line(unsafe-typecast)
        if (safeHost && address(uint160(envelope[4])) != logicalHost) revert DelegatecallContextRequired();
        bytes32[] memory activeFrames = new bytes32[](1);
        activeFrames[0] = _linkFrameKey(bytes32(envelope[1]), relation);
        return _runLinkedArtifact(
            relation,
            envelope,
            maxSteps,
            stepsUsed,
            referencesUsed,
            registryAddr,
            logicalHost,
            recursionDepth,
            activeFrames
        );
    }

    /// @notice Read-only linked-artifact recursion entry used after host authentication.
    /// @dev Callable only by this engine while the EVM static flag is inherited.
    /// @param relation Base-scoped linked-artifact relation to execute.
    /// @param subjectEnvelope Validated root-subject envelope.
    /// @param maxSteps Shared execution-tree step cap.
    /// @param stepsUsed Steps consumed before this nested frame.
    /// @param referencesUsed Static references consumed before this nested frame.
    /// @param registryAddr Authenticated Registry address inherited from the host.
    /// @param logicalHost Authenticated MiniScript or account host.
    /// @param depth Read-only recursion depth before appending this frame.
    /// @param activeFrames Ancestor frame keys used for cycle detection.
    /// @return result Single word returned by the linked artifact.
    /// @return stepsUsedOut Updated shared step count.
    /// @return referencesUsedOut Updated static-reference count.
    function runLinkedNested(
        bytes32 relation,
        uint256[] calldata subjectEnvelope,
        uint256 maxSteps,
        uint256 stepsUsed,
        uint256 referencesUsed,
        address registryAddr,
        address logicalHost,
        uint256 depth,
        bytes32[] calldata activeFrames
    ) external returns (uint256 result, uint256 stepsUsedOut, uint256 referencesUsedOut) {
        if (msg.sender != address(this)) revert DelegatecallContextRequired();
        uint256[] memory envelope = subjectEnvelope;
        _validateSubjectEnvelope(envelope);
        bytes32[] memory nextActiveFrames =
            _appendActiveFrame(activeFrames, _linkFrameKey(bytes32(envelope[1]), relation), depth);
        return _runLinkedArtifact(
            relation, envelope, maxSteps, stepsUsed, referencesUsed, registryAddr, logicalHost, depth, nextActiveFrames
        );
    }

    /// @notice Read-only CALLI recursion after the host-authenticated boundary.
    /// @dev Callable only by this engine; the child must return exactly one stack word.
    /// @param childId Public interaction identifier loaded by CALLI.
    /// @param args Arguments supplied to the child interaction.
    /// @param subjectEnvelope Validated root-subject envelope.
    /// @param maxSteps Shared execution-tree step cap.
    /// @param stepsUsed Steps consumed before entering the child.
    /// @param referencesUsed Static references consumed before entering the child.
    /// @param registryAddr Authenticated Registry address inherited from the host.
    /// @param logicalHost Authenticated MiniScript or account host.
    /// @param depth Read-only recursion depth before appending this child frame.
    /// @param activeFrames Ancestor frame keys used for cycle detection.
    /// @return result Single word returned by the child.
    /// @return stepsUsedOut Updated shared step count.
    /// @return referencesUsedOut Updated static-reference count.
    function runReadOnlyCalli(
        bytes32 childId,
        uint256[] calldata args,
        uint256[] calldata subjectEnvelope,
        uint256 maxSteps,
        uint256 stepsUsed,
        uint256 referencesUsed,
        address registryAddr,
        address logicalHost,
        uint256 depth,
        bytes32[] calldata activeFrames
    ) external returns (uint256 result, uint256 stepsUsedOut, uint256 referencesUsedOut) {
        if (msg.sender != address(this) || depth == 0 || depth > MiniScriptLimits.MAX_RECURSION_DEPTH) {
            revert DelegatecallContextRequired();
        }
        uint256[] memory envelope = subjectEnvelope;
        _validateSubjectEnvelope(envelope);
        bytes32[] memory nextActiveFrames = _appendActiveFrame(activeFrames, _calliFrameKey(childId), depth);
        uint256 flags = IRegistry(registryAddr).getInteractionFlags(childId);
        if ((flags & _INTERACTION_UNAVAILABLE_FLAGS) != 0) revert FailWord(ERR_02);
        bytes memory childScript = IRegistry(registryAddr).getInteractionScript(childId);
        if (childScript.length == 0) revert FailWord(ERR_02);
        uint256 stackWords;
        (result, stepsUsedOut,, referencesUsedOut, stackWords) = _runFrame(
            FrameInput({
                script: childScript,
                args: args,
                maxSteps: maxSteps,
                stepsUsed: stepsUsed,
                remainingValue: 0,
                registry: registryAddr,
                // Subject-envelope validation rejects address words above uint160 before execution.
                // forge-lint: disable-next-line(unsafe-typecast)
                actor: address(uint160(envelope[3])),
                engine: address(this),
                subjectEnvelope: envelope,
                readOnly: true,
                logicalHost: logicalHost,
                referencesUsed: referencesUsed,
                recursionDepth: depth,
                activeFrames: nextActiveFrames
            })
        );
        if (stackWords != 1) revert FailWord(ERR_00);
    }

    /// @dev Load and execute one linked artifact under the inherited read-only context.
    function _runLinkedArtifact(
        bytes32 relation,
        uint256[] memory subjectEnvelope,
        uint256 maxSteps,
        uint256 stepsUsed,
        uint256 referencesUsed,
        address registryAddr,
        address logicalHost,
        uint256 depth,
        bytes32[] memory activeFrames
    ) private returns (uint256 result, uint256 stepsUsedOut, uint256 referencesUsedOut) {
        if (relation == bytes32(0) || depth == 0 || depth > MiniScriptLimits.MAX_RECURSION_DEPTH) {
            revert FailWord(ERR_02);
        }
        bytes32 baseId = bytes32(subjectEnvelope[1]);
        uint256 flags = IRegistry(registryAddr).getInteractionFlags(baseId);
        if ((flags & _INTERACTION_UNAVAILABLE_FLAGS) != 0) revert FailWord(ERR_02);
        bytes memory script = IRegistry(registryAddr).getLinkedArtifact(baseId, relation);
        if (script.length == 0) revert FailWord(ERR_02);

        uint256 stackWords;
        (result, stepsUsedOut,, referencesUsedOut, stackWords) = _runFrame(
            FrameInput({
                script: script,
                args: subjectEnvelope,
                maxSteps: maxSteps,
                stepsUsed: stepsUsed,
                remainingValue: 0,
                registry: registryAddr,
                // Subject-envelope validation rejects address words above uint160 before execution.
                // forge-lint: disable-next-line(unsafe-typecast)
                actor: address(uint160(subjectEnvelope[3])),
                engine: address(this),
                subjectEnvelope: subjectEnvelope,
                readOnly: true,
                logicalHost: logicalHost,
                referencesUsed: referencesUsed,
                recursionDepth: depth,
                activeFrames: activeFrames
            })
        );
        if (stackWords != 1) revert FailWord(ERR_00);
    }

    /// @dev Append one recursion frame after validating depth and rejecting cycles.
    function _appendActiveFrame(bytes32[] calldata activeFrames, bytes32 frameKey, uint256 depth)
        private
        pure
        returns (bytes32[] memory next)
    {
        if (
            frameKey == bytes32(0) || depth == 0 || depth > MiniScriptLimits.MAX_RECURSION_DEPTH
                || activeFrames.length >= MiniScriptLimits.MAX_RECURSION_DEPTH
        ) revert FailWord(ERR_02);
        next = new bytes32[](activeFrames.length + 1);
        for (uint256 i; i < activeFrames.length; ++i) {
            // A failed structural, read, or budget check must roll back the execution tree; NOFAIL covers only
            // WRITE transport failures.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (activeFrames[i] == frameKey) revert FailWord(ERR_02);
            next[i] = activeFrames[i];
        }
        next[activeFrames.length] = frameKey;
    }

    function _linkFrameKey(bytes32 baseId, bytes32 relation) private pure returns (bytes32) {
        return keccak256(abi.encode(uint8(1), baseId, relation));
    }

    function _calliFrameKey(bytes32 interactionId) private pure returns (bytes32) {
        return keccak256(abi.encode(uint8(2), interactionId));
    }

    /// @dev Authenticate a configured host, or an allowlisted Safe plus its Interact authority.
    function _requireExecutionContext(
        address logicalHost,
        address expectedEngine,
        address expectedRegistry,
        address executionAuthority
    ) private view returns (bool safeHost) {
        return _analyzer(expectedEngine)
            .requireExecutionHost(logicalHost, expectedEngine, expectedRegistry, executionAuthority);
    }

    /// @dev Encode the versioned subject context consumed by `SUBJECT` and linked frames.
    ///      Version 2 uses selectors 0..6 for fixed fields and 7+n for interaction argument n.
    function _subjectEnvelope(IMiniScript.SubjectContext calldata subject)
        private
        pure
        returns (uint256[] memory envelope)
    {
        if (
            subject.version != 2 || subject.interactionId == bytes32(0) || subject.actor == address(0)
                || subject.vault == address(0) || subject.policyId == bytes32(0)
        ) revert FailWord(ERR_02);
        envelope = new uint256[](7 + subject.interactionArgs.length);
        envelope[0] = subject.version;
        envelope[1] = uint256(subject.interactionId);
        envelope[2] = subject.nativeValue;
        envelope[3] = uint256(uint160(subject.actor));
        envelope[4] = uint256(uint160(subject.vault));
        envelope[5] = subject.interactionArgs.length;
        envelope[6] = uint256(subject.policyId);
        uint256[] calldata interactionArgs = subject.interactionArgs;
        assembly ("memory-safe") {
            // The checked allocation above includes every argument word.
            calldatacopy(add(envelope, 0x100), interactionArgs.offset, shl(5, interactionArgs.length))
        }
    }

    /// @dev Validate an inherited envelope before any field can influence execution.
    function _validateSubjectEnvelope(uint256[] memory envelope) private pure {
        if (
            envelope.length < 7 || envelope[0] != 2 || envelope[1] == 0 || envelope[3] > type(uint160).max
                || envelope[3] == 0 || envelope[4] > type(uint160).max || envelope[4] == 0
                || envelope[5] > type(uint256).max - 7 || envelope.length != 7 + envelope[5] || envelope[6] == 0
        ) revert FailWord(ERR_02);
    }

    /// @notice Pure arithmetic entry used by the RATIO opcode through STATICCALL.
    /// @dev Keeping the bounded multi-limb implementation outside the assembly
    ///      interpreter makes the arithmetic independently testable. The caller
    ///      maps `valid == false` to ERR_10.
    /// @param denominatorMask Bit i is one when `factors[i]` is a denominator.
    /// @param factors Numerator and denominator factors in source evaluation order.
    /// @return valid False for malformed input, zero denominator, or uint256 overflow.
    /// @return result Exact floored ratio when valid is true.
    function tryProductRatio(uint256 denominatorMask, uint256[] calldata factors)
        external
        pure
        returns (bool valid, uint256 result)
    {
        return ProductRatioMath.tryFloor(factors, denominatorMask);
    }

    /// @dev Require execution through a host configured with `expectedEngine`.
    function _requireDelegatecallContext(address expectedEngine, address expectedRegistry)
        private
        view
        returns (bool safeHost)
    {
        // An engine runtime has no host configuration. Comparing codehashes
        // rejects direct calls even if a caller supplies another canonical
        // engine address and a hostile Registry.
        if (address(this).codehash == expectedEngine.codehash) revert DelegatecallContextRequired();
        return _requireExecutionContext(address(this), expectedEngine, expectedRegistry, msg.sender);
    }

    /// @notice Authenticated external frame entry and read-only STATICCALL boundary.
    /// @dev Mutable wrappers enter the shared interpreter internally only after
    ///      performing the same host and subject checks at their own boundary.
    /// @param input Complete frame-local and shared execution context.
    /// @return stackTop Final word returned by this frame.
    /// @return stepsUsedOut Updated shared step count.
    /// @return remainingValueOut Updated mutable native value budget.
    /// @return referencesUsedOut Updated shared static-reference count.
    /// @return stackWordsOut Number of words remaining when the frame exits.
    function executeFrame(FrameInput calldata input)
        external
        payable
        returns (
            uint256 stackTop,
            uint256 stepsUsedOut,
            uint256 remainingValueOut,
            uint256 referencesUsedOut,
            uint256 stackWordsOut
        )
    {
        if (input.readOnly) {
            if (msg.sender != address(this)) revert DelegatecallContextRequired();
        } else {
            bool safeHost = _requireDelegatecallContext(input.engine, input.registry);
            if (
                safeHost
                    && (input.subjectEnvelope.length == 0
                        // Subject-envelope validation rejects address words above uint160 before execution.
                        // forge-lint: disable-next-line(unsafe-typecast)
                        || address(uint160(input.subjectEnvelope[4])) != address(this))
            ) {
                revert DelegatecallContextRequired();
            }
        }
        if (input.subjectEnvelope.length != 0) _validateSubjectEnvelope(input.subjectEnvelope);
        return _runInternal(input);
    }

    /// @dev Mutable callers have already authenticated their host and subject.
    ///      Read-only frames still enter a real STATICCALL, including when the
    ///      first linked boundary was reached through an ordinary CALL.
    function _runFrame(FrameInput memory input)
        private
        returns (
            uint256 stackTop,
            uint256 stepsUsedOut,
            uint256 remainingValueOut,
            uint256 referencesUsedOut,
            uint256 stackWordsOut
        )
    {
        if (!input.readOnly) return _runInternal(input);
        (bool ok, bytes memory result) = address(this).staticcall(abi.encodeCall(this.executeFrame, (input)));
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(result, 0x20), mload(result))
            }
        }
        return abi.decode(result, (uint256, uint256, uint256, uint256, uint256));
    }

    // Passing one memory frame keeps the large interpreter shared across entry
    // points without specializing it for individual constant scalar arguments.
    function _runInternal(FrameInput memory input)
        internal
        returns (
            uint256 stackTop,
            uint256 stepsUsedOut,
            uint256 remainingValueOut,
            uint256 referencesUsedOut,
            uint256 stackWordsOut
        )
    {
        bytes memory script = input.script;
        uint256[] memory args = input.args;
        uint256[] memory subjectEnvelope = input.subjectEnvelope;
        bytes32[] memory activeFrames = input.activeFrames;
        if (input.stepsUsed > input.maxSteps) revert FailWord(ERR_03);
        MiniScriptBytecode.DecodedReferences memory decoded = MiniScriptBytecode.decode(script);
        if (input.referencesUsed > MAX_PREFETCH || decoded.rawReferenceCount > MAX_PREFETCH - input.referencesUsed) {
            revert StaticReferenceLimitExceeded();
        }
        referencesUsedOut = input.referencesUsed + decoded.rawReferenceCount;
        uint256 stackCapacity = input.maxSteps - input.stepsUsed;
        if (stackCapacity > 1024) stackCapacity = 1024;
        // Validated jumps only move forward, so each instruction runs at most
        // once. Each pushes at most its byte width, including READWORDS. This
        // cheap bound avoids reserving a large stack for a short script.
        if (stackCapacity > script.length) stackCapacity = script.length;

        uint256[] memory ctx = new uint256[](15);
        ctx[0] = input.maxSteps;
        ctx[1] = input.stepsUsed;
        ctx[2] = input.remainingValue;
        ctx[3] = uint256(uint160(input.registry));
        ctx[4] = uint256(uint160(input.actor));
        ctx[5] = uint256(uint160(input.engine));
        ctx[7] = uint256(uint160(input.logicalHost));
        ctx[8] = input.readOnly ? 1 : 0;
        // Subject-envelope validation rejects address words above uint160 before execution.
        // forge-lint: disable-next-line(unsafe-typecast)
        ctx[9] = subjectEnvelope.length == 0 ? 0 : uint256(uint160(subjectEnvelope[4]));
        ctx[10] = subjectEnvelope.length == 0 ? 0 : 1;
        ctx[11] = referencesUsedOut;
        ctx[12] = input.recursionDepth;
        ctx[13] = uint256(_ABI_ENCODER_CODEHASH);
        ctx[14] = uint256(uint160(address(_abiEncoder(input.engine))));

        bytes32[] memory hashes = decoded.targets;
        bytes32[] memory staticCalliIds = decoded.calliIds;
        address[] memory addrs;
        bool[] memory ok;
        // Prefetch PUSH32 literals in script and resolve via registry.
        if (hashes.length > 0) {
            (addrs, ok) = IRegistry(input.registry).getAddressesByHash(hashes);
            if (addrs.length != hashes.length || ok.length != hashes.length) {
                revert FailWord(ERR_00);
            }
        } else {
            addrs = new address[](0);
            ok = new bool[](0);
        }

        assembly ("memory-safe") {
            let ctxPtr := ctx
            let stepsMain := mload(add(ctxPtr, 0x40))
            mstore(0x00, 0)
            // Integer square root using OpenZeppelin Math.sqrt's seed and six
            // Newton refinements. The seed bounds the initial error; six steps
            // leave at most one unit of error over the entire uint256 domain.
            function sqrtWord(a) -> r {
                // For zero, the first iteration reaches zero and EVM DIV(0, 0)
                // keeps it there. One is already fixed; neither needs a branch.
                let aa := a
                r := 1
                if shr(128, aa) {
                    aa := shr(128, aa)
                    r := shl(64, r)
                }
                if shr(64, aa) {
                    aa := shr(64, aa)
                    r := shl(32, r)
                }
                if shr(32, aa) {
                    aa := shr(32, aa)
                    r := shl(16, r)
                }
                if shr(16, aa) {
                    aa := shr(16, aa)
                    r := shl(8, r)
                }
                if shr(8, aa) {
                    aa := shr(8, aa)
                    r := shl(4, r)
                }
                if shr(4, aa) {
                    aa := shr(4, aa)
                    r := shl(2, r)
                }
                if shr(2, aa) { r := shl(1, r) }
                r := shr(1, mul(3, r))
                r := shr(1, add(r, div(a, r)))
                r := shr(1, add(r, div(a, r)))
                r := shr(1, add(r, div(a, r)))
                r := shr(1, add(r, div(a, r)))
                r := shr(1, add(r, div(a, r)))
                r := shr(1, add(r, div(a, r)))
                r := sub(r, gt(r, div(a, r)))
            }

            // Prefetch tables (addresses and ok flags) built in Solidity above.
            // Returns (addr, allowed, hit).
            function preLookup(h, pHashes, pAddrs, pOk, pN) -> a, allowed, hit {
                let i := 0
                for {} lt(i, pN) { i := add(i, 1) } {
                    let hh := mload(add(pHashes, shl(5, i)))
                    if eq(hh, h) {
                        a := mload(add(pAddrs, shl(5, i)))
                        allowed := mload(add(pOk, shl(5, i)))
                        hit := 1
                        i := pN
                    }
                }
            }

            function requirePrefetchedAllowed(h, pHashes, pOk, pN) {
                let allowed := 0
                let i := 0
                for {} lt(i, pN) { i := add(i, 1) } {
                    if eq(mload(add(pHashes, shl(5, i))), h) {
                        allowed := mload(add(pOk, shl(5, i)))
                        i := pN
                    }
                }
                if iszero(allowed) { failWord(ERR_02) }
            }

            // Resolve only literals collected by the structural prepass. This
            // keeps execution targets aligned with dependency analysis.
            // A target must be a contract with code of its own. An EIP-7702 designator
            // (exactly 23 bytes, 0xef0100 || delegate) marks an EOA: it still has a private
            // key, and one signed authorization replaces the code its calls run. The
            // scratch word is restored so callers' memory assumptions are unchanged.
            function hasOwnCode(a) -> own {
                let codeSize := extcodesize(a)
                own := iszero(iszero(codeSize))
                if eq(codeSize, 23) {
                    let savedWord := mload(0x00)
                    extcodecopy(a, 0x00, 0, 3)
                    if eq(shr(232, mload(0x00)), 0xef0100) { own := 0 }
                    mstore(0x00, savedWord)
                }
            }

            function resolveTarget(h, pHashes, pAddrs, pOk, pN) -> target {
                let a, allowed, hit := preLookup(h, pHashes, pAddrs, pOk, pN)
                if iszero(and(hit, allowed)) { failWord(ERR_02) }
                if iszero(hasOwnCode(a)) { failWord(ERR_02) }
                target := a
            }

            // Reject opaque ABI calls into engine entrypoints or back into the
            // delegatecall host, whose ambient authority scripts must not use.
            function requireGenericCallTarget(target, engineAddr) {
                if or(eq(target, engineAddr), eq(target, address())) { failWord(ERR_02) }
            }

            // Policy frames preserve the authenticated vault but execute in a
            // dedicated host. Nested frames inherit this distinction.
            function isPolicyFrame(contextPtr) -> policyMode {
                policyMode := and(
                    mload(add(contextPtr, 0x160)),
                    iszero(eq(mload(add(contextPtr, 0x100)), mload(add(contextPtr, 0x140))))
                )
            }

            // Registered custom targets may mutate their own state at zero
            // outgoing value. Registry authority remains limited to PolicyState;
            // its active context checks also bind every write to the live policy.
            function requirePolicyWrite(contextPtr, target, selector, callValue) {
                if isPolicyFrame(contextPtr) {
                    if callValue { failWord(ERR_13) }
                    if eq(target, mload(add(contextPtr, 0x80))) {
                        let canonicalSelector := and(selector, 0xffffffff)
                        // setPolicyUint(bytes32,bytes32,bytes32,bytes32,uint256)
                        // consumePolicyMeter(bytes32,bytes32,uint64,uint256,uint256,bytes32,bytes32,bytes32,bytes32)
                        if and(iszero(eq(canonicalSelector, 0x21f1e4cb)), iszero(eq(canonicalSelector, 0x4671fe19))) {
                            failWord(ERR_13)
                        }
                    }
                }
            }

            // Packs selector + N args from stack and performs call/staticcall.
            // Pops N args (LIFO). Returns the new stack pointer and either
            // the READ result word (for static) or the WRITE bool result.
            function doCall(isStatic, target, selector, nArgs, sp, base, scratch) -> spOut, outWord {
                let size := checkedAdd(4, wordsToBytes(nArgs))
                checkScratchEnd(scratch, size, scratch)
                mstore(scratch, shl(224, selector))
                {
                    let i := 0
                    for {} lt(i, nArgs) { i := add(i, 1) } {
                        sp := sub(sp, 0x20)
                        if lt(sp, base) { failWord(ERR_06) }
                        mstore(add(scratch, add(4, mul(i, 32))), mload(sp))
                    }
                }
                // static path (READ)
                if iszero(iszero(isStatic)) {
                    let outPtr := add(scratch, and(add(size, 0x1f), not(0x1f)))
                    checkScratchEnd(outPtr, 0x20, scratch)
                    mstore(outPtr, 0)
                    let okc := staticcall(gas(), target, scratch, size, outPtr, 0x20)
                    if iszero(okc) { failWord(ERR_04) }
                    if lt(returndatasize(), 0x20) { failWord(ERR_00) }
                    outWord := mload(outPtr)
                }
                // mutable path (WRITE)
                if iszero(isStatic) {
                    let okc2 := call(gas(), target, 0, scratch, size, scratch, 0x20)
                    outWord := decodeWriteResult(okc2, scratch)
                }
                spOut := sp
            }

            // Same as doCall, but sends native value with CALL.
            function doCallValue(target, selector, nArgs, sp, base, scratch, callValue) -> spOut, outWord, okcOut {
                let size := checkedAdd(4, wordsToBytes(nArgs))
                checkScratchEnd(scratch, size, scratch)
                mstore(scratch, shl(224, selector))
                {
                    let i := 0
                    for {} lt(i, nArgs) { i := add(i, 1) } {
                        sp := sub(sp, 0x20)
                        if lt(sp, base) { failWord(ERR_06) }
                        mstore(add(scratch, add(4, mul(i, 32))), mload(sp))
                    }
                }
                // mutable path (WRITE with value)
                let okc := call(gas(), target, callValue, scratch, size, scratch, 0x20)
                outWord := decodeWriteResult(okc, scratch)
                okcOut := okc
                spOut := sp
            }

            // WRITE-family opcodes expose optional-bool semantics while also
            // accepting write calls that return non-bool data, such as Lido
            // shares or Uniswap amount arrays.
            function decodeWriteResult(okc, outPtr) -> outWord {
                if iszero(okc) {
                    if iszero(mload(0x00)) { failWord(ERR_04) }
                    outWord := 0
                }
                if okc {
                    switch returndatasize()
                    case 0 { outWord := 1 }
                    default {
                        if lt(returndatasize(), 0x20) { failWord(ERR_00) }
                        outWord := mload(outPtr)
                        if gt(outWord, 1) { outWord := 1 }
                    }
                }
            }

            function failWord(word) {
                // NOFAIL is scoped to low-level WRITE transport failures in
                // decodeWriteResult. Structural VM errors, failed READ/CALLI,
                // budget exhaustion, and malformed returndata always revert.
                mstore(0x00, 0x80cf34d400000000000000000000000000000000000000000000000000000000)
                mstore(0x04, word)
                // A failed structural, read, or budget check must roll back the execution tree; NOFAIL covers only
                // WRITE transport failures.
                // forge-lint: disable-next-line(require-revert-in-loop)
                revert(0x00, 36)
            }

            function checkUnder(spPtr, basePtr) {
                if lt(spPtr, basePtr) { failWord(ERR_06) }
            }

            function checkedAdd(a, b) -> c {
                c := add(a, b)
                if lt(c, a) { failWord(ERR_08) }
            }

            function wordsToBytes(words) -> out {
                out := mul(words, 0x20)
                if iszero(eq(div(out, 0x20), words)) { failWord(ERR_08) }
            }

            function checkScratchEnd(ptr, lenBytes, scratchPtr) {
                if lt(ptr, scratchPtr) { failWord(ERR_08) }
                let end := checkedAdd(ptr, lenBytes)
                let limit := checkedAdd(scratchPtr, 0x4000)
                if gt(end, limit) { failWord(ERR_08) }
            }

            function checkStackBytes(top, basePtr, lenBytes) {
                if gt(lenBytes, sub(top, basePtr)) { failWord(ERR_06) }
            }

            function doStaticLink(
                relation,
                subjectPtr,
                maxStepsValue,
                stepsIn,
                referencesIn,
                reg,
                logicalHostArg,
                executionAuthorityArg,
                engineAddr,
                readOnlyMode,
                depth,
                activeFramesPtr,
                scratchPtr
            ) -> result, stepsOut, referencesOut {
                if iszero(mload(subjectPtr)) { failWord(ERR_02) }
                let selector := _RUN_LINKED_SELECTOR
                let headSize := 0x100
                if readOnlyMode {
                    selector := _RUN_LINKED_NESTED_SELECTOR
                    headSize := 0x120
                }
                mstore(scratchPtr, shl(224, selector))
                let head := add(scratchPtr, 4)
                mstore(head, relation)
                mstore(add(head, 0x20), headSize)
                mstore(add(head, 0x40), maxStepsValue)
                mstore(add(head, 0x60), stepsIn)
                mstore(add(head, 0x80), referencesIn)
                if iszero(readOnlyMode) {
                    mstore(add(head, 0xA0), reg)
                    mstore(add(head, 0xC0), executionAuthorityArg)
                    mstore(add(head, 0xE0), add(depth, 1))
                }
                if readOnlyMode {
                    mstore(add(head, 0xA0), reg)
                    mstore(add(head, 0xC0), logicalHostArg)
                    mstore(add(head, 0xE0), add(depth, 1))
                }
                let subjectHead := add(head, headSize)
                let subjectLength := mload(subjectPtr)
                mstore(subjectHead, subjectLength)
                let size := add(add(4, headSize), add(0x20, shl(5, subjectLength)))
                checkScratchEnd(scratchPtr, size, scratchPtr)
                mcopy(add(subjectHead, 0x20), add(subjectPtr, 0x20), shl(5, subjectLength))
                if readOnlyMode {
                    let activeOffset := add(headSize, add(0x20, shl(5, subjectLength)))
                    mstore(add(head, 0x100), activeOffset)
                    let activeHead := add(head, activeOffset)
                    let activeLength := mload(activeFramesPtr)
                    size := add(add(4, activeOffset), add(0x20, shl(5, activeLength)))
                    checkScratchEnd(scratchPtr, size, scratchPtr)
                    mstore(activeHead, activeLength)
                    mcopy(add(activeHead, 0x20), add(activeFramesPtr, 0x20), shl(5, activeLength))
                }
                let okc := staticcall(gas(), engineAddr, scratchPtr, size, scratchPtr, 0x60)
                if iszero(okc) {
                    returndatacopy(0, 0, returndatasize())
                    // A failed structural, read, or budget check must roll back the execution tree; NOFAIL covers
                    // only WRITE transport failures.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert(0, returndatasize())
                }
                if lt(returndatasize(), 0x60) { failWord(ERR_00) }
                result := mload(scratchPtr)
                stepsOut := mload(add(scratchPtr, 0x20))
                referencesOut := mload(add(scratchPtr, 0x40))
            }

            function doReadOnlyCalli(
                spIn,
                basePtr,
                scratchPtr,
                staticIds,
                staticIdCount,
                subjectPtr,
                maxStepsValue,
                stepsIn,
                referencesIn,
                reg,
                logicalHostArg,
                engineAddr,
                depth,
                activeFramesPtr
            ) -> spOut, stepsOut, referencesOut {
                let sp := sub(spIn, 0x20)
                checkUnder(sp, basePtr)
                let nArgs := mload(sp)
                sp := sub(sp, 0x20)
                checkUnder(sp, basePtr)
                let childId := mload(sp)
                let staticIdAllowed := 0
                for { let i := 0 } lt(i, staticIdCount) { i := add(i, 1) } {
                    if eq(childId, mload(add(staticIds, shl(5, i)))) {
                        staticIdAllowed := 1
                        i := staticIdCount
                    }
                }
                if iszero(staticIdAllowed) { failWord(ERR_02) }
                if gt(nArgs, div(sub(sp, basePtr), 0x20)) { failWord(ERR_06) }
                sp := sub(sp, shl(5, nArgs))
                checkUnder(sp, basePtr)

                mstore(scratchPtr, shl(224, _RUN_READ_ONLY_CALLI_SELECTOR))
                let head := add(scratchPtr, 4)
                let headSize := 0x140
                let argsOff := headSize
                let subjectOff := add(argsOff, add(0x20, shl(5, nArgs)))
                let subjectLength := mload(subjectPtr)
                let activeOff := add(subjectOff, add(0x20, shl(5, subjectLength)))
                let activeLength := mload(activeFramesPtr)
                let size := add(add(4, activeOff), add(0x20, shl(5, activeLength)))
                checkScratchEnd(scratchPtr, size, scratchPtr)
                mstore(head, childId)
                mstore(add(head, 0x20), argsOff)
                mstore(add(head, 0x40), subjectOff)
                mstore(add(head, 0x60), maxStepsValue)
                mstore(add(head, 0x80), stepsIn)
                mstore(add(head, 0xA0), referencesIn)
                mstore(add(head, 0xC0), reg)
                mstore(add(head, 0xE0), logicalHostArg)
                mstore(add(head, 0x100), add(depth, 1))
                mstore(add(head, 0x120), activeOff)

                let argsHead := add(head, argsOff)
                mstore(argsHead, nArgs)
                mcopy(add(argsHead, 0x20), sp, shl(5, nArgs))
                let subjectHead := add(head, subjectOff)
                mstore(subjectHead, subjectLength)
                mcopy(add(subjectHead, 0x20), add(subjectPtr, 0x20), shl(5, subjectLength))
                let activeHead := add(head, activeOff)
                mstore(activeHead, activeLength)
                mcopy(add(activeHead, 0x20), add(activeFramesPtr, 0x20), shl(5, activeLength))
                let okc := staticcall(gas(), engineAddr, scratchPtr, size, scratchPtr, 0x60)
                if iszero(okc) {
                    returndatacopy(0, 0, returndatasize())
                    // A failed structural, read, or budget check must roll back the execution tree; NOFAIL covers
                    // only WRITE transport failures.
                    // forge-lint: disable-next-line(require-revert-in-loop)
                    revert(0, returndatasize())
                }
                if lt(returndatasize(), 0x60) { failWord(ERR_00) }
                mstore(sp, mload(scratchPtr))
                spOut := add(sp, 0x20)
                if gt(spOut, scratchPtr) { failWord(ERR_08) }
                stepsOut := mload(add(scratchPtr, 0x20))
                referencesOut := mload(add(scratchPtr, 0x40))
            }

            // CALLI handler: invokes nested interactions while sharing step and value budgets.
            function doCalli(
                spIn,
                basePtr,
                scratchPtr,
                stepsIn,
                maxStepsValue,
                remainingIn,
                reg,
                actorLocal,
                engineAddr,
                staticIds,
                staticIdCount,
                subjectPtr,
                referencesIn,
                depth
            ) -> spOut, stepsOut, remainingOut, referencesOut {
                let sp := spIn
                let steps := stepsIn
                let remaining := remainingIn

                // stack before: [..., arg data..., interactionId, nArgs]
                sp := sub(sp, 0x20)
                checkUnder(sp, basePtr)
                mstore(scratchPtr, mload(sp))
                sp := sub(sp, 0x20)
                checkUnder(sp, basePtr)

                let staticIdAllowed := 0
                {
                    let i := 0
                    for {} lt(i, staticIdCount) { i := add(i, 1) } {
                        if eq(mload(sp), mload(add(staticIds, shl(5, i)))) {
                            staticIdAllowed := 1
                            i := staticIdCount
                        }
                    }
                }
                if iszero(staticIdAllowed) { failWord(ERR_02) }

                // Validate parent stack availability before using nArgs for memory
                // sizing. Without this, a malformed CALLI could allocate or hit the
                // registry before the VM reports the actual stack underflow.
                if gt(mload(scratchPtr), div(sub(sp, basePtr), 0x20)) { failWord(ERR_06) }

                // Memory layout is monotonic and non-overlapping:
                // [scratchPtr, callBuf)        argument count and reserved args region
                // [callBuf, callScratchEnd)    registry call scratch
                // [scriptBuf, scriptEnd)       ABI bytes returned by registry
                // [subBuf, total)              runSub calldata
                // Parent nArgs can be large, so the child script buffer must not be
                // allocated at the free pointer before the args region is accounted
                // for; otherwise parent args can overwrite the fetched child script.
                // Arguments now copy directly from the parent stack into the final
                // child calldata; the reserved layout remains disjoint throughout.
                let argsData := add(scratchPtr, 0x20)
                let callBuf := add(argsData, mul(mload(scratchPtr), 0x20))
                let callScratchEnd := add(callBuf, 0x260)
                if gt(callScratchEnd, mload(0x40)) { mstore(0x40, callScratchEnd) }
                mstore(callBuf, shl(224, _GET_INTERACTION_FLAGS_SELECTOR))
                mstore(add(callBuf, 4), mload(sp))
                let okFlags := staticcall(gas(), reg, callBuf, 0x24, callBuf, 0x20)
                if iszero(okFlags) { failWord(ERR_04) }
                if lt(returndatasize(), 0x20) { failWord(ERR_00) }
                if and(mload(callBuf), _INTERACTION_UNAVAILABLE_FLAGS) { failWord(ERR_02) }

                mstore(callBuf, shl(224, 0x08615d08))
                mstore(add(callBuf, 4), mload(sp))
                let okScript := staticcall(gas(), reg, callBuf, 0x24, 0, 0)
                if iszero(okScript) { failWord(ERR_04) }
                let rdlen := returndatasize()
                let scriptBuf := callScratchEnd
                let scriptEnd := add(scriptBuf, and(add(rdlen, 31), not(31)))
                if gt(scriptEnd, mload(0x40)) { mstore(0x40, scriptEnd) }
                returndatacopy(scriptBuf, 0, rdlen)
                if lt(rdlen, 0x40) { failWord(ERR_00) }
                let offScript := mload(scriptBuf)
                if iszero(eq(offScript, 0x20)) { failWord(ERR_00) }
                if gt(offScript, sub(rdlen, 0x20)) { failWord(ERR_00) }
                mstore(callBuf, mload(add(scriptBuf, offScript)))
                if gt(mload(callBuf), sub(rdlen, add(offScript, 0x20))) { failWord(ERR_00) }
                if iszero(mload(callBuf)) { failWord(ERR_07) }
                mstore(add(callBuf, 0x20), and(add(mload(callBuf), 31), not(31)))

                sp := sub(sp, mul(mload(scratchPtr), 0x20))
                checkUnder(sp, basePtr)

                // Build calldata for runSub, including immutable subject and
                // the shared raw-reference budget.
                let subBuf := scriptEnd
                mstore(subBuf, shl(224, _RUN_SUB_SELECTOR))
                let head := add(subBuf, 4)
                let headSize := 0x160
                let argsOff := add(headSize, add(0x20, mload(add(callBuf, 0x20))))
                let subjectOff := add(argsOff, add(0x20, mul(mload(scratchPtr), 0x20)))
                mstore(head, headSize)
                mstore(add(head, 0x20), argsOff)
                mstore(add(head, 0x40), maxStepsValue)
                mstore(add(head, 0x60), steps)
                mstore(add(head, 0x80), remaining)
                mstore(add(head, 0xA0), reg)
                mstore(add(head, 0xC0), actorLocal)
                mstore(add(head, 0xE0), engineAddr)
                mstore(add(head, 0x100), subjectOff)
                mstore(add(head, 0x120), referencesIn)
                mstore(add(head, 0x140), add(depth, 1))

                mstore(add(head, headSize), mload(callBuf))
                {
                    let scriptData := add(add(head, headSize), 0x20)
                    let scriptLength := mload(callBuf)
                    // Clear the partial final word before copying exact bytes.
                    // This cannot clobber the following argument length word.
                    if and(scriptLength, 31) { mstore(add(scriptData, and(scriptLength, not(31))), 0) }
                    mcopy(scriptData, add(add(scriptBuf, offScript), 0x20), scriptLength)
                }

                let argsHead := add(head, argsOff)
                mstore(argsHead, mload(scratchPtr))
                mcopy(add(argsHead, 0x20), sp, shl(5, mload(scratchPtr)))
                let subjectHead := add(head, subjectOff)
                let subjectLength := mload(subjectPtr)
                mstore(subjectHead, subjectLength)
                mcopy(add(subjectHead, 0x20), add(subjectPtr, 0x20), shl(5, subjectLength))
                let total := add(subjectHead, add(0x20, mul(subjectLength, 0x20)))
                if gt(total, mload(0x40)) { mstore(0x40, and(add(total, 31), not(31))) }
                // Recursion executes via delegatecall into the same engine code.
                let parentNofail := mload(0x00)
                let okc := delegatecall(gas(), engineAddr, subBuf, sub(total, subBuf), subBuf, 0x80)
                if iszero(okc) { failWord(ERR_04) }
                if lt(returndatasize(), 0x80) { failWord(ERR_00) }
                mstore(0x00, parentNofail)
                let nestedTop := mload(subBuf)
                steps := mload(add(subBuf, 0x20))
                remaining := mload(add(subBuf, 0x40))
                referencesOut := mload(add(subBuf, 0x60))
                mstore(sp, nestedTop)
                sp := add(sp, 0x20)
                if gt(sp, scratchPtr) { failWord(ERR_08) }

                spOut := sp
                stepsOut := steps
                remainingOut := remaining
            }

            // typed calldata builder for dynamic word-arrays.
            // argKinds: bit i set => arg i is dynamic array of 32-byte words.
            // Stack (before opcode), top at right:
            //   [... data for args ..., h, selector, nArgs, argKinds]            (READX/WRITEX)
            //   [... data for args ..., h, selector, nArgs, argKinds, value]    (WRITEVX)
            // For each arg i from 0..nArgs-1:
            //   if static (bit i == 0): push its 1 word value when building the script
            //   if dynamic (bit i == 1): push elem[0], elem[1], ..., elem[len-1], then push len
            // Walk arguments once, retaining reverse tail order and validating
            // every length before copying. Scratch is disjoint from the stack;
            // a later validation failure reverts before any external call.
            function packTypedArguments(selector, nArgs, argKinds, sp, base, scratch) -> spOut, size {
                // Layout: [ selector(4) | head(n*32) | tail(...) ]
                mstore(scratch, shl(224, selector))
                let headStart := checkedAdd(scratch, 4)
                let tp := checkedAdd(headStart, wordsToBytes(nArgs))
                checkScratchEnd(scratch, sub(tp, scratch), scratch)
                spOut := sp
                for { let i := nArgs } i {} {
                    i := sub(i, 1)
                    spOut := sub(spOut, 0x20)
                    checkUnder(spOut, base)
                    let word := mload(spOut)
                    switch and(1, shr(i, argKinds))
                    case 0 { mstore(add(headStart, shl(5, i)), word) }
                    default {
                        let elemBytes := wordsToBytes(word)
                        let tailEnd := checkedAdd(tp, checkedAdd(0x20, elemBytes))
                        // Preserve scratch-limit precedence over array underflow.
                        checkScratchEnd(scratch, sub(tailEnd, scratch), scratch)
                        checkStackBytes(spOut, base, elemBytes)
                        spOut := sub(spOut, elemBytes)
                        checkUnder(spOut, base)
                        // Offsets are relative to headStart. Array elements retain
                        // their source order even though arguments are visited backwards.
                        mstore(add(headStart, shl(5, i)), sub(tp, headStart))
                        mstore(tp, word)
                        mcopy(add(tp, 0x20), spOut, elemBytes)
                        tp := tailEnd
                    }
                }
                size := sub(tp, scratch)
            }

            function doCallTyped(isStatic, target, selector, nArgs, argKinds, sp, base, scratch) -> spOut, outWord {
                let size
                spOut, size := packTypedArguments(selector, nArgs, argKinds, sp, base, scratch)
                checkScratchEnd(scratch, size, scratch)
                // static path (READX)
                if iszero(iszero(isStatic)) {
                    let outPtr := add(scratch, and(add(size, 0x1f), not(0x1f)))
                    checkScratchEnd(outPtr, 0x20, scratch)
                    mstore(outPtr, 0)
                    let okc := staticcall(gas(), target, scratch, size, outPtr, 0x20)
                    if iszero(okc) { failWord(ERR_04) }
                    if lt(returndatasize(), 0x20) { failWord(ERR_00) }
                    outWord := mload(outPtr)
                }
                // mutable path (WRITEX)
                if iszero(isStatic) {
                    let okc2 := call(gas(), target, 0, scratch, size, scratch, 0x20)
                    outWord := decodeWriteResult(okc2, scratch)
                }
            }

            function doCallValueTyped(target, selector, nArgs, argKinds, sp, base, scratch, callValue) ->
                spOut,
                outWord,
                okcOut
            {
                let size
                spOut, size := packTypedArguments(selector, nArgs, argKinds, sp, base, scratch)
                checkScratchEnd(scratch, size, scratch)
                let okc := call(gas(), target, callValue, scratch, size, scratch, 0x20)
                outWord := decodeWriteResult(okc, scratch)
                okcOut := okc
            }

            // Delegate one recursive ABI encoding and target call to the
            // canonical stateless encoder. The descriptor and target remain
            // immutable instruction data; tape words come from either an exact
            // authenticated argument slice or evaluated stack values.
            function doCallABI(
                encoderAddr,
                engineAddr,
                target,
                selector,
                mode,
                callValue,
                maxWork,
                descriptorPtr,
                descriptorLength,
                tapeLength,
                tapeDataPtr,
                wordCount,
                scratchPtr
            ) -> failure, returnWordsPtr, workUnits {
                let headSize := 0x100
                let descriptorOffset := headSize
                let descriptorPadded := and(add(descriptorLength, 31), not(31))
                let tapeOffset := checkedAdd(descriptorOffset, checkedAdd(0x20, descriptorPadded))
                let total := checkedAdd(add(4, tapeOffset), checkedAdd(0x20, wordsToBytes(tapeLength)))
                checkScratchEnd(scratchPtr, total, scratchPtr)

                mstore(scratchPtr, shl(224, _EXECUTE_ABI_SELECTOR))
                let head := add(scratchPtr, 4)
                mstore(head, engineAddr)
                mstore(add(head, 0x20), target)
                mstore(add(head, 0x40), shl(224, selector))
                mstore(add(head, 0x60), mode)
                mstore(add(head, 0x80), callValue)
                mstore(add(head, 0xA0), maxWork)
                mstore(add(head, 0xC0), descriptorOffset)
                mstore(add(head, 0xE0), tapeOffset)

                let descriptorHead := add(head, descriptorOffset)
                mstore(descriptorHead, descriptorLength)
                let descriptorData := add(descriptorHead, 0x20)
                mstore(add(descriptorData, descriptorLength), 0)
                mcopy(descriptorData, descriptorPtr, descriptorLength)

                let tapeHead := add(head, tapeOffset)
                mstore(tapeHead, tapeLength)
                mcopy(add(tapeHead, 0x20), tapeDataPtr, wordsToBytes(tapeLength))

                // The canonical helper returns two scalar fields and one exact
                // bounded word array, including on target failure or budget exhaustion.
                let resultBytes := add(0x80, shl(5, wordCount))
                let okEncoder := delegatecall(gas(), encoderAddr, scratchPtr, total, scratchPtr, resultBytes)
                if iszero(okEncoder) { failWord(ERR_12) }
                if iszero(eq(returndatasize(), resultBytes)) { failWord(ERR_00) }
                if or(
                    iszero(eq(mload(add(scratchPtr, 0x40)), 0x60)),
                    iszero(eq(mload(add(scratchPtr, 0x60)), wordCount))
                ) {
                    failWord(ERR_00)
                }
                failure := mload(scratchPtr)
                workUnits := mload(add(scratchPtr, 0x20))
                returnWordsPtr := add(scratchPtr, 0x80)
            }

            function executeABIOp(
                mode,
                pcIn,
                spIn,
                basePtr,
                argsPtr,
                pHashes,
                pAddrs,
                pOk,
                hashCount,
                contextPtr,
                scratchPtr,
                stepsIn
            ) -> pcOut, spOut, stepsOut {
                let isWrite := lt(sub(mode, 1), 2) // only modes 1 and 2 write
                if and(isWrite, mload(add(contextPtr, 0x120))) {
                    failWord(ERR_11)
                }
                let descriptorLength := shr(240, mload(pcIn))
                let tapeSource := byte(2, mload(pcIn))
                // The canonical structural decoder has already bounded tapeSource to 0 or 1.
                let h := mload(add(pcIn, 3))
                let selector := shr(224, mload(add(pcIn, 35)))
                let descriptorPtr := add(pcIn, 39)
                let wordCount := 1
                if eq(mode, 3) {
                    // READWORDS: count:u8, indices:u16be[count], then the input
                    // descriptor. Structural decoding already checked ordering
                    // and framing; the helper independently validates the prefix.
                    wordCount := byte(0, mload(descriptorPtr))
                    let selectionBytes := add(1, mul(wordCount, 2))
                    descriptorLength := add(descriptorLength, selectionBytes)
                }
                pcOut := add(descriptorPtr, descriptorLength)

                let sp := spIn
                let callValue := 0
                if eq(mode, 2) {
                    sp := sub(sp, 0x20)
                    checkUnder(sp, basePtr)
                    callValue := mload(sp)
                    if gt(callValue, mload(add(contextPtr, 0x60))) { failWord(ERR_09) }
                }
                sp := sub(sp, 0x20)
                checkUnder(sp, basePtr)
                let tapeLength := mload(sp)
                if gt(tapeLength, 384) { failWord(ERR_12) }
                let tapeDataPtr := 0
                if tapeSource {
                    sp := sub(sp, 0x20)
                    checkUnder(sp, basePtr)
                    let tapeStart := mload(sp)
                    if gt(tapeStart, mload(argsPtr)) { failWord(ERR_12) }
                    if gt(tapeLength, sub(mload(argsPtr), tapeStart)) { failWord(ERR_12) }
                    tapeDataPtr := add(add(argsPtr, 0x20), wordsToBytes(tapeStart))
                }
                if iszero(tapeSource) {
                    let tapeBytes := wordsToBytes(tapeLength)
                    checkStackBytes(sp, basePtr, tapeBytes)
                    sp := sub(sp, tapeBytes)
                    tapeDataPtr := sp
                }

                spOut := add(sp, shl(5, wordCount))
                if gt(spOut, scratchPtr) { failWord(ERR_08) }
                let target := resolveTarget(h, pHashes, pAddrs, pOk, hashCount)
                requireGenericCallTarget(target, mload(add(contextPtr, 0xC0)))
                if isWrite { requirePolicyWrite(contextPtr, target, selector, callValue) }
                let encoderAddr := mload(add(contextPtr, 0x1E0))
                if iszero(eq(extcodehash(encoderAddr), mload(add(contextPtr, 0x1C0)))) { failWord(ERR_12) }
                let maxWork := sub(mload(add(contextPtr, 0x20)), stepsIn)
                let failure, returnWordsPtr, workUnits :=
                    doCallABI(
                        encoderAddr,
                        mload(add(contextPtr, 0xC0)),
                        target,
                        selector,
                        mode,
                        callValue,
                        maxWork,
                        descriptorPtr,
                        descriptorLength,
                        tapeLength,
                        tapeDataPtr,
                        wordCount,
                        scratchPtr
                    )
                if failure {
                    if or(iszero(isWrite), or(iszero(mload(0x00)), iszero(eq(failure, ERR_04)))) { failWord(failure) }
                }
                if gt(workUnits, maxWork) { failWord(ERR_00) }
                stepsOut := add(stepsIn, workUnits)
                if and(eq(mode, 2), iszero(failure)) {
                    mstore(add(contextPtr, 0x60), sub(mload(add(contextPtr, 0x60)), callValue))
                }
                mcopy(sp, returnWordsPtr, shl(5, wordCount))
            }

            /* initial pointers */
            let pc1 := add(script, 0x20)
            let sp := mload(0x40)
            let base := sp // remember stack base for under-flow checks
            let _getPriceSel := _GET_TOKEN_PRICE_FRESH_SELECTOR
            let _tryProductRatioSel := _TRY_PRODUCT_RATIO_SELECTOR
            // Scratch starts after the bounded frame-local stack reserve.
            let scratch := add(sp, shl(5, stackCapacity))
            mstore(0x40, checkedAdd(scratch, 0x4000))

            /* interpreter loop */
            for {} 1 {} {
                if iszero(lt(pc1, add(add(script, 0x20), mload(script)))) { break }
                if lt(pc1, add(script, 0x20)) { failWord(ERR_07) }
                if iszero(lt(stepsMain, mload(add(ctxPtr, 0x20)))) { failWord(ERR_03) }
                stepsMain := add(stepsMain, 1)

                let op := byte(0, mload(pc1))
                pc1 := add(pc1, 1)
                let opClass := and(op, 0xF0)

                switch opClass
                case 0x00 {
                    // PUSH32 declares a Registry reference; PUSHDATA32 is an
                    // opaque value. Runtime stack behavior is otherwise exact.
                    if or(eq(op, 0x02), eq(op, 0x04)) {
                        if gt(add(pc1, 32), add(add(script, 0x20), mload(script))) { failWord(ERR_07) }
                        mstore(sp, mload(pc1))
                        pc1 := add(pc1, 32)
                        sp := add(sp, 0x20)
                        if gt(sp, scratch) { failWord(ERR_08) }
                        continue
                    }
                    switch op
                    // STOP: halt and return the current stack top, if any.
                    case 0x00 {
                        break
                    }
                    // PUSH1: push the next byte as one word.
                    case 0x01 {
                        if gt(add(pc1, 1), add(add(script, 0x20), mload(script))) { failWord(ERR_07) }
                        mstore(sp, byte(0, mload(pc1)))
                        pc1 := add(pc1, 1)
                        sp := add(sp, 0x20)
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // PUSH8: push the next big-endian uint64 as one word.
                    case 0x03 {
                        if gt(add(pc1, 8), add(add(script, 0x20), mload(script))) { failWord(ERR_07) }
                        mstore(sp, shr(192, mload(pc1)))
                        pc1 := add(pc1, 8)
                        sp := add(sp, 0x20)
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    default { failWord(ERR_05) }
                    continue
                }
                case 0x10 {
                    switch op
                    // SQRT: floor(sqrt(word)); zero is a valid operand/result.
                    case 0x1c {
                        let ptr := sub(sp, 0x20)
                        checkUnder(ptr, base)
                        mstore(ptr, sqrtWord(mload(ptr)))
                    }
                    // NOT: replace the top word with its bitwise complement.
                    case 0x17 {
                        let ptr := sub(sp, 0x20)
                        checkUnder(ptr, base)
                        mstore(ptr, not(mload(ptr)))
                        sp := add(ptr, 0x20)
                    }
                    // REQUIRE: pop a condition and fail when it is zero.
                    case 0x18 {
                        let ptr := sub(sp, 0x20)
                        checkUnder(ptr, base)
                        if iszero(mload(ptr)) { failWord(ERR_01) }
                        sp := ptr
                    }
                    // RATIO: evaluate the exact fixed-width product-ratio descriptor.
                    case 0x1a {
                        // Immediate: [factorCount:uint8][denominatorMask:uint16].
                        // The factors stay in source evaluation order on the stack;
                        // mask bit i classifies factor i as a denominator.
                        let scriptEnd := add(add(script, 0x20), mload(script))
                        if gt(add(pc1, 3), scriptEnd) { failWord(ERR_07) }
                        let factorCount := byte(0, mload(pc1))
                        let denominatorMask := or(shl(8, byte(0, mload(add(pc1, 1)))), byte(0, mload(add(pc1, 2))))
                        pc1 := add(pc1, 3)

                        let factorBytes := shl(5, factorCount)
                        // Check available bytes before subtraction. RATIO may
                        // consume 512 bytes, so relying on the current memory
                        // base being above that value would be brittle.
                        checkStackBytes(sp, base, factorBytes)
                        let ptr := sub(sp, factorBytes)

                        // ABI encode tryProductRatio(mask, factors) in scratch.
                        mstore(scratch, shl(224, _tryProductRatioSel))
                        mstore(add(scratch, 4), denominatorMask)
                        mstore(add(scratch, 36), 0x40)
                        mstore(add(scratch, 68), factorCount)
                        let inputSize := add(100, factorBytes)
                        checkScratchEnd(scratch, inputSize, scratch)
                        mcopy(add(scratch, 100), ptr, factorBytes)
                        let okc := staticcall(gas(), mload(add(ctxPtr, 0xC0)), scratch, inputSize, scratch, 0x40)
                        if iszero(okc) { failWord(ERR_00) }
                        if lt(returndatasize(), 0x40) { failWord(ERR_00) }
                        if gt(mload(scratch), 1) { failWord(ERR_00) }
                        if iszero(mload(scratch)) { failWord(ERR_10) }
                        mstore(ptr, mload(add(scratch, 0x20)))
                        sp := add(ptr, 0x20)
                    }
                    // KECCAK: hash the immediate-counted stack words in source order.
                    case 0x1b {
                        // Immediate: [wordCount:uint8]. Each input contributes
                        // one complete 32-byte word, matching static ABI encoding.
                        let scriptEnd := add(add(script, 0x20), mload(script))
                        if gt(add(pc1, 1), scriptEnd) { failWord(ERR_07) }
                        let wordCount := byte(0, mload(pc1))
                        pc1 := add(pc1, 1)

                        let inputBytes := shl(5, wordCount)
                        checkStackBytes(sp, base, inputBytes)
                        let ptr := sub(sp, inputBytes)
                        mstore(ptr, keccak256(ptr, inputBytes))
                        sp := add(ptr, 0x20)
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    default {
                        // Binary arithmetic / bitwise ops share the same stack plumbing.
                        let ptr := sub(sp, 0x40)
                        checkUnder(ptr, base)
                        let a := mload(ptr)
                        let b := mload(add(ptr, 0x20))
                        switch op
                        // ADD: replace the top two words with their wrapping sum.
                        case 0x10 { mstore(ptr, add(a, b)) }
                        // SUB: replace the top two words with their wrapping difference.
                        case 0x11 { mstore(ptr, sub(a, b)) }
                        // MUL: replace the top two words with their wrapping product.
                        case 0x12 { mstore(ptr, mul(a, b)) }
                        // DIV: replace the top two words with unsigned a / b.
                        case 0x13 { mstore(ptr, div(a, b)) }
                        // MOD: replace the top two words with unsigned a % b.
                        case 0x19 { mstore(ptr, mod(a, b)) }
                        // AND: replace the top two words with their bitwise conjunction.
                        case 0x14 { mstore(ptr, and(a, b)) }
                        // OR: replace the top two words with their bitwise disjunction.
                        case 0x15 { mstore(ptr, or(a, b)) }
                        // XOR: replace the top two words with their bitwise exclusive-or.
                        case 0x16 { mstore(ptr, xor(a, b)) }
                        default { failWord(ERR_05) }
                        sp := add(ptr, 0x20)
                    }
                    continue
                }
                case 0x60 {
                    // Comparison ops (return 1 on true, 0 on false).
                    let ptr := sub(sp, 0x40)
                    checkUnder(ptr, base)
                    let a := mload(ptr)
                    let b := mload(add(ptr, 0x20))
                    switch op
                    // EQ: push one when a equals b.
                    case 0x60 { mstore(ptr, eq(a, b)) }
                    // NEQ: push one when a differs from b.
                    case 0x61 { mstore(ptr, iszero(eq(a, b))) }
                    // LT: push one when unsigned a is less than b.
                    case 0x62 { mstore(ptr, lt(a, b)) }
                    // GT: push one when unsigned a is greater than b.
                    case 0x63 { mstore(ptr, gt(a, b)) }
                    // LTE: push one when unsigned a is at most b.
                    case 0x64 { mstore(ptr, or(lt(a, b), eq(a, b))) }
                    // GTE: push one when unsigned a is at least b.
                    case 0x65 { mstore(ptr, or(gt(a, b), eq(a, b))) }
                    default { failWord(ERR_05) }
                    sp := add(ptr, 0x20)
                    continue
                }
                case 0x40 {
                    // Stack ops and extended addressing ops.
                    switch op
                    // DUP1: duplicate the top stack word.
                    case 0x40 {
                        let ptr := sub(sp, 0x20)
                        checkUnder(ptr, base)
                        let x := mload(ptr)
                        mstore(sp, x)
                        sp := add(sp, 0x20)
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // DROP: remove the top stack word.
                    case 0x41 {
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                    }
                    // SWAP1: exchange the top two stack words.
                    case 0x42 {
                        let dst := sub(sp, 0x40)
                        checkUnder(dst, base)
                        let a := mload(sub(sp, 0x20))
                        let b := mload(dst)
                        mstore(sub(sp, 0x20), b)
                        mstore(dst, a)
                    }
                    default {
                        switch and(iszero(lt(op, 0x44)), iszero(gt(op, 0x4A)))
                        // DUP2 through DUP8 duplicate the selected depth onto the top.
                        case 1 {
                            let depth := sub(op, 0x42)
                            let ptr := sub(sp, shl(5, depth))
                            checkUnder(ptr, base)
                            let x := mload(ptr)
                            mstore(sp, x)
                            sp := add(sp, 0x20)
                            if gt(sp, scratch) { failWord(ERR_08) }
                        }
                        default {
                            switch and(iszero(lt(op, 0x4C)), iszero(gt(op, 0x4F)))
                            // PICK3 through PICK6 move the selected depth to the top.
                            case 1 {
                                let depth := sub(op, 0x49)
                                let ptr := sub(sp, shl(5, depth))
                                checkUnder(ptr, base)
                                let top1 := sub(sp, 0x20)
                                let x := mload(ptr)
                                mcopy(ptr, add(ptr, 0x20), sub(top1, ptr))
                                mstore(top1, x)
                            }
                            default { failWord(ERR_05) }
                        }
                    }
                    continue
                }
                case 0x50 {
                    switch and(iszero(lt(op, 0x50)), iszero(gt(op, 0x51)))
                    // PICK7 and PICK8 move the selected depth to the top.
                    case 1 {
                        let depth := sub(op, 0x49)
                        let ptr := sub(sp, shl(5, depth))
                        checkUnder(ptr, base)
                        let top1 := sub(sp, 0x20)
                        let x := mload(ptr)
                        mcopy(ptr, add(ptr, 0x20), sub(top1, ptr))
                        mstore(top1, x)
                    }
                    default {
                        switch and(iszero(lt(op, 0x52)), iszero(gt(op, 0x58)))
                        // SWAP2 through SWAP8 exchange the top with the selected depth.
                        case 1 {
                            let depth := sub(op, 0x50)
                            let dst := sub(sp, shl(5, add(depth, 1)))
                            checkUnder(dst, base)
                            let a := mload(sub(sp, 0x20))
                            let b := mload(dst)
                            mstore(sub(sp, 0x20), b)
                            mstore(dst, a)
                        }
                        default { failWord(ERR_05) }
                    }
                    continue
                }
                case 0x30 {
                    switch op
                    // JUMPI: consume a condition and apply the immediate relative jump when true.
                    case 0x30 {
                        if gt(add(pc1, 2), add(add(script, 0x20), mload(script))) { failWord(ERR_07) }
                        let hi := byte(0, mload(pc1))
                        let lo := byte(1, mload(pc1))
                        pc1 := add(pc1, 2)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let cond := mload(sp)
                        if iszero(iszero(cond)) {
                            pc1 := add(pc1, sub(or(shl(8, hi), lo), 1))
                            // jump target must remain within [scriptPtr, end)
                            if or(lt(pc1, add(script, 0x20)), iszero(lt(pc1, add(add(script, 0x20), mload(script))))) {
                                failWord(ERR_07)
                            }
                        }
                    }
                    // JMP: apply the immediate relative jump unconditionally.
                    case 0x31 {
                        if gt(add(pc1, 2), add(add(script, 0x20), mload(script))) { failWord(ERR_07) }
                        let hi := byte(0, mload(pc1))
                        let lo := byte(1, mload(pc1))
                        pc1 := add(pc1, 2)
                        pc1 := add(pc1, sub(or(shl(8, hi), lo), 1))
                        // jump target must remain within [scriptPtr, end)
                        if or(lt(pc1, add(script, 0x20)), iszero(lt(pc1, add(add(script, 0x20), mload(script))))) {
                            failWord(ERR_07)
                        }
                    }
                    // SUBJECT: replace a selector with one immutable root-context word.
                    case 0x32 {
                        if iszero(mload(add(ctxPtr, 0x160))) { failWord(ERR_02) }
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let subjectSelector := mload(sp)
                        if iszero(lt(subjectSelector, 7)) {
                            let subjectIndex := sub(subjectSelector, 7)
                            if iszero(lt(subjectIndex, mload(add(subjectEnvelope, 0xC0)))) {
                                failWord(ERR_02)
                            }
                        }
                        mstore(sp, mload(add(subjectEnvelope, shl(5, add(subjectSelector, 1)))))
                        sp := add(sp, 0x20)
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // VALUEUSD: conservatively value one amount using the inline asset and freshness.
                    case 0x33 {
                        // Immediate: <assetHash:bytes32> <maxAge:uint32>.
                        let scriptEnd := add(add(script, 0x20), mload(script))
                        if gt(add(pc1, 36), scriptEnd) { failWord(ERR_07) }
                        let assetHash := mload(pc1)
                        let maxAge := shr(224, mload(add(pc1, 0x20)))
                        if or(iszero(maxAge), gt(maxAge, 172800)) { failWord(ERR_02) }
                        pc1 := add(pc1, 36)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let amount := mload(sp)
                        let inputSize := 0x64
                        mstore(scratch, shl(224, _GET_TOKEN_VALUE_USD18_SELECTOR))
                        mstore(add(scratch, 4), assetHash)
                        mstore(add(scratch, 36), amount)
                        mstore(add(scratch, 68), maxAge)
                        if iszero(assetHash) {
                            mstore(scratch, shl(224, _GET_NATIVE_VALUE_USD18_SELECTOR))
                            mstore(add(scratch, 4), amount)
                            mstore(add(scratch, 36), maxAge)
                            inputSize := 0x44
                        }
                        let okValue := staticcall(gas(), mload(add(ctxPtr, 0x80)), scratch, inputSize, scratch, 0x20)
                        if iszero(okValue) {
                            returndatacopy(0, 0, returndatasize())
                            // A failed structural, read, or budget check must roll back the execution tree; NOFAIL
                            // covers only WRITE transport failures.
                            // forge-lint: disable-next-line(require-revert-in-loop)
                            revert(0, returndatasize())
                        }
                        if lt(returndatasize(), 0x20) { failWord(ERR_00) }
                        mstore(sp, mload(scratch))
                        sp := add(sp, 0x20)
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // TRANSFER_NATIVE: send a bounded amount to one canonical address word.
                    // Zero is a successful no-op so a zero native budget cannot become
                    // an arbitrary external callback capability.
                    case 0x34 {
                        if mload(add(ctxPtr, 0x120)) { failWord(ERR_11) }
                        if isPolicyFrame(ctxPtr) { failWord(ERR_13) }
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let amount := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let recipient := mload(sp)
                        if or(iszero(recipient), shr(160, recipient)) { failWord(ERR_02) }
                        if gt(amount, mload(add(ctxPtr, 0x60))) { failWord(ERR_09) }
                        let okc := 1
                        if amount {
                            okc := call(gas(), recipient, amount, 0, 0, 0, 0)
                            if okc {
                                mstore(add(ctxPtr, 0x60), sub(mload(add(ctxPtr, 0x60)), amount))
                            }
                        }
                        mstore(sp, okc)
                        sp := add(sp, 0x20)
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    default {
                        // Cases 0x30..0x34 were handled above in this nibble.
                        if gt(op, 0x38) { failWord(ERR_05) }
                        pc1, sp, stepsMain :=
                            executeABIOp(
                            sub(op, 0x35),
                            pc1,
                            sp,
                            base,
                            args,
                            add(hashes, 0x20),
                            add(addrs, 0x20),
                            add(ok, 0x20),
                            mload(hashes),
                            ctxPtr,
                            scratch,
                            stepsMain
                        )
                    }
                    continue
                }
                case 0x20 {
                    // Calls, resolution and context-dependent opcodes.
                    switch op
                    // READ: staticcall one Registry-resolved target and push its result.
                    case 0x20 {
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let nArgs := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let selector := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let h := mload(sp)
                        let target :=
                            resolveTarget(h, add(hashes, 0x20), add(addrs, 0x20), add(ok, 0x20), mload(hashes))
                        requireGenericCallTarget(target, mload(add(ctxPtr, 0xC0)))
                        {
                            let sp2, out := doCall(1, target, selector, nArgs, sp, base, scratch)
                            sp := sp2
                            mstore(sp, out)
                            sp := add(sp, 0x20)
                        }
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // WRITE: call one Registry-resolved target without native value.
                    case 0x21 {
                        if mload(add(ctxPtr, 0x120)) { failWord(ERR_11) }
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let nArgs := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let selector := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let h := mload(sp)
                        let target :=
                            resolveTarget(h, add(hashes, 0x20), add(addrs, 0x20), add(ok, 0x20), mload(hashes))
                        requireGenericCallTarget(target, mload(add(ctxPtr, 0xC0)))
                        requirePolicyWrite(ctxPtr, target, selector, 0)
                        {
                            let sp2, out := doCall(0, target, selector, nArgs, sp, base, scratch)
                            sp := sp2
                            mstore(sp, out)
                            sp := add(sp, 0x20)
                        }
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // WRITEV: call one Registry-resolved target with native value.
                    case 0x26 {
                        if mload(add(ctxPtr, 0x120)) { failWord(ERR_11) }
                        // Stack layout before executing (top at right):
                        // [..., args..., h, selector, nArgs, value]
                        // Pops: value, nArgs, selector, h, and nArgs arguments
                        // Pushes: decoded optional bool result.
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let callValue := mload(sp)
                        // Enforce total native value cap.
                        if gt(callValue, mload(add(ctxPtr, 0x60))) { failWord(ERR_09) }
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let nArgs := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let selector := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let h := mload(sp)

                        let target :=
                            resolveTarget(h, add(hashes, 0x20), add(addrs, 0x20), add(ok, 0x20), mload(hashes))
                        requireGenericCallTarget(target, mload(add(ctxPtr, 0xC0)))
                        requirePolicyWrite(ctxPtr, target, selector, callValue)
                        {
                            let sp2, out, okc := doCallValue(target, selector, nArgs, sp, base, scratch, callValue)
                            if okc {
                                mstore(add(ctxPtr, 0x60), sub(mload(add(ctxPtr, 0x60)), callValue))
                            }
                            sp := sp2
                            mstore(sp, out)
                            sp := add(sp, 0x20)
                        }
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // READX: staticcall with a bitmask describing dynamic-array arguments.
                    case 0x27 {
                        // Stack before: [..., arg data..., h, selector, nArgs, argKinds]
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let kinds := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let nArgs := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let selector := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let h := mload(sp)

                        let target :=
                            resolveTarget(h, add(hashes, 0x20), add(addrs, 0x20), add(ok, 0x20), mload(hashes))
                        requireGenericCallTarget(target, mload(add(ctxPtr, 0xC0)))
                        {
                            let sp2, out := doCallTyped(1, target, selector, nArgs, kinds, sp, base, scratch)
                            sp := sp2
                            mstore(sp, out)
                            sp := add(sp, 0x20)
                        }
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // WRITEX: call without value using dynamic-array argument metadata.
                    case 0x28 {
                        if mload(add(ctxPtr, 0x120)) { failWord(ERR_11) }
                        // Stack before: [..., arg data..., h, selector, nArgs, argKinds]
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let kinds := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let nArgs := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let selector := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let h := mload(sp)

                        let target :=
                            resolveTarget(h, add(hashes, 0x20), add(addrs, 0x20), add(ok, 0x20), mload(hashes))
                        requireGenericCallTarget(target, mload(add(ctxPtr, 0xC0)))
                        requirePolicyWrite(ctxPtr, target, selector, 0)
                        {
                            let sp2, out := doCallTyped(0, target, selector, nArgs, kinds, sp, base, scratch)
                            sp := sp2
                            mstore(sp, out)
                            sp := add(sp, 0x20)
                        }
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // WRITEVX: call with value using dynamic-array argument metadata.
                    case 0x29 {
                        if mload(add(ctxPtr, 0x120)) { failWord(ERR_11) }
                        // Stack before: [..., arg data..., h, selector, nArgs, argKinds, value]
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let callValue := mload(sp)
                        // Enforce total native value cap.
                        if gt(callValue, mload(add(ctxPtr, 0x60))) { failWord(ERR_09) }
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let kinds := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let nArgs := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let selector := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let h := mload(sp)

                        let target :=
                            resolveTarget(h, add(hashes, 0x20), add(addrs, 0x20), add(ok, 0x20), mload(hashes))
                        requireGenericCallTarget(target, mload(add(ctxPtr, 0xC0)))
                        requirePolicyWrite(ctxPtr, target, selector, callValue)
                        {
                            let sp2, out, okc :=
                                doCallValueTyped(target, selector, nArgs, kinds, sp, base, scratch, callValue)
                            if okc {
                                mstore(add(ctxPtr, 0x60), sub(mload(add(ctxPtr, 0x60)), callValue))
                            }
                            sp := sp2
                            mstore(sp, out)
                            sp := add(sp, 0x20)
                        }
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // RESOLVE: replace a Registry hash with its allowlisted address.
                    case 0x22 {
                        // stack: [..., h] -> [..., addr]
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let h := mload(sp)
                        let addr := resolveTarget(h, add(hashes, 0x20), add(addrs, 0x20), add(ok, 0x20), mload(hashes))
                        mstore(sp, addr)
                        sp := add(sp, 0x20)
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // ARG: replace an index with the corresponding frame argument or zero.
                    case 0x23 {
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let idx := mload(sp)
                        // If idx < nInit, load from original args; else push 0.
                        let nInit := mload(args)
                        if lt(idx, nInit) { mstore(sp, mload(add(add(args, 0x20), mul(idx, 0x20)))) }
                        if iszero(lt(idx, nInit)) { mstore(sp, 0) }
                        sp := add(sp, 0x20)
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // CALLER: push the governed vault or the authenticated raw-execution actor.
                    case 0x24 {
                        let callerValue := mload(add(ctxPtr, 0xA0))
                        if mload(add(ctxPtr, 0x160)) { callerValue := mload(add(ctxPtr, 0x140)) }
                        mstore(sp, callerValue)
                        sp := add(sp, 0x20)
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // TIME: push the current block timestamp.
                    case 0x25 {
                        let t := timestamp()
                        mstore(sp, t)
                        sp := add(sp, 0x20)
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // THIS: push the authenticated host, including inside static frames.
                    case 0x2D {
                        let thisValue := address()
                        if mload(add(ctxPtr, 0x120)) { thisValue := mload(add(ctxPtr, 0x100)) }
                        mstore(sp, thisValue)
                        sp := add(sp, 0x20)
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // BALANCE: replace an owner address with its native balance.
                    case 0x2E {
                        if lt(sub(sp, base), 0x20) { failWord(ERR_06) }
                        let ptr := sub(sp, 0x20)
                        let owner := mload(ptr)
                        mstore(ptr, balance(owner))
                    }
                    // CALLI: execute a public child interaction under shared budgets and subject.
                    case 0x2A {
                        let sp2 := 0
                        let steps2 := 0
                        let remaining2 := mload(add(ctxPtr, 0x60))
                        let references2 := 0
                        if iszero(mload(add(ctxPtr, 0x120))) {
                            sp2, steps2, remaining2, references2 :=
                                doCalli(
                                sp,
                                base,
                                scratch,
                                stepsMain,
                                mload(add(ctxPtr, 0x20)),
                                mload(add(ctxPtr, 0x60)),
                                mload(add(ctxPtr, 0x80)),
                                mload(add(ctxPtr, 0xA0)),
                                mload(add(ctxPtr, 0xC0)),
                                add(staticCalliIds, 0x20),
                                mload(staticCalliIds),
                                subjectEnvelope,
                                mload(add(ctxPtr, 0x180)),
                                mload(add(ctxPtr, 0x1A0))
                            )
                        }
                        if mload(add(ctxPtr, 0x120)) {
                            sp2, steps2, references2 :=
                                doReadOnlyCalli(
                                sp,
                                base,
                                scratch,
                                add(staticCalliIds, 0x20),
                                mload(staticCalliIds),
                                subjectEnvelope,
                                mload(add(ctxPtr, 0x20)),
                                stepsMain,
                                mload(add(ctxPtr, 0x180)),
                                mload(add(ctxPtr, 0x80)),
                                mload(add(ctxPtr, 0x100)),
                                mload(add(ctxPtr, 0xC0)),
                                mload(add(ctxPtr, 0x1A0)),
                                activeFrames
                            )
                        }
                        sp := sp2
                        stepsMain := steps2
                        mstore(add(ctxPtr, 0x60), remaining2)
                        mstore(add(ctxPtr, 0x180), references2)
                    }
                    // PRICEUSD: replace a token hash and scaling inputs with its fresh USD price.
                    case 0x2B {
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let maxAge := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let outDec := mload(sp)
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        let h := mload(sp)

                        // PRICEUSD token metadata is part of the approval
                        // dependency hash. Reject hashes that were not declared
                        // as PUSH32 literals during structural validation.
                        requirePrefetchedAllowed(h, add(hashes, 0x20), add(ok, 0x20), mload(hashes))

                        // staticcall registry.getTokenUsdPriceScaledFresh(h, outDec, maxAge)
                        mstore(scratch, shl(224, _getPriceSel))
                        mstore(add(scratch, 4), h)
                        mstore(add(scratch, 36), outDec)
                        mstore(add(scratch, 68), maxAge)
                        let outPtr := add(scratch, 0x80)
                        mstore(outPtr, 0)
                        let okPrice := staticcall(gas(), mload(add(ctxPtr, 0x80)), scratch, 0x64, outPtr, 0x20)
                        if iszero(okPrice) { failWord(ERR_02) }
                        if lt(returndatasize(), 0x20) { failWord(ERR_00) }
                        mstore(sp, mload(outPtr))
                        sp := add(sp, 0x20)
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // STATICLINK: lazily execute one base-scoped artifact in read-only mode.
                    case 0x2F {
                        let scriptEnd := add(add(script, 0x20), mload(script))
                        if gt(add(pc1, 0x20), scriptEnd) { failWord(ERR_07) }
                        if iszero(mload(add(ctxPtr, 0x160))) { failWord(ERR_02) }
                        let relation := mload(pc1)
                        if iszero(relation) { failWord(ERR_02) }
                        pc1 := add(pc1, 0x20)
                        let linkedResult, linkedSteps, linkedReferences :=
                            doStaticLink(
                                relation,
                                subjectEnvelope,
                                mload(add(ctxPtr, 0x20)),
                                stepsMain,
                                mload(add(ctxPtr, 0x180)),
                                mload(add(ctxPtr, 0x80)),
                                mload(add(ctxPtr, 0x100)),
                                caller(),
                                mload(add(ctxPtr, 0xC0)),
                                mload(add(ctxPtr, 0x120)),
                                mload(add(ctxPtr, 0x1A0)),
                                activeFrames,
                                scratch
                            )
                        stepsMain := linkedSteps
                        mstore(add(ctxPtr, 0x180), linkedReferences)
                        mstore(sp, linkedResult)
                        sp := add(sp, 0x20)
                        if gt(sp, scratch) { failWord(ERR_08) }
                    }
                    // NOFAIL: toggle suppression of low-level WRITE transport failures.
                    case 0x2C {
                        mstore(0x00, iszero(mload(0x00)))
                    }
                    default { failWord(ERR_05) }
                    continue
                }
                case 0xF0 {
                    switch op
                    // RETURN: pop and return one explicit result word.
                    case 0xFF {
                        mstore(add(ctxPtr, 0x1C0), div(sub(sp, base), 0x20))
                        sp := sub(sp, 0x20)
                        checkUnder(sp, base)
                        stackTop := mload(sp)
                        mstore(add(ctxPtr, 0xE0), 1)
                        break
                    }
                    default { failWord(ERR_05) }
                }
                default { failWord(ERR_05) }
            }
            // return top of stack by default if STOP hit
            if iszero(mload(add(ctxPtr, 0xE0))) { if gt(sp, base) { stackTop := mload(sub(sp, 0x20)) } }
            stepsUsedOut := stepsMain
            remainingValueOut := mload(add(ctxPtr, 0x60))
            referencesUsedOut := mload(add(ctxPtr, 0x180))
            stackWordsOut := div(sub(sp, base), 0x20)
            if mload(add(ctxPtr, 0xE0)) { stackWordsOut := mload(add(ctxPtr, 0x1C0)) }
            // Only scalar results escape. Inputs, context and prefetch tables
            // precede base; all stack/scratch allocations above it are dead.
            // Let the caller encode the result without expanding past scratch.
            mstore(0x40, base)
        }
    }
}
