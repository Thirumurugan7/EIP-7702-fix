// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "./Delegation7702.sol";
import {MiniScriptLimits} from "./MiniScriptLimits.sol";

interface IABIEncoderExecutionHostAnalyzer {
    function requireExecutionHost(
        address logicalHost,
        address expectedEngine,
        address expectedRegistry,
        address executionAuthority
    ) external view returns (bool safeHost);
}

/// @title MiniScriptABIEncoder
/// @notice Stateless bounded encoder for recursive and precompiled Solidity ABI input values.
/// @dev The canonical MiniScript engine deploys this contract as its second CREATE
///      child and enters {execute} through DELEGATECALL. The delegatecall preserves
///      the governed host as `address(this)`, so the final target observes the same
///      caller as every other MiniScript write opcode.
contract MiniScriptABIEncoder {
    /// @notice Descriptor or root-node framing is invalid.
    error InvalidDescriptor();
    /// @notice The value tape is truncated, non-canonical, or not consumed exactly.
    error InvalidTape();
    /// @notice A descriptor, tape, expansion, or encoded call exceeds a protocol limit.
    error ResourceLimit();
    /// @notice The requested call mode or native-value combination is invalid.
    error InvalidCallMode();
    /// @notice READWORDS has an empty, oversized, truncated, or unordered selection.
    error InvalidReadSelection();
    /// @notice {execute} was not delegatecalled by the engine or a configured MiniScript host.
    error DelegatecallContextRequired();
    /// @notice The resolved external target has no runtime code.
    error TargetNotContract();

    uint8 private constant RECURSIVE_VERSION = 1;
    uint8 private constant PRECOMPILED_VERSION = 2;

    uint8 private constant PRECOMPILED_WORD = 0x00;
    uint8 private constant PRECOMPILED_ADDRESS = 0x01;
    uint8 private constant PRECOMPILED_BOOL = 0x02;
    uint8 private constant PRECOMPILED_UINT_BASE = 0x20;
    uint8 private constant PRECOMPILED_INT_BASE = 0x40;
    uint8 private constant PRECOMPILED_FIXED_BYTES_BASE = 0x60;
    uint8 private constant PRECOMPILED_EXACT_U16 = 0x80;
    uint256 private constant PRECOMPILED_HEADER_BYTES = 9;
    uint256 private constant PRECOMPILED_CONSTANT_FLAG = 0x8000;
    uint256 private constant PRECOMPILED_CONSTANT_MASK = 0x7fff;
    uint256 private constant MAX_PRECOMPILED_TAPE_WORDS = 256;

    uint8 private constant UINT = 0x00;
    uint8 private constant INT = 0x01;
    uint8 private constant ADDRESS = 0x02;
    uint8 private constant BOOL = 0x03;
    uint8 private constant FIXED_BYTES = 0x04;
    uint8 private constant TUPLE = 0x10;
    uint8 private constant FIXED_ARRAY = 0x11;
    uint8 private constant DYNAMIC_ARRAY = 0x12;
    uint8 private constant DYNAMIC_BYTES = 0x13;

    uint8 private constant READ = 0;
    uint8 private constant WRITE = 1;
    uint8 private constant WRITE_VALUE = 2;
    uint8 private constant READ_WORDS = 3;

    // ABI selectors are the leading four keccak256 bytes.
    // forge-lint: disable-next-line(unsafe-typecast)
    bytes4 private constant HOST_CONFIG_SELECTOR = bytes4(keccak256("miniScriptHostConfig()"));

    /// @dev Packed node metadata layout:
    ///      bits 0..7 kind, 8..23 parameter, 24 dynamic flag,
    ///      32..63 static byte size, 64..79 subtree-end node index.
    struct ParseState {
        uint256[] nodes;
        uint256 count;
    }

    struct Measure {
        uint256 tape;
        uint256 size;
        uint256 visits;
        bool workLimitExceeded;
    }

    struct Written {
        uint256 tape;
        uint256 size;
    }

    struct PreparedEncoding {
        uint256[] nodes;
        uint256 root;
        uint256 size;
        uint256 workUnits;
        uint256 planOffset;
        bool precompiled;
    }

    /// @notice Encode a selector and recursive ABI argument tuple without executing it.
    /// @dev This pure surface is the contract reference implementation used by tests
    ///      and off-chain equivalence checks. The descriptor root must be a tuple.
    /// @param descriptor Version 1 recursive schema or version 2 precompiled layout plan.
    /// @param tape Canonical flattened values consumed by the descriptor.
    /// @param selector Four-byte function selector prepended to the encoded tuple.
    /// @return callData Canonical selector-prefixed Solidity ABI calldata.
    /// @return workUnits Descriptor and expanded-node work charged by MiniScript.
    function encode(bytes calldata descriptor, uint256[] calldata tape, bytes4 selector)
        external
        pure
        returns (bytes memory callData, uint256 workUnits)
    {
        return _encode(descriptor, tape, selector);
    }

    /// @notice Encode one recursive ABI call and invoke its target in the host context.
    /// @dev Called only through DELEGATECALL from the canonical MiniScript engine.
    ///      Target transport failures are returned, not bubbled, so the engine can
    ///      apply its frame-local NOFAIL semantics. Encoder failures always revert.
    /// @param expectedEngine Engine that must be configured by the current host.
    /// @param target Registry-resolved target contract.
    /// @param selector Immutable function selector embedded in MiniScript bytecode.
    /// @param mode 0 for STATICCALL, 1 for CALL, 2 for CALL with native value, 3 for READWORDS.
    /// @param callValue Native value used only by mode 2.
    /// @param maxWorkUnits Remaining MiniScript work budget before the target call.
    /// @param descriptor Immutable input schema or layout plan. Mode 3 prefixes it
    ///        with count:u8 and increasing return-word indices:u16be[count].
    /// @param tape Exact authenticated argument slice interpreted by the descriptor.
    /// @return failure Zero on success, ERR_03 for work exhaustion, ERR_04 for
    ///         target failure, or ERR_00 for short returndata. The engine alone
    ///         decides whether NOFAIL may suppress a WRITE transport failure.
    /// @return workUnits Encoding work plus one unit per selected word in mode 3.
    /// @return returnWords One read word or normalized WRITE bool for modes 0..2,
    ///         or the selected raw words in mode 3.
    ///         Results remain zero when work is exhausted, the call fails, or selected data is short.
    function execute(
        address expectedEngine,
        address target,
        bytes4 selector,
        uint8 mode,
        uint256 callValue,
        uint256 maxWorkUnits,
        bytes calldata descriptor,
        uint256[] calldata tape
    ) external payable returns (bytes6 failure, uint256 workUnits, uint256[] memory returnWords) {
        _requireDelegatecallContext(expectedEngine);
        if (!Delegation7702.hasContractCode(target)) revert TargetNotContract();
        if (mode > READ_WORDS || (mode != WRITE_VALUE && callValue != 0)) revert InvalidCallMode();

        uint256 count = 1;
        uint256 selectionBytes = 0;
        uint256 requiredBytes = 32;
        if (mode == READ_WORDS) {
            if (descriptor.length == 0) revert InvalidReadSelection();
            count = uint8(descriptor[0]);
            selectionBytes = 1 + count * 2;
            if (count == 0 || count > MiniScriptLimits.MAX_READ_WORDS || descriptor.length < selectionBytes) {
                revert InvalidReadSelection();
            }
            uint256 previous = 0;
            for (uint256 i; i < count; ++i) {
                uint256 index = _u16(descriptor, 1 + i * 2);
                // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
                // forge-lint: disable-next-line(require-revert-in-loop)
                if (i != 0 && index <= previous) revert InvalidReadSelection();
                previous = index;
            }
            requiredBytes = (previous + 1) * 32;
            workUnits = count;
        }
        returnWords = new uint256[](count);
        if (workUnits > maxWorkUnits) return ("ERR_03", workUnits, returnWords);

        PreparedEncoding memory prepared;
        bool workLimitExceeded;
        bytes calldata inputDescriptor = descriptor[selectionBytes:];
        (prepared, workLimitExceeded) = _prepare(inputDescriptor, tape, maxWorkUnits - workUnits, true);
        workUnits += prepared.workUnits;
        if (workLimitExceeded) return ("ERR_03", workUnits, returnWords);
        bytes memory callData = _render(prepared, inputDescriptor, tape, selector);
        bool callSucceeded;
        uint256 returnSize;
        assembly ("memory-safe") {
            let out := add(returnWords, 0x20)
            switch or(iszero(mode), eq(mode, 3))
            case 1 {
                // Capture selected words in this frame before any other call can
                // replace its returndata. Caller memory grows only with count.
                callSucceeded := staticcall(gas(), target, add(callData, 0x20), mload(callData), 0, 0)
            }
            default {
                callSucceeded := call(gas(), target, callValue, add(callData, 0x20), mload(callData), 0, 0)
            }
            returnSize := returndatasize()
            if and(callSucceeded, iszero(lt(returnSize, requiredBytes))) {
                for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                    let index := 0
                    if selectionBytes {
                        index := shr(240, calldataload(add(descriptor.offset, add(1, mul(i, 2)))))
                    }
                    returndatacopy(add(out, mul(i, 32)), mul(index, 32), 32)
                }
            }
        }
        if (!callSucceeded) return ("ERR_04", workUnits, returnWords);
        if (mode == WRITE || mode == WRITE_VALUE) {
            if (returnSize == 0) returnWords[0] = 1;
            else if (returnSize < 32) return ("ERR_00", workUnits, returnWords);
            else if (returnWords[0] > 1) returnWords[0] = 1;
        } else if (returnSize < requiredBytes) {
            return ("ERR_00", workUnits, returnWords);
        }
    }

    function _encode(bytes calldata descriptor, uint256[] calldata tape, bytes4 selector)
        private
        pure
        returns (bytes memory callData, uint256 workUnits)
    {
        (PreparedEncoding memory prepared,) = _prepare(descriptor, tape, 0, false);
        callData = _render(prepared, descriptor, tape, selector);
        workUnits = prepared.workUnits;
    }

    function _prepare(bytes calldata descriptor, uint256[] calldata tape, uint256 maxWorkUnits, bool enforceWorkLimit)
        private
        pure
        returns (PreparedEncoding memory prepared, bool workLimitExceeded)
    {
        if (descriptor.length < 4 || descriptor.length > MiniScriptLimits.MAX_ABI_DESCRIPTOR_BYTES) {
            revert InvalidDescriptor();
        }
        if (tape.length > MiniScriptLimits.MAX_ABI_TAPE_WORDS) revert ResourceLimit();
        uint8 version = uint8(descriptor[0]);
        if (version == PRECOMPILED_VERSION) {
            return _preparePrecompiled(descriptor, tape, maxWorkUnits, enforceWorkLimit);
        }
        if (version != RECURSIVE_VERSION) revert InvalidDescriptor();

        ParseState memory state =
            ParseState({nodes: new uint256[](MiniScriptLimits.MAX_ABI_DESCRIPTOR_NODES), count: 0});
        (uint256 descriptorEnd, uint256 root) = _parseNode(descriptor, 1, descriptor.length, 1, state);
        if (descriptorEnd != descriptor.length || _kind(state.nodes[root]) != TUPLE) revert InvalidDescriptor();

        prepared.nodes = state.nodes;
        prepared.root = root;
        if (enforceWorkLimit && state.count > maxWorkUnits) {
            prepared.workUnits = state.count;
            return (prepared, true);
        }

        uint256 visitLimit = MiniScriptLimits.MAX_ABI_EXPANDED_NODES;
        if (enforceWorkLimit) visitLimit = (maxWorkUnits - state.count) / 2;
        Measure memory measured = _measure(state.nodes, root, tape, 0, 0, visitLimit);
        prepared.workUnits = state.count + measured.visits * 2;
        if (measured.workLimitExceeded) return (prepared, true);
        if (measured.tape != tape.length) revert InvalidTape();
        uint256 totalSize = measured.size + 4;
        if (totalSize > MiniScriptLimits.MAX_ABI_CALLDATA_BYTES) revert ResourceLimit();
        prepared.size = measured.size;
    }

    function _render(
        PreparedEncoding memory prepared,
        bytes calldata descriptor,
        uint256[] calldata tape,
        bytes4 selector
    ) private pure returns (bytes memory callData) {
        callData = new bytes(prepared.size + 4);
        uint256 selectorWord = uint256(uint32(selector)) << 224;
        assembly ("memory-safe") {
            mstore(add(callData, 0x20), selectorWord)
        }
        if (prepared.precompiled) {
            _renderPrecompiled(descriptor, prepared.planOffset, tape, callData);
        } else {
            Written memory written = _write(prepared.nodes, prepared.root, tape, 0, callData, 4);
            assert(written.tape == tape.length && written.size == prepared.size);
        }
    }

    function _preparePrecompiled(
        bytes calldata descriptor,
        uint256[] calldata tape,
        uint256 maxWorkUnits,
        bool enforceWorkLimit
    ) private pure returns (PreparedEncoding memory prepared, bool workLimitExceeded) {
        if (descriptor.length < PRECOMPILED_HEADER_BYTES + 4) revert InvalidDescriptor();

        uint256 schemaLength = _u16(descriptor, 1);
        uint256 tapeWords = _u16(descriptor, 3);
        uint256 outputWords = _u16(descriptor, 5);
        uint256 validationLength = _u16(descriptor, 7);
        if (schemaLength < 4 || tapeWords > MAX_PRECOMPILED_TAPE_WORDS) revert InvalidDescriptor();
        if (tape.length != tapeWords) revert InvalidTape();
        if (outputWords > (MiniScriptLimits.MAX_ABI_CALLDATA_BYTES - 4) / 32) revert ResourceLimit();

        uint256 validationStart = PRECOMPILED_HEADER_BYTES + schemaLength;
        if (validationStart > descriptor.length || uint8(descriptor[PRECOMPILED_HEADER_BYTES]) != RECURSIVE_VERSION) {
            revert InvalidDescriptor();
        }
        if (validationLength > descriptor.length - validationStart) revert InvalidDescriptor();
        uint256 planOffset = validationStart + validationLength;
        if (outputWords * 2 != descriptor.length - planOffset) revert InvalidDescriptor();

        prepared.size = outputWords * 32;
        prepared.workUnits = 1 + tapeWords + outputWords * 2;
        prepared.planOffset = planOffset;
        prepared.precompiled = true;
        if (enforceWorkLimit && prepared.workUnits > maxWorkUnits) {
            return (prepared, true);
        }

        uint256 cursor = validationStart;
        for (uint256 i; i < tapeWords; ++i) {
            cursor = _validatePrecompiledWord(descriptor, cursor, planOffset, tape[i]);
        }
        if (cursor != planOffset) revert InvalidDescriptor();

        uint256 seen = 0;
        for (uint256 i; i < outputWords; ++i) {
            uint256 source = _u16(descriptor, planOffset + i * 2);
            if ((source & PRECOMPILED_CONSTANT_FLAG) != 0) {
                uint256 value = source & PRECOMPILED_CONSTANT_MASK;
                // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
                // forge-lint: disable-next-line(require-revert-in-loop)
                if (value == 0 || (value & 31) != 0 || value > prepared.size) revert InvalidDescriptor();
            } else {
                // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
                // forge-lint: disable-next-line(require-revert-in-loop)
                if (source >= tapeWords) revert InvalidDescriptor();
                uint256 sourceMask = uint256(1) << source;
                // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
                // forge-lint: disable-next-line(require-revert-in-loop)
                if ((seen & sourceMask) != 0) revert InvalidDescriptor();
                seen |= sourceMask;
            }
        }
        uint256 expectedSeen = tapeWords == 256 ? type(uint256).max : (uint256(1) << tapeWords) - 1;
        if (seen != expectedSeen) revert InvalidDescriptor();
    }

    function _validatePrecompiledWord(bytes calldata descriptor, uint256 cursor, uint256 limit, uint256 value)
        private
        pure
        returns (uint256 nextCursor)
    {
        // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (cursor >= limit) revert InvalidDescriptor();
        uint8 validation = uint8(descriptor[cursor]);
        nextCursor = cursor + 1;
        if (validation == PRECOMPILED_WORD) return nextCursor;
        if (validation == PRECOMPILED_ADDRESS) {
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (value > type(uint160).max) revert InvalidTape();
            return nextCursor;
        }
        if (validation == PRECOMPILED_BOOL) {
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (value > 1) revert InvalidTape();
            return nextCursor;
        }
        if (validation > PRECOMPILED_UINT_BASE && validation < PRECOMPILED_INT_BASE) {
            uint256 width = validation - PRECOMPILED_UINT_BASE;
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (value >= uint256(1) << (width * 8)) revert InvalidTape();
            return nextCursor;
        }
        if (validation > PRECOMPILED_INT_BASE && validation < PRECOMPILED_FIXED_BYTES_BASE) {
            uint256 bits = (validation - PRECOMPILED_INT_BASE) * 8;
            uint256 mask = (uint256(1) << bits) - 1;
            uint256 canonical = value & mask;
            if (canonical & (uint256(1) << (bits - 1)) != 0) canonical |= ~mask;
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (canonical != value) revert InvalidTape();
            return nextCursor;
        }
        if (validation > PRECOMPILED_FIXED_BYTES_BASE && validation < PRECOMPILED_EXACT_U16) {
            uint256 width = validation - PRECOMPILED_FIXED_BYTES_BASE;
            uint256 paddingBits = (32 - width) * 8;
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (value & ((uint256(1) << paddingBits) - 1) != 0) revert InvalidTape();
            return nextCursor;
        }
        if (validation == PRECOMPILED_EXACT_U16) {
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (limit - cursor < 3) revert InvalidDescriptor();
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (value != _u16(descriptor, cursor + 1)) revert InvalidTape();
            return cursor + 3;
        }
        // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
        // forge-lint: disable-next-line(require-revert-in-loop)
        revert InvalidDescriptor();
    }

    function _renderPrecompiled(
        bytes calldata descriptor,
        uint256 planOffset,
        uint256[] calldata tape,
        bytes memory out
    ) private pure {
        uint256 outputWords = (descriptor.length - planOffset) / 2;
        for (uint256 i; i < outputWords; ++i) {
            uint256 source = _u16(descriptor, planOffset + i * 2);
            uint256 value =
                (source & PRECOMPILED_CONSTANT_FLAG) == 0 ? tape[source] : source & PRECOMPILED_CONSTANT_MASK;
            _store(out, 4 + i * 32, value);
        }
    }

    function _parseNode(
        bytes calldata descriptor,
        uint256 cursor,
        uint256 limit,
        uint256 depth,
        ParseState memory state
    ) private pure returns (uint256 nextCursor, uint256 nodeIndex) {
        if (depth > MiniScriptLimits.MAX_ABI_DESCRIPTOR_DEPTH || cursor > limit || limit - cursor < 3) {
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert InvalidDescriptor();
        }
        // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (state.count == MiniScriptLimits.MAX_ABI_DESCRIPTOR_NODES) revert ResourceLimit();

        uint8 kind = uint8(descriptor[cursor]);
        uint256 payloadLength = _u16(descriptor, cursor + 1);
        uint256 payloadStart = cursor + 3;
        // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (payloadLength > limit - payloadStart) revert InvalidDescriptor();
        uint256 payloadEnd = payloadStart + payloadLength;

        nodeIndex = state.count++;
        bool dynamicType = false;
        uint256 parameter = 0;
        uint256 staticSize = 0;

        if (kind == UINT || kind == INT || kind == FIXED_BYTES) {
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (payloadLength != 1) revert InvalidDescriptor();
            parameter = uint8(descriptor[payloadStart]);
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (parameter == 0 || parameter > 32) revert InvalidDescriptor();
            staticSize = 32;
        } else if (kind == ADDRESS || kind == BOOL) {
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (payloadLength != 0) revert InvalidDescriptor();
            staticSize = 32;
        } else if (kind == DYNAMIC_BYTES) {
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (payloadLength != 0) revert InvalidDescriptor();
            dynamicType = true;
        } else if (kind == TUPLE) {
            uint256 childCursor = payloadStart;
            while (childCursor < payloadEnd) {
                // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
                // forge-lint: disable-next-line(require-revert-in-loop)
                if (parameter == MiniScriptLimits.MAX_ABI_TUPLE_CHILDREN) revert ResourceLimit();
                uint256 child;
                (childCursor, child) = _parseNode(descriptor, childCursor, payloadEnd, depth + 1, state);
                ++parameter;
                uint256 childMeta = state.nodes[child];
                if (_dynamic(childMeta)) {
                    dynamicType = true;
                } else {
                    staticSize = _boundedAdd(staticSize, _staticSize(childMeta));
                }
            }
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (childCursor != payloadEnd) revert InvalidDescriptor();
            if (dynamicType) staticSize = 0;
        } else if (kind == FIXED_ARRAY) {
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (payloadLength < 5) revert InvalidDescriptor();
            parameter = _u16(descriptor, payloadStart);
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (parameter == 0) revert InvalidDescriptor();
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (parameter > MiniScriptLimits.MAX_ABI_ARRAY_ELEMENTS) revert ResourceLimit();
            uint256 child;
            uint256 childEnd;
            (childEnd, child) = _parseNode(descriptor, payloadStart + 2, payloadEnd, depth + 1, state);
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (childEnd != payloadEnd) revert InvalidDescriptor();
            uint256 childMeta = state.nodes[child];
            dynamicType = _dynamic(childMeta);
            if (!dynamicType) staticSize = _boundedMultiply(_staticSize(childMeta), parameter);
        } else if (kind == DYNAMIC_ARRAY) {
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (payloadLength < 3) revert InvalidDescriptor();
            uint256 childEnd;
            (childEnd,) = _parseNode(descriptor, payloadStart, payloadEnd, depth + 1, state);
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (childEnd != payloadEnd) revert InvalidDescriptor();
            dynamicType = true;
        } else {
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert InvalidDescriptor();
        }

        state.nodes[nodeIndex] = _pack(kind, parameter, dynamicType, staticSize, state.count);
        return (payloadEnd, nodeIndex);
    }

    function _measure(
        uint256[] memory nodes,
        uint256 node,
        uint256[] calldata tape,
        uint256 tapeCursor,
        uint256 visits,
        uint256 visitLimit
    ) private pure returns (Measure memory out) {
        // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (++visits > MiniScriptLimits.MAX_ABI_EXPANDED_NODES) revert ResourceLimit();
        if (visits > visitLimit) {
            return Measure({tape: tapeCursor, size: 0, visits: visits, workLimitExceeded: true});
        }
        uint256 meta = nodes[node];
        uint256 kind = _kind(meta);

        if (kind <= FIXED_BYTES) {
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (tapeCursor >= tape.length) revert InvalidTape();
            _validateWord(kind, _parameter(meta), tape[tapeCursor]);
            return Measure({tape: tapeCursor + 1, size: 32, visits: visits, workLimitExceeded: false});
        }
        if (kind == DYNAMIC_BYTES) return _measureBytes(tape, tapeCursor, visits);
        if (kind == TUPLE) return _measureTuple(nodes, node, tape, tapeCursor, visits, visitLimit);
        if (kind == FIXED_ARRAY) {
            return _measureRepeated(nodes, node + 1, _parameter(meta), tape, tapeCursor, visits, false, visitLimit);
        }
        if (kind == DYNAMIC_ARRAY) {
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (tapeCursor >= tape.length) revert InvalidTape();
            uint256 length = tape[tapeCursor++];
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (length > MiniScriptLimits.MAX_ABI_ARRAY_ELEMENTS) revert ResourceLimit();
            out = _measureRepeated(nodes, node + 1, length, tape, tapeCursor, visits, true, visitLimit);
            return out;
        }
        // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
        // forge-lint: disable-next-line(require-revert-in-loop)
        revert InvalidDescriptor();
    }

    function _measureTuple(
        uint256[] memory nodes,
        uint256 node,
        uint256[] calldata tape,
        uint256 tapeCursor,
        uint256 visits,
        uint256 visitLimit
    ) private pure returns (Measure memory out) {
        uint256 child = node + 1;
        uint256 children = _parameter(nodes[node]);
        uint256 size = 0;
        for (uint256 i; i < children; ++i) {
            uint256 childMeta = nodes[child];
            size = _boundedAdd(size, _dynamic(childMeta) ? 32 : _staticSize(childMeta));
            Measure memory measured = _measure(nodes, child, tape, tapeCursor, visits, visitLimit);
            if (measured.workLimitExceeded) return measured;
            tapeCursor = measured.tape;
            visits = measured.visits;
            if (_dynamic(childMeta)) size = _boundedAdd(size, measured.size);
            child = _subtreeEnd(childMeta);
        }
        return Measure({tape: tapeCursor, size: size, visits: visits, workLimitExceeded: false});
    }

    function _measureRepeated(
        uint256[] memory nodes,
        uint256 element,
        uint256 length,
        uint256[] calldata tape,
        uint256 tapeCursor,
        uint256 visits,
        bool withLength,
        uint256 visitLimit
    ) private pure returns (Measure memory out) {
        uint256 elementMeta = nodes[element];
        uint256 size = withLength ? 32 : 0;
        size = _boundedAdd(size, _boundedMultiply(_dynamic(elementMeta) ? 32 : _staticSize(elementMeta), length));
        for (uint256 i; i < length; ++i) {
            Measure memory measured = _measure(nodes, element, tape, tapeCursor, visits, visitLimit);
            if (measured.workLimitExceeded) return measured;
            tapeCursor = measured.tape;
            visits = measured.visits;
            if (_dynamic(elementMeta)) size = _boundedAdd(size, measured.size);
        }
        return Measure({tape: tapeCursor, size: size, visits: visits, workLimitExceeded: false});
    }

    function _measureBytes(uint256[] calldata tape, uint256 tapeCursor, uint256 visits)
        private
        pure
        returns (Measure memory out)
    {
        // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (tapeCursor >= tape.length) revert InvalidTape();
        uint256 length = tape[tapeCursor++];
        // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (length > MiniScriptLimits.MAX_ABI_DYNAMIC_BYTES) revert ResourceLimit();
        uint256 words = (length + 31) / 32;
        // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (words > tape.length - tapeCursor) revert InvalidTape();
        uint256 remainder = length & 31;
        if (remainder != 0 && words != 0) {
            uint256 paddingBits = (32 - remainder) * 8;
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (tape[tapeCursor + words - 1] & ((uint256(1) << paddingBits) - 1) != 0) revert InvalidTape();
        }
        return Measure({
            tape: tapeCursor + words,
            // words is the rounded-up ABI word count; multiplying by 32 must preserve that padding.
            // forge-lint: disable-next-line(divide-before-multiply)
            size: _boundedAdd(32, words * 32),
            visits: visits,
            workLimitExceeded: false
        });
    }

    function _write(
        uint256[] memory nodes,
        uint256 node,
        uint256[] calldata tape,
        uint256 tapeCursor,
        bytes memory out,
        uint256 outCursor
    ) private pure returns (Written memory written) {
        uint256 meta = nodes[node];
        uint256 kind = _kind(meta);
        if (kind <= FIXED_BYTES) {
            _store(out, outCursor, tape[tapeCursor]);
            return Written({tape: tapeCursor + 1, size: 32});
        }
        if (kind == DYNAMIC_BYTES) {
            uint256 length = tape[tapeCursor++];
            uint256 words = (length + 31) / 32;
            _store(out, outCursor, length);
            for (uint256 i; i < words; ++i) {
                _store(out, outCursor + 32 + i * 32, tape[tapeCursor + i]);
            }
            // The rounded-up word count includes ABI padding; converting it to bytes must follow rounding.
            // forge-lint: disable-next-line(divide-before-multiply)
            return Written({tape: tapeCursor + words, size: 32 + words * 32});
        }
        if (kind == TUPLE) return _writeTuple(nodes, node, tape, tapeCursor, out, outCursor);
        if (kind == FIXED_ARRAY) {
            return _writeRepeated(nodes, node + 1, _parameter(meta), tape, tapeCursor, out, outCursor);
        }
        if (kind == DYNAMIC_ARRAY) {
            uint256 length = tape[tapeCursor++];
            _store(out, outCursor, length);
            Written memory elements = _writeRepeated(nodes, node + 1, length, tape, tapeCursor, out, outCursor + 32);
            return Written({tape: elements.tape, size: elements.size + 32});
        }
        // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
        // forge-lint: disable-next-line(require-revert-in-loop)
        revert InvalidDescriptor();
    }

    function _writeTuple(
        uint256[] memory nodes,
        uint256 node,
        uint256[] calldata tape,
        uint256 tapeCursor,
        bytes memory out,
        uint256 outCursor
    ) private pure returns (Written memory written) {
        uint256 child = node + 1;
        uint256 children = _parameter(nodes[node]);
        uint256 headSize = 0;
        for (uint256 i; i < children; ++i) {
            uint256 childMeta = nodes[child];
            headSize += _dynamic(childMeta) ? 32 : _staticSize(childMeta);
            child = _subtreeEnd(childMeta);
        }

        child = node + 1;
        uint256 headCursor = outCursor;
        uint256 tailCursor = outCursor + headSize;
        for (uint256 i; i < children; ++i) {
            uint256 childMeta = nodes[child];
            if (_dynamic(childMeta)) {
                _store(out, headCursor, tailCursor - outCursor);
                Written memory tail = _write(nodes, child, tape, tapeCursor, out, tailCursor);
                tapeCursor = tail.tape;
                headCursor += 32;
                tailCursor += tail.size;
            } else {
                Written memory head = _write(nodes, child, tape, tapeCursor, out, headCursor);
                tapeCursor = head.tape;
                headCursor += head.size;
            }
            child = _subtreeEnd(childMeta);
        }
        return Written({tape: tapeCursor, size: tailCursor - outCursor});
    }

    function _writeRepeated(
        uint256[] memory nodes,
        uint256 element,
        uint256 length,
        uint256[] calldata tape,
        uint256 tapeCursor,
        bytes memory out,
        uint256 outCursor
    ) private pure returns (Written memory written) {
        uint256 elementMeta = nodes[element];
        uint256 headSize = (_dynamic(elementMeta) ? 32 : _staticSize(elementMeta)) * length;
        uint256 headCursor = outCursor;
        uint256 tailCursor = outCursor + headSize;
        for (uint256 i; i < length; ++i) {
            if (_dynamic(elementMeta)) {
                _store(out, headCursor, tailCursor - outCursor);
                Written memory tail = _write(nodes, element, tape, tapeCursor, out, tailCursor);
                tapeCursor = tail.tape;
                headCursor += 32;
                tailCursor += tail.size;
            } else {
                Written memory head = _write(nodes, element, tape, tapeCursor, out, headCursor);
                tapeCursor = head.tape;
                headCursor += head.size;
            }
        }
        return Written({tape: tapeCursor, size: tailCursor - outCursor});
    }

    function _validateWord(uint256 kind, uint256 width, uint256 value) private pure {
        if (kind == UINT) {
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (width != 32 && value >= uint256(1) << (width * 8)) revert InvalidTape();
            return;
        }
        if (kind == INT) {
            if (width == 32) return;
            uint256 bits = width * 8;
            uint256 mask = (uint256(1) << bits) - 1;
            uint256 canonical = value & mask;
            if (canonical & (uint256(1) << (bits - 1)) != 0) canonical |= ~mask;
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (canonical != value) revert InvalidTape();
            return;
        }
        if (kind == ADDRESS) {
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (value > type(uint160).max) revert InvalidTape();
            return;
        }
        if (kind == BOOL) {
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (value > 1) revert InvalidTape();
            return;
        }
        if (kind == FIXED_BYTES && width != 32) {
            uint256 paddingBits = (32 - width) * 8;
            // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (value & ((uint256(1) << paddingBits) - 1) != 0) revert InvalidTape();
        }
    }

    function _requireDelegatecallContext(address expectedEngine) private view {
        // Mutable frames delegatecall the engine and therefore preserve the
        // governed host as address(this). Read-only frames execute on the
        // engine through a self-STATICCALL, so the encoder's delegatecall
        // context is the engine itself. executeFrame authenticates that
        // self-call before reaching this branch.
        if (address(this) == expectedEngine && msg.sender == expectedEngine && expectedEngine != address(0)) return;

        (bool ok, bytes memory result) = address(this).staticcall(abi.encodeWithSelector(HOST_CONFIG_SELECTOR));
        if (ok && result.length == 64) {
            (address configuredEngine, address registry) = abi.decode(result, (address, address));
            if (
                expectedEngine != address(0) && configuredEngine == expectedEngine && registry != address(0)
                    && Delegation7702.hasContractCode(registry)
            ) return;
        }

        // A managed Safe cannot expose MiniScript host configuration itself.
        // Its exact tenant Interact module does, and the engine analyzer binds
        // that authority back to a currently valid SafeFactory registration.
        (ok, result) = msg.sender.staticcall(abi.encodeWithSelector(HOST_CONFIG_SELECTOR));
        if (!ok || result.length != 64) revert DelegatecallContextRequired();
        (address authorityEngine, address authorityRegistry) = abi.decode(result, (address, address));
        if (authorityEngine != expectedEngine || authorityRegistry == address(0)) revert DelegatecallContextRequired();

        address analyzer = address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", expectedEngine, hex"01")))));
        (ok, result) = analyzer.staticcall(
            abi.encodeCall(
                IABIEncoderExecutionHostAnalyzer.requireExecutionHost,
                (address(this), expectedEngine, authorityRegistry, msg.sender)
            )
        );
        if (!ok || result.length != 32 || !abi.decode(result, (bool))) revert DelegatecallContextRequired();
    }

    function _pack(uint8 kind, uint256 parameter, bool dynamicType, uint256 staticSize, uint256 subtreeEnd)
        private
        pure
        returns (uint256)
    {
        return uint256(kind) | (parameter << 8) | (dynamicType ? uint256(1) << 24 : 0) | (staticSize << 32)
            | (subtreeEnd << 64);
    }

    function _kind(uint256 meta) private pure returns (uint256) {
        return meta & type(uint8).max;
    }

    function _parameter(uint256 meta) private pure returns (uint256) {
        return (meta >> 8) & type(uint16).max;
    }

    function _dynamic(uint256 meta) private pure returns (bool) {
        return meta & (uint256(1) << 24) != 0;
    }

    function _staticSize(uint256 meta) private pure returns (uint256) {
        return (meta >> 32) & type(uint32).max;
    }

    function _subtreeEnd(uint256 meta) private pure returns (uint256) {
        return (meta >> 64) & type(uint16).max;
    }

    function _u16(bytes calldata data, uint256 offset) private pure returns (uint256) {
        return (uint256(uint8(data[offset])) << 8) | uint256(uint8(data[offset + 1]));
    }

    function _boundedAdd(uint256 a, uint256 b) private pure returns (uint256 sum) {
        sum = a + b;
        // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (sum > MiniScriptLimits.MAX_ABI_CALLDATA_BYTES - 4) revert ResourceLimit();
    }

    function _boundedMultiply(uint256 a, uint256 b) private pure returns (uint256 product) {
        // Descriptor and tape validation is atomic; skipping a bad node would encode different calldata.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (a != 0 && b > (MiniScriptLimits.MAX_ABI_CALLDATA_BYTES - 4) / a) revert ResourceLimit();
        product = a * b;
    }

    function _store(bytes memory out, uint256 offset, uint256 value) private pure {
        assembly ("memory-safe") {
            mstore(add(add(out, 0x20), offset), value)
        }
    }
}
