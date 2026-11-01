// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {MiniScriptLimits} from "./MiniScriptLimits.sol";
import {ProductRatioMath} from "./ProductRatioMath.sol";

/// @title MiniScriptBytecode
/// @notice Canonical structural decoder and categorized static-reference analyzer.
/// @dev Every on-chain scanner uses this decoder before skipping variable-width
///      immediates. Keeping framing, jump validation, and reference classification
///      together prevents immediate bytes from being interpreted as opcodes or dependencies.
library MiniScriptBytecode {
    /// @dev Bytes occupied by opcode, factor count, and uint16 denominator mask.
    uint256 internal constant RATIO_INSTRUCTION_BYTES = 4;
    /// @dev Bytes occupied by PUSHDATA32 and its non-reference word.
    uint256 internal constant PUSH_DATA_32_INSTRUCTION_BYTES = 33;
    /// @dev Bytes occupied by opcode and uint8 word count.
    uint256 internal constant KECCAK_INSTRUCTION_BYTES = 2;
    /// @dev Bytes occupied by opcode and relation word.
    uint256 internal constant STATICLINK_INSTRUCTION_BYTES = 33;
    /// @dev Bytes occupied by opcode, asset word, and uint32 maximum feed age.
    uint256 internal constant VALUEUSD_INSTRUCTION_BYTES = 37;
    /// @dev Bytes occupied by opcode, descriptor length, tape source, target hash, and selector.
    uint256 internal constant ABI_CALL_FIXED_BYTES = 40;
    /// @dev Maximum raw syntactic references accepted in one script.
    uint256 internal constant MAX_STATIC_REFERENCES = 128;
    /// @dev Maximum freshness bound an inline valuation may request.
    uint32 internal constant MAX_VALUATION_FEED_AGE = 2 days;

    /// @notice Categorized static references and completeness facts for one script.
    struct DecodedReferences {
        /// @notice Generic PUSH32 targets not consumed as CALLI identifiers.
        bytes32[] targets;
        /// @notice Statically declared CALLI child interaction identifiers.
        bytes32[] calliIds;
        /// @notice Inline STATICLINK relation identifiers.
        bytes32[] linkedRelations;
        /// @notice Inline VALUEUSD asset identifiers, including zero for native value.
        bytes32[] priceAssets;
        /// @notice Raw reference count before first-occurrence deduplication.
        uint256 rawReferenceCount;
        /// @notice False when a dynamic CALLI prevents complete dependency analysis.
        bool complete;
        /// @notice True when the script contains stack-based PRICEUSD.
        bool readsStackPrice;
        /// @notice True when decoding failed specifically because the raw-reference cap was exceeded.
        bool referenceLimitExceeded;
    }

    struct ScanState {
        uint256 calliCount;
        uint256 targetCapacity;
        uint256 linkedCapacity;
        uint256 priceCapacity;
        bool complete;
        bool readsStackPrice;
        bool hasJumps;
    }

    /// @notice Thrown when instruction framing, descriptors, or jump targets are invalid.
    error MalformedBytecode();
    /// @notice Thrown when a script contains too many raw static references.
    error StaticReferenceLimitExceeded();

    /// @notice Validate the fixed-width RATIO instruction at `pc`.
    /// @param script Complete MiniScript bytecode.
    /// @param pc Byte offset of the RATIO opcode.
    function validateRatio(bytes memory script, uint256 pc) internal pure {
        if (!isValidRatio(script, pc)) revert MalformedBytecode();
    }

    /// @notice Return whether the fixed-width RATIO instruction at `pc` is valid.
    /// @dev Dependency analysis uses this non-reverting form so an invalid child
    ///      can become an opaque dependency without weakening strict validation
    ///      of a root or of a child that execution actually enters.
    /// @param script Complete MiniScript bytecode.
    /// @param pc Byte offset of the RATIO opcode.
    /// @return valid True when framing, factor count, and denominator mask are valid.
    function isValidRatio(bytes memory script, uint256 pc) internal pure returns (bool) {
        if (pc > script.length || script.length - pc < RATIO_INSTRUCTION_BYTES) return false;
        uint256 factorCount = uint8(script[pc + 1]);
        uint256 denominatorMask = (uint256(uint8(script[pc + 2])) << 8) | uint256(uint8(script[pc + 3]));
        uint256 factorMask = factorCount <= ProductRatioMath.MAX_FACTORS ? (uint256(1) << factorCount) - 1 : 0;
        return factorCount >= 2 && factorCount <= ProductRatioMath.MAX_FACTORS && denominatorMask != 0
            && denominatorMask != factorMask && denominatorMask == (denominatorMask & factorMask);
    }

    /// @notice Strictly decode one script and return its categorized references.
    /// @param script Complete MiniScript bytecode.
    /// @return refs Categorized and deduplicated static references.
    function decode(bytes memory script) internal pure returns (DecodedReferences memory refs) {
        bool valid;
        (valid, refs) = tryDecode(script);
        if (!valid) {
            // Strict decoding rejects the complete malformed script; callers requiring partial analysis use
            // tryDecode.
            // forge-lint: disable-next-line(require-revert-in-loop)
            if (refs.referenceLimitExceeded) revert StaticReferenceLimitExceeded();
            // Strict decoding rejects the complete malformed script; callers requiring partial analysis use
            // tryDecode.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert MalformedBytecode();
        }
    }

    /// @notice Return whether instruction framing and jump targets are structurally valid.
    /// @dev Unknown one-byte opcodes remain structurally framed and are rejected
    ///      by the interpreter only if reached. Variable-width instructions use
    ///      the same rules consumed by strict execution and dependency analysis.
    /// @param script Complete MiniScript bytecode.
    /// @return valid True when the script has valid framing and jump targets.
    function isStructurallyValid(bytes memory script) internal pure returns (bool) {
        (bool valid,) = tryDecode(script);
        return valid;
    }

    /// @notice Return whether `opcode` appears at an instruction boundary.
    /// @dev Immediate and recursive-ABI descriptor bytes are never interpreted as
    ///      opcodes. A malformed suffix stops the scan; malformed scripts cannot
    ///      execute because the engine performs strict structural decoding first.
    function containsOpcode(bytes memory script, uint8 opcode) internal pure returns (bool) {
        uint256 i = 0;
        while (i < script.length) {
            uint8 current = uint8(script[i]);
            if (current == opcode) return true;
            uint256 width = _instructionWidth(script, i, current);
            if (width == 0 || width > script.length - i) return false;
            unchecked {
                i += width;
            }
        }
        return false;
    }

    /// @notice Decode one script, validate all framing and jumps, and classify references.
    /// @dev Raw syntactic references are counted before first-occurrence deduplication.
    /// @param script Complete MiniScript bytecode.
    /// @return valid False for malformed framing, invalid jumps, invalid immediates, or excess references.
    /// @return refs Partial failure facts or complete categorized references.
    function tryDecode(bytes memory script) internal pure returns (bool valid, DecodedReferences memory refs) {
        uint256 len = script.length;
        bytes memory markers = new bytes(len);
        ScanState memory scan;
        (valid, scan) = _scan(script, markers);
        if (!valid) return (false, refs);

        refs.complete = scan.complete;
        refs.readsStackPrice = scan.readsStackPrice;
        if (scan.calliCount > MAX_STATIC_REFERENCES) {
            refs.referenceLimitExceeded = true;
            return (false, refs);
        }
        bytes32[] memory calliScratch = new bytes32[](scan.calliCount);
        bytes32[] memory targetScratch = new bytes32[](scan.targetCapacity);
        bytes32[] memory linkedScratch = new bytes32[](scan.linkedCapacity);
        bytes32[] memory priceScratch = new bytes32[](scan.priceCapacity);
        uint256 uniqueCalliCount = 0;
        uint256 targetCount = 0;
        uint256 linkedCount = 0;
        uint256 priceCount = 0;
        uint256 rawCount = scan.calliCount;
        uint256 i = 0;
        while (i < len) {
            uint8 op = uint8(script[i]);
            if ((uint8(markers[i]) & 8) != 0) {
                uniqueCalliCount = _appendUnique(calliScratch, uniqueCalliCount, _readBytes32(script, i + 1));
            }
            if (op == 0x02 && (uint8(markers[i]) & 4) == 0) {
                if (++rawCount > MAX_STATIC_REFERENCES) {
                    refs.referenceLimitExceeded = true;
                    return (false, refs);
                }
                targetCount = _appendUnique(targetScratch, targetCount, _readBytes32(script, i + 1));
            } else if (op == 0x2F) {
                bytes32 relation = _readBytes32(script, i + 1);
                if (relation == bytes32(0)) return (false, refs);
                if (++rawCount > MAX_STATIC_REFERENCES) {
                    refs.referenceLimitExceeded = true;
                    return (false, refs);
                }
                linkedCount = _appendUnique(linkedScratch, linkedCount, relation);
            } else if (op == 0x33) {
                uint32 maxAge = _readUint32(script, i + 33);
                if (maxAge == 0 || maxAge > MAX_VALUATION_FEED_AGE) return (false, refs);
                if (++rawCount > MAX_STATIC_REFERENCES) {
                    refs.referenceLimitExceeded = true;
                    return (false, refs);
                }
                priceCount = _appendUnique(priceScratch, priceCount, _readBytes32(script, i + 1));
            } else if (op >= 0x35 && op <= 0x38) {
                if (++rawCount > MAX_STATIC_REFERENCES) {
                    refs.referenceLimitExceeded = true;
                    return (false, refs);
                }
                targetCount = _appendUnique(targetScratch, targetCount, _readBytes32(script, i + 4));
            }
            unchecked {
                i += _instructionWidth(script, i, op);
            }
        }

        refs.targets = _truncate(targetScratch, targetCount);
        refs.calliIds = _truncate(calliScratch, uniqueCalliCount);
        refs.linkedRelations = _truncate(linkedScratch, linkedCount);
        refs.priceAssets = _truncate(priceScratch, priceCount);
        refs.rawReferenceCount = rawCount;
        return (true, refs);
    }

    /// @dev Validate the whole frame before exposing any reference failure facts.
    function _scan(bytes memory script, bytes memory markers) private pure returns (bool valid, ScanState memory scan) {
        uint256 len = script.length;
        uint256 i = 0;
        uint256 previousStart = 0;
        uint256 lastStart = 0;
        uint8 previousOp = 0;
        uint8 lastOp = 0;
        scan.complete = true;

        while (i < len) {
            markers[i] = bytes1(uint8(markers[i]) | 1);
            uint8 op = uint8(script[i]);
            uint256 width = _instructionWidth(script, i, op);
            if (width == 0 || width > len - i) return (false, scan);
            if (op == 0x30 || op == 0x31) {
                scan.hasJumps = true;
                uint256 offset = (uint256(uint8(script[i + 1])) << 8) | uint256(uint8(script[i + 2]));
                uint256 target = i + 2 + offset;
                if (target >= len) return (false, scan);
                markers[target] = bytes1(uint8(markers[target]) | 2);
            }
            // Classify while framing, but defer reference failure until the whole
            // frame and its jumps have been validated. After the first excess CALLI,
            // freeze the partial facts at the same point as the original decoder.
            if (scan.calliCount <= MAX_STATIC_REFERENCES) {
                if (op == 0x2A) {
                    bool lastPush = lastOp == 0x01 || lastOp == 0x02 || lastOp == 0x03;
                    if (previousOp == 0x02 && lastPush) {
                        // Bit 2 excludes both operands from generic references;
                        // bit 3 identifies the id to collect in source order.
                        markers[previousStart] = bytes1(uint8(markers[previousStart]) | 12);
                        markers[lastStart] = bytes1(uint8(markers[lastStart]) | 4);
                        ++scan.calliCount;
                    } else {
                        scan.complete = false;
                    }
                }
                if (op == 0x2B) scan.readsStackPrice = true;
            }
            // Upper bounds include PUSH32 CALLI operands, which collection skips.
            // Capacities stay bounded even for a script that will fail the raw cap.
            if (op == 0x02 || (op >= 0x35 && op <= 0x38)) {
                if (scan.targetCapacity < MAX_STATIC_REFERENCES) ++scan.targetCapacity;
            } else if (op == 0x2F) {
                if (scan.linkedCapacity < MAX_STATIC_REFERENCES) ++scan.linkedCapacity;
            } else if (op == 0x33) {
                if (scan.priceCapacity < MAX_STATIC_REFERENCES) ++scan.priceCapacity;
            }
            previousStart = lastStart;
            previousOp = lastOp;
            lastStart = i;
            lastOp = op;
            unchecked {
                i += width;
            }
        }
        // Only low bits 2 are invalid: a destination without a boundary.
        // CALLI classification lives in separate high bits.
        // Skip empty words, which cover most long immediates and ABI descriptors.
        // Inspect nonzero words bytewise so padding can never cause rejection.
        bool hasJumps = scan.hasJumps;
        assembly ("memory-safe") {
            valid := 1
            let end := add(add(markers, 0x20), mload(markers))
            if iszero(hasJumps) { end := markers }
            for { let ptr := add(markers, 0x20) } lt(ptr, end) {} {
                let word := mload(ptr)
                if eq(and(byte(0, word), 3), 2) {
                    valid := 0
                    break
                }
                ptr := add(ptr, add(1, mul(31, iszero(word))))
            }
        }
    }

    function _instructionWidth(bytes memory script, uint256 pc, uint8 op) private pure returns (uint256) {
        if (op == 0x01) return 2;
        if (op == 0x02) return 33;
        if (op == 0x03) return 9;
        if (op == 0x04) return PUSH_DATA_32_INSTRUCTION_BYTES;
        if (op == 0x30 || op == 0x31) return 3;
        if (op == 0x1A) return isValidRatio(script, pc) ? RATIO_INSTRUCTION_BYTES : 0;
        if (op == 0x1B) return KECCAK_INSTRUCTION_BYTES;
        if (op == 0x2F) return STATICLINK_INSTRUCTION_BYTES;
        if (op == 0x33) return VALUEUSD_INSTRUCTION_BYTES;
        if (op >= 0x35 && op <= 0x38) return _abiCallWidth(script, pc);
        return 1;
    }

    function _abiCallWidth(bytes memory script, uint256 programCounter) private pure returns (uint256 width) {
        uint256 maxDescriptorBytes = MiniScriptLimits.MAX_ABI_DESCRIPTOR_BYTES;
        uint256 maxReadWords = MiniScriptLimits.MAX_READ_WORDS;
        // This decoder is embedded in both the analyzer and the size-constrained
        // engine. Check each region once before reading its fixed-width fields.
        assembly ("memory-safe") {
            function abiWidth(data, length, offset, maxDescriptor, maxWords) -> size {
                if gt(offset, length) { leave }
                let remaining := sub(length, offset)
                if lt(remaining, ABI_CALL_FIXED_BYTES) { leave }
                let start := add(data, offset)
                let descriptorLength := shr(240, mload(add(start, 1)))
                if or(lt(descriptorLength, 4), gt(descriptorLength, maxDescriptor)) { leave }
                if gt(byte(3, mload(start)), 1) { leave }
                let descriptorOffset := ABI_CALL_FIXED_BYTES
                // READWORDS inserts count:u8 and increasing indices:u16be[count]
                // before the input descriptor. The length field measures only
                // that descriptor; selection bytes cannot become opcodes or jumps.
                if eq(byte(0, mload(start)), 0x38) {
                    if eq(remaining, descriptorOffset) { leave }
                    let count := byte(0, mload(add(start, descriptorOffset)))
                    if or(iszero(count), gt(count, maxWords)) { leave }
                    descriptorOffset := add(descriptorOffset, add(1, shl(1, count)))
                    if gt(descriptorOffset, remaining) { leave }
                    let previous := shr(240, mload(add(start, 41)))
                    for { let i := 1 } lt(i, count) { i := add(i, 1) } {
                        let index := shr(240, mload(add(start, add(41, shl(1, i)))))
                        if iszero(gt(index, previous)) { leave }
                        previous := index
                    }
                }
                if gt(descriptorLength, sub(remaining, descriptorOffset)) { leave }
                let version := byte(0, mload(add(start, descriptorOffset)))
                if and(iszero(eq(version, 1)), iszero(eq(version, 2))) { leave }
                size := add(descriptorOffset, descriptorLength)
            }
            width := abiWidth(add(script, 32), mload(script), programCounter, maxDescriptorBytes, maxReadWords)
        }
    }

    function _readBytes32(bytes memory script, uint256 offset) private pure returns (bytes32 value) {
        assembly ("memory-safe") {
            value := mload(add(add(script, 0x20), offset))
        }
    }

    function _readUint32(bytes memory script, uint256 offset) private pure returns (uint32 value) {
        value = (uint32(uint8(script[offset])) << 24) | (uint32(uint8(script[offset + 1])) << 16)
            | (uint32(uint8(script[offset + 2])) << 8) | uint32(uint8(script[offset + 3]));
    }

    function _appendUnique(bytes32[] memory values, uint256 count, bytes32 value) private pure returns (uint256) {
        bool found = false;
        // Only initialized words are searched. All callers keep count within the
        // allocated category capacity; the checked append below enforces its end.
        assembly ("memory-safe") {
            let end := add(add(values, 0x20), shl(5, count))
            for { let ptr := add(values, 0x20) } lt(ptr, end) { ptr := add(ptr, 0x20) } {
                if eq(mload(ptr), value) {
                    found := 1
                    break
                }
            }
        }
        if (found) return count;
        values[count] = value;
        return count + 1;
    }

    function _truncate(bytes32[] memory values, uint256 count) private pure returns (bytes32[] memory) {
        // The scratch array has a single owner and no further appends. Expose only
        // initialized entries without allocating and copying a second array.
        assembly ("memory-safe") { mstore(values, count) }
        return values;
    }
}
