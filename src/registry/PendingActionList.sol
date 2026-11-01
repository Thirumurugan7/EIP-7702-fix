// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @notice Bounded pending references with stable slots and shared action identifiers.
/// @dev A singleton occupies one slot. Larger sets use a bitmap and four uint64 ids per word.
///      Callers retain each returned position in their immutable dependency data.
library PendingActionList {
    bytes32 private constant SLOT = keccak256("okc.storage.pending.action.ids");
    uint256 private constant SINGLE = 1 << 255;
    uint256 private constant INDEX_MASK = type(uint64).max;
    error TooManyPendingActions();

    struct Identifiers {
        uint64 nonce;
        mapping(bytes32 => uint64) indexes;
        mapping(uint64 => bytes32) ids;
    }

    struct List {
        uint256 header;
        mapping(uint256 => uint256) entries;
    }

    function identifiers() private pure returns (Identifiers storage s) {
        bytes32 slot = SLOT;
        assembly ("memory-safe") { s.slot := slot }
    }

    /// @dev The caller must deduplicate dependencies before adding a root to this set.
    function add(List storage list, bytes32 actionId) internal returns (uint8 position) {
        Identifiers storage s = identifiers();
        uint64 index = s.indexes[actionId];
        if (index == 0) {
            index = ++s.nonce;
            s.indexes[actionId] = index;
            s.ids[index] = actionId;
        }
        uint256 header = list.header;
        if (header == 0) {
            list.header = SINGLE | index;
            return 0;
        }
        if (header & SINGLE != 0) {
            uint256 oldPosition = (header >> 64) & 255;
            _write(list, oldPosition, header & INDEX_MASK);
            header = 1 << oldPosition;
        }
        uint256 free = ~header & (SINGLE - 1);
        // Every dependency must be registered; a full set rejects the entire proposal atomically.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (free == 0) revert TooManyPendingActions();
        uint256 bit = free & (~free + 1);
        position = SafeCast.toUint8(Math.log2(bit));
        _write(list, position, index);
        list.header = header | bit;
    }

    function remove(List storage list, uint8 position, bytes32 actionId) internal returns (bool) {
        uint256 index = identifiers().indexes[actionId];
        uint256 header = list.header;
        if (index == 0 || header == 0) return false;
        if (header & SINGLE != 0) {
            if (header & INDEX_MASK != index || (header >> 64) & 255 != position) return false;
            list.header = 0;
            return true;
        }
        uint256 bit = 1 << position;
        if (header & bit == 0 || _entry(list, position) != index) return false;
        header ^= bit;
        if (header != 0 && header & (header - 1) == 0) {
            uint256 remaining = Math.log2(header);
            header = SINGLE | (remaining << 64) | _entry(list, remaining);
        }
        // Inactive packed entries are harmless. Retaining them avoids extra writes and
        // preserves stable positions for every other pending root.
        list.header = header;
        return true;
    }

    function count(List storage list) internal view returns (uint256 n) {
        uint256 bits = list.header;
        if (bits & SINGLE != 0) return 1;
        while (bits != 0) {
            bits &= bits - 1;
            ++n;
        }
    }

    function contains(List storage list, bytes32 actionId) internal view returns (bool) {
        uint256 index = identifiers().indexes[actionId];
        uint256 bits = list.header;
        if (index == 0) return false;
        if (bits & SINGLE != 0) return bits & INDEX_MASK == index;
        while (bits != 0) {
            uint256 bit = bits & (~bits + 1);
            if (_entry(list, Math.log2(bit)) == index) return true;
            bits ^= bit;
        }
        return false;
    }

    function firstExcept(List storage list, bytes32 excluded) internal view returns (bytes32) {
        Identifiers storage s = identifiers();
        uint256 bits = list.header;
        if (bits & SINGLE != 0) {
            bytes32 id = s.ids[SafeCast.toUint64(bits & INDEX_MASK)];
            return id == excluded ? bytes32(0) : id;
        }
        if (bits == 0) return bytes32(0);
        uint256 bit = bits & (~bits + 1);
        bytes32 first = s.ids[SafeCast.toUint64(_entry(list, Math.log2(bit)))];
        if (first != excluded) return first;
        bits ^= bit;
        if (bits == 0) return bytes32(0);
        bit = bits & (~bits + 1);
        return s.ids[SafeCast.toUint64(_entry(list, Math.log2(bit)))];
    }

    function _entry(List storage list, uint256 position) private view returns (uint256) {
        return (list.entries[position >> 2] >> ((position & 3) * 64)) & INDEX_MASK;
    }

    function _write(List storage list, uint256 position, uint256 index) private {
        uint256 shift = (position & 3) * 64;
        uint256 word = list.entries[position >> 2];
        list.entries[position >> 2] = (word & ~(INDEX_MASK << shift)) | (index << shift);
    }
}
