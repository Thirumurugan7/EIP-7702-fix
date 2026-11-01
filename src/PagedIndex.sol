// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @title PagedIndex
/// @notice Indexed set of bytes32 values with stable ids and pagination helpers.
/// @dev Ids are assigned monotonically and never reused. Deletions mark ids as
///      inactive while leaving the stored value intact.
library PagedIndex {
    error NoSuchId();
    error RangeOutOfBounds();
    error DuplicateValue();
    error EpochOverflow();

    struct Index {
        // Lower 128 bits store nextId, upper 128 bits store liveCount.
        uint256 counters;
        uint64 currentEpoch;
        mapping(uint256 => bytes32) values; // id => payload
        mapping(uint256 => uint256) alive; // page => 256-bit membership bitmap
        mapping(bytes32 => uint256) positions; // value => id+1 when alive
        mapping(uint64 => uint128[]) epochPages; // pages touched within the epoch
        mapping(uint256 => uint256) journalBits; // packed key => bitmap
    }

    // ===== Mutations =====

    /// @notice Insert a new value. Returns the assigned id.
    /// @dev Assigned ids are monotonically increasing and never reused.
    function insert(Index storage self, bytes32 value_) internal returns (uint256 id) {
        if (self.positions[value_] != 0) {
            // Duplicate or dead entries must abort the enclosing mutation to preserve index membership and
            // counters.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert DuplicateValue();
        }

        uint256 counters = self.counters;
        (uint128 nextId128, uint128 liveCount128) = _decodeCounters(counters);
        id = uint256(nextId128);
        unchecked {
            nextId128 += 1;
            liveCount128 += 1;
        }
        self.counters = _encodeCounters(nextId128, liveCount128);

        self.values[id] = value_;

        (uint128 pageIndex, uint256 bit) = _pageAndBit(id);
        uint256 oldAlive = self.alive[pageIndex];
        uint256 newAlive = oldAlive | bit;
        if (newAlive != oldAlive) {
            self.alive[pageIndex] = newAlive; // SSTORE
        }

        self.positions[value_] = id + 1;
    }

    /// @notice Update an existing id and mark it in the current epoch journal.
    /// @dev Passing the existing value is an intentional semantic touch for an
    ///      external record identified by this stable index entry.
    function update(Index storage self, uint256 id, bytes32 newValue) internal {
        uint256 counters = self.counters;
        // counters encodes nextId in the lower 128 bits; values never exceed that range
        // forge-lint: disable-next-line(unsafe-typecast)
        uint128 nextId128 = uint128(counters);
        if (id >= uint256(nextId128)) {
            // Duplicate or dead entries must abort the enclosing mutation to preserve index membership and
            // counters.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert NoSuchId();
        }

        (uint128 pageIndex, uint256 bit) = _pageAndBit(id);
        if ((self.alive[pageIndex] & bit) == 0) {
            // Duplicate or dead entries must abort the enclosing mutation to preserve index membership and
            // counters.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert NoSuchId();
        }

        bytes32 oldValue = self.values[id];
        if (oldValue != newValue) {
            uint256 pos = self.positions[newValue];
            if (pos != 0 && pos - 1 != id) {
                // Duplicate or dead entries must abort the enclosing mutation to preserve index membership and
                // counters.
                // forge-lint: disable-next-line(require-revert-in-loop)
                revert DuplicateValue();
            }
            self.values[id] = newValue;
            self.positions[oldValue] = 0;
            self.positions[newValue] = id + 1;
        }

        _markUpdateBit(self, pageIndex, bit);
    }

    /// @notice Delete an existing id. Value remains in storage slot.
    function remove(Index storage self, uint256 id) internal {
        uint256 counters = self.counters;
        (uint128 nextId128, uint128 liveCount128) = _decodeCounters(counters);
        if (id >= uint256(nextId128)) {
            // Duplicate or dead entries must abort the enclosing mutation to preserve index membership and
            // counters.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert NoSuchId();
        }

        (uint128 pageIndex, uint256 bit) = _pageAndBit(id);

        uint256 oldAlive = self.alive[pageIndex];
        if ((oldAlive & bit) == 0) {
            // Duplicate or dead entries must abort the enclosing mutation to preserve index membership and
            // counters.
            // forge-lint: disable-next-line(require-revert-in-loop)
            revert NoSuchId();
        }

        // Clear membership
        uint256 newAlive = oldAlive & ~bit;
        if (newAlive != oldAlive) {
            self.alive[pageIndex] = newAlive;
        }

        bytes32 value_ = self.values[id];
        self.positions[value_] = 0;

        unchecked {
            liveCount128 -= 1;
        }
        self.counters = _encodeCounters(nextId128, liveCount128);

        // Mark delete in journal (and clear any update bit this epoch)
        _markDeleteBit(self, pageIndex, bit);
    }

    /// @notice Remove an existing value when the caller only knows the value, not the id.
    function removeValue(Index storage self, bytes32 value_) internal returns (bool removed) {
        uint256 pos = self.positions[value_];
        if (pos == 0) {
            return false;
        }
        uint256 id = pos - 1;
        remove(self, id);
        return true;
    }

    /// @notice Seal the current epoch and start a new one.
    /// @dev New updates/deletes will be recorded under the incremented epoch.
    function rollEpoch(Index storage self) internal {
        uint64 currentEpoch_ = self.currentEpoch;
        if (currentEpoch_ == type(uint64).max) revert EpochOverflow();
        self.currentEpoch = currentEpoch_ + 1;
    }

    // ===== Set-style helpers =====

    function contains(Index storage self, bytes32 value_) internal view returns (bool) {
        uint256 pos = self.positions[value_];
        if (pos == 0) return false;
        uint256 id = pos - 1;
        (uint128 pageIndex, uint256 bit) = _pageAndBit(id);
        return (self.alive[pageIndex] & bit) != 0;
    }

    function idOf(Index storage self, bytes32 value_) internal view returns (uint256 id, bool exists) {
        uint256 pos = self.positions[value_];
        if (pos == 0) return (0, false);
        id = pos - 1;
        (uint128 pageIndex, uint256 bit) = _pageAndBit(id);
        exists = (self.alive[pageIndex] & bit) != 0;
    }

    /// @notice Returns the next id to be assigned (monotonic).
    function nextId(Index storage self) internal view returns (uint256) {
        // Counters pack nextId in the low 128 bits and liveCount in the high 128 bits.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint256(uint128(self.counters));
    }

    /// @notice Returns the number of live values.
    function length(Index storage self) internal view returns (uint256) {
        // Counters pack nextId in the low 128 bits and liveCount in the high 128 bits.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint256(uint128(self.counters >> 128));
    }

    /// @notice Returns the nth live value (0-based).
    function valueAt(Index storage self, uint256 index) internal view returns (bytes32) {
        if (index >= length(self)) revert RangeOutOfBounds();
        uint256 id = _locateNthId(self, index);
        return self.values[id];
    }

    /// @notice Returns a page of live values starting at index `start`.
    function page(Index storage self, uint256 start, uint256 count) internal view returns (bytes32[] memory out) {
        uint256 live = length(self);
        if (start >= live) {
            return new bytes32[](0);
        }

        uint256 target = count;
        uint256 remaining = live - start;
        if (target > remaining) {
            target = remaining;
        }

        out = new bytes32[](target);
        if (target == 0) return out;

        uint256 skip = start;
        uint256 written = 0;
        uint256 totalPages = _pageCount(nextId(self));
        for (uint256 pageIdx = 0; pageIdx < totalPages && written < target; ++pageIdx) {
            uint256 bitmap = self.alive[pageIdx];
            if (bitmap == 0) continue;

            uint256 setBits = _popcount(bitmap);
            if (skip >= setBits) {
                skip -= setBits;
                continue;
            }

            uint256 baseId = pageIdx << 8;
            uint256 localSkip = skip;
            uint256 remainingMask = bitmap;
            while (remainingMask != 0 && written < target) {
                uint256 lsb = remainingMask & (~remainingMask + 1);
                uint256 bitIndex = _bitIndex(lsb);
                remainingMask ^= lsb;

                if (localSkip > 0) {
                    unchecked {
                        --localSkip;
                    }
                    continue;
                }

                out[written] = self.values[baseId + bitIndex];
                unchecked {
                    ++written;
                }
            }
            skip = 0;
        }
    }

    // ===== Views for clients =====

    /// @notice Return the alive bitmap for a page of 256 ids (id range: [page*256 .. page*256+255])
    function alivePage(Index storage self, uint256 pageIndex) internal view returns (uint256 bitmap) {
        bitmap = self.alive[pageIndex];
    }

    /// @notice Return value and membership in one go.
    function get(Index storage self, uint256 id) internal view returns (bytes32 value_, bool isAlive) {
        value_ = self.values[id];
        (uint128 pageIndex, uint256 bit) = _pageAndBit(id);
        isAlive = (self.alive[pageIndex] & bit) != 0;
    }

    /// @notice Batch fetch values (no membership check).
    function getValues(Index storage self, uint256[] calldata ids) internal view returns (bytes32[] memory out) {
        uint256 n = ids.length;
        out = new bytes32[](n);
        for (uint256 i = 0; i < n;) {
            out[i] = self.values[ids[i]];
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Sequential fetch helper returning values[start .. start+count-1].
    function getPage(Index storage self, uint256 start, uint256 count) internal view returns (bytes32[] memory out) {
        uint256 nextId_ = nextId(self);
        if (start > nextId_) {
            revert RangeOutOfBounds();
        }

        uint256 end;
        unchecked {
            end = start + count;
        }

        if (end > nextId_ || end < start) {
            revert RangeOutOfBounds();
        }

        out = new bytes32[](count);
        uint256 id = start;
        for (uint256 i = 0; i < count;) {
            out[i] = self.values[id];
            unchecked {
                ++id;
                ++i;
            }
        }
    }

    /// @notice Number of pages touched in a given epoch (to drive pagination).
    function epochPageCount(Index storage self, uint64 epoch) internal view returns (uint256) {
        return self.epochPages[epoch].length;
    }

    /// @notice Page index at position i in epoch's directory.
    function epochPageAt(Index storage self, uint64 epoch, uint256 i) internal view returns (uint128) {
        return self.epochPages[epoch][i];
    }

    /// @notice Return the two journal bitmaps for (epoch, page): updates and deletes.
    function journal(Index storage self, uint64 epoch, uint128 pageIndex)
        internal
        view
        returns (uint256 updates, uint256 deletes)
    {
        (uint256 kU, uint256 kD) = _journalKeys(epoch, pageIndex);
        updates = self.journalBits[kU];
        deletes = self.journalBits[kD];
    }

    // ===== Internal helpers =====

    function _encodeCounters(uint128 nextId_, uint128 liveCount_) private pure returns (uint256 packed) {
        packed = (uint256(liveCount_) << 128) | uint256(nextId_);
    }

    function _decodeCounters(uint256 packed) private pure returns (uint128 nextId_, uint128 liveCount_) {
        // counters encode nextId/liveCount in 128-bit lanes; both values stay within that bound
        // forge-lint: disable-next-line(unsafe-typecast)
        nextId_ = uint128(packed);
        // forge-lint: disable-next-line(unsafe-typecast)
        liveCount_ = uint128(packed >> 128);
    }

    function _pageAndBit(uint256 id) private pure returns (uint128 pageIndex, uint256 bit) {
        unchecked {
            // casting to uint128 is safe: 2^128 pages correspond to 2^136 ids (unreachable in practice)
            // forge-lint: disable-next-line(unsafe-typecast)
            pageIndex = uint128(id >> 8); // / 256
            bit = uint256(1) << (id & 255); // mod 256
        }
    }

    function _journalKeys(uint64 epoch, uint128 pageIndex)
        private
        pure
        returns (uint256 updatesKey, uint256 deletesKey)
    {
        uint256 base =
            (uint256(epoch) << 192) | (uint256(pageIndex) << 64);
        updatesKey = base;
        deletesKey = base | 1;
    }

    function _pageCount(uint256 nextId_) private pure returns (uint256) {
        if (nextId_ == 0) return 0;
        unchecked {
            return ((nextId_ - 1) >> 8) + 1;
        }
    }

    function _popcount(uint256 x) private pure returns (uint256 count) {
        while (x != 0) {
            x &= (x - 1);
            unchecked {
                ++count;
            }
        }
    }

    function _bitIndex(uint256 bitMask) private pure returns (uint256 idx) {
        unchecked {
            if (bitMask >= 1 << 128) {
                bitMask >>= 128;
                idx += 128;
            }
            if (bitMask >= 1 << 64) {
                bitMask >>= 64;
                idx += 64;
            }
            if (bitMask >= 1 << 32) {
                bitMask >>= 32;
                idx += 32;
            }
            if (bitMask >= 1 << 16) {
                bitMask >>= 16;
                idx += 16;
            }
            if (bitMask >= 1 << 8) {
                bitMask >>= 8;
                idx += 8;
            }
            if (bitMask >= 1 << 4) {
                bitMask >>= 4;
                idx += 4;
            }
            if (bitMask >= 1 << 2) {
                bitMask >>= 2;
                idx += 2;
            }
            if (bitMask >= 1 << 1) {
                idx += 1;
            }
        }
    }

    function _locateNthId(Index storage self, uint256 ordinal) private view returns (uint256 id) {
        uint256 totalPages = _pageCount(nextId(self));
        uint256 remaining = ordinal;
        for (uint256 pageIdx; pageIdx < totalPages; ++pageIdx) {
            uint256 bitmap = self.alive[pageIdx];
            if (bitmap == 0) continue;

            uint256 setBits = _popcount(bitmap);
            if (remaining >= setBits) {
                remaining -= setBits;
                continue;
            }

            uint256 mask = bitmap;
            uint256 baseId = pageIdx << 8;
            while (true) {
                uint256 lsb = mask & (~mask + 1);
                uint256 bitIndex = _bitIndex(lsb);
                if (remaining == 0) {
                    return baseId + bitIndex;
                }
                mask ^= lsb;
                unchecked {
                    --remaining;
                }
            }
        }
        revert RangeOutOfBounds();
    }

    function _markUpdateBit(Index storage self, uint128 pageIndex, uint256 bit) private {
        uint64 e = self.currentEpoch;

        (uint256 kU, uint256 kD) = _journalKeys(e, pageIndex);
        uint256 u = self.journalBits[kU];
        uint256 d = self.journalBits[kD];

        if ((u | d) == 0) {
            self.epochPages[e].push(pageIndex);
        }

        if ((u & bit) == 0) {
            self.journalBits[kU] = u | bit;
        }

        if ((d & bit) != 0) {
            self.journalBits[kD] = d & ~bit;
        }
    }

    function _markDeleteBit(Index storage self, uint128 pageIndex, uint256 bit) private {
        uint64 e = self.currentEpoch;

        (uint256 kU, uint256 kD) = _journalKeys(e, pageIndex);
        uint256 u = self.journalBits[kU];
        uint256 d = self.journalBits[kD];

        if ((u | d) == 0) {
            self.epochPages[e].push(pageIndex);
        }

        if ((d & bit) == 0) {
            self.journalBits[kD] = d | bit;
        }

        if ((u & bit) != 0) {
            self.journalBits[kU] = u & ~bit;
        }
    }
}

/**
 * @title PagedBitmapIndex
 * @notice Thin wrapper contract exposing the PagedIndex library for testing.
 */
contract PagedBitmapIndex {
    using PagedIndex for PagedIndex.Index;

    PagedIndex.Index private index;

    function nextId() external view returns (uint256) {
        return index.nextId();
    }

    function currentEpoch() external view returns (uint64) {
        return index.currentEpoch;
    }

    function liveCount() external view returns (uint256) {
        return index.length();
    }

    function insert(bytes32 value_) external returns (uint256 id) {
        return index.insert(value_);
    }

    function update(uint256 id, bytes32 newValue) external {
        index.update(id, newValue);
    }

    function remove(uint256 id) external {
        index.remove(id);
    }

    function rollEpoch() external {
        index.rollEpoch();
    }

    function alivePage(uint256 pageIndex) external view returns (uint256 bitmap) {
        return index.alivePage(pageIndex);
    }

    function contains(bytes32 value_) external view returns (bool) {
        return index.contains(value_);
    }

    function idOf(bytes32 value_) external view returns (uint256 id, bool exists) {
        return index.idOf(value_);
    }

    function get(uint256 id) external view returns (bytes32 value_, bool isAlive) {
        return index.get(id);
    }

    function getValues(uint256[] calldata ids) external view returns (bytes32[] memory out) {
        return index.getValues(ids);
    }

    function getPage(uint256 start, uint256 count) external view returns (bytes32[] memory out) {
        return index.getPage(start, count);
    }

    function removeValue(bytes32 value_) external returns (bool removed) {
        return index.removeValue(value_);
    }

    function valueAt(uint256 index_) external view returns (bytes32) {
        return index.valueAt(index_);
    }

    function page(uint256 start, uint256 count) external view returns (bytes32[] memory out) {
        return index.page(start, count);
    }

    function epochPageCount(uint64 epoch) external view returns (uint256) {
        return index.epochPageCount(epoch);
    }

    function epochPageAt(uint64 epoch, uint256 i) external view returns (uint128) {
        return index.epochPageAt(epoch, i);
    }

    function journal(uint64 epoch, uint128 pageIndex) external view returns (uint256 updates, uint256 deletes) {
        return index.journal(epoch, pageIndex);
    }
}
