// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @title ProductRatioMath
/// @notice Exact floor of a product ratio whose factors are uint256 values.
/// @dev Products are represented as little-endian base-2^256 limbs. This makes
///      intermediate overflow impossible within the bounded factor set. The
///      quotient is restricted to one uint256 because that is MiniScript's
///      numeric value type.
library ProductRatioMath {
    uint256 internal constant MAX_FACTORS = 16;

    /// @notice Result class for exact-ceiling product-ratio evaluation.
    enum RatioStatus {
        /// @notice Evaluation succeeded and `result` is exact.
        Ok,
        /// @notice Input shape or a denominator was invalid.
        Invalid,
        /// @notice The exact result exceeded uint256.
        Overflow
    }

    /// @notice Compute floor(product(numerators) / product(denominators)).
    /// @param factors Factors in source evaluation order.
    /// @param denominatorMask Bit i is one when factors[i] is a denominator.
    /// @return valid False for malformed input, a zero denominator, or a quotient above uint256.
    /// @return result The exact floor when valid is true.
    function tryFloor(uint256[] calldata factors, uint256 denominatorMask)
        internal
        pure
        returns (bool valid, uint256 result)
    {
        uint256 factorCount = factors.length;
        if (factorCount < 2 || factorCount > MAX_FACTORS) return (false, 0);

        uint256 factorMask = (uint256(1) << factorCount) - 1;
        if (denominatorMask == 0 || denominatorMask == factorMask || denominatorMask != (denominatorMask & factorMask))
        {
            return (false, 0);
        }

        uint256 numeratorCount = 0;
        uint256 denominatorCount = 0;
        uint256 numerator0 = 0;
        uint256 numerator1 = 0;
        uint256 denominator0 = 0;
        bool numeratorIsZero = false;

        for (uint256 i; i < factorCount; ++i) {
            uint256 factor = factors[i];
            if ((denominatorMask & (uint256(1) << i)) != 0) {
                if (factor == 0) return (false, 0);
                if (denominatorCount == 0) denominator0 = factor;
                unchecked {
                    ++denominatorCount;
                }
            } else {
                if (numeratorCount == 0) numerator0 = factor;
                if (numeratorCount == 1) numerator1 = factor;
                if (factor == 0) numeratorIsZero = true;
                unchecked {
                    ++numeratorCount;
                }
            }
        }

        if (numeratorIsZero) return (true, 0);

        // Keep the overwhelmingly common cases on the audited OpenZeppelin
        // paths. The general limb path below has identical floor semantics.
        if (numeratorCount == 1 && denominatorCount == 1) {
            return (true, numerator0 / denominator0);
        }
        if (numeratorCount == 2 && denominatorCount == 1) {
            (uint256 high,) = Math.mul512(numerator0, numerator1);
            if (denominator0 <= high) return (false, 0);
            return (true, Math.mulDiv(numerator0, numerator1, denominator0));
        }

        uint256[] memory numerator = new uint256[](factorCount + 1);
        uint256[] memory denominator = new uint256[](factorCount + 1);
        numerator[0] = 1;
        denominator[0] = 1;
        uint256 numeratorLength = 1;
        uint256 denominatorLength = 1;

        for (uint256 i; i < factorCount; ++i) {
            uint256 factor = factors[i];
            if ((denominatorMask & (uint256(1) << i)) != 0) {
                denominatorLength = _multiplyInPlace(denominator, denominatorLength, factor);
            } else {
                numeratorLength = _multiplyInPlace(numerator, numeratorLength, factor);
            }
        }

        if (numeratorLength == 1 && denominatorLength == 1) {
            return (true, numerator[0] / denominator[0]);
        }
        if (_compare(numerator, numeratorLength, denominator, denominatorLength) < 0) {
            return (true, 0);
        }

        // A uint256 quotient exists exactly when numerator < denominator * 2^256.
        if (_compareShiftedDenominator(numerator, numeratorLength, denominator, denominatorLength) >= 0) {
            return (false, 0);
        }

        // N >= D > 0 here. If their bit lengths differ by k, N / D < 2^(k+1),
        // so higher candidate bits are necessarily zero. Retain the exact product
        // comparisons below and the 256-bit overflow check above. Build the
        // result from most-significant to least-significant bit, still bounded
        // by 256 * MAX_FACTORS work rather than variable-precision division.
        uint256 quotientBits = 1 + (numeratorLength - denominatorLength) * 256
            + Math.log2(numerator[numeratorLength - 1]) - Math.log2(denominator[denominatorLength - 1]);
        if (quotientBits > 256) quotientBits = 256;
        uint256[] memory candidateProduct = new uint256[](factorCount + 1);
        for (uint256 bit = quotientBits; bit != 0;) {
            unchecked {
                --bit;
            }
            uint256 candidate = result | (uint256(1) << bit);
            uint256 candidateLength = _multiplyInto(denominator, denominatorLength, candidate, candidateProduct);
            if (_compare(candidateProduct, candidateLength, numerator, numeratorLength) <= 0) {
                result = candidate;
            }
        }
        return (true, result);
    }

    /// @notice Compute ceil(product(numerators) / product(denominators)).
    /// @dev `Invalid` distinguishes malformed input and a zero denominator from
    ///      `Overflow`, while `Ok, 0` remains an unambiguous valid zero result.
    /// @param factors Factors in source evaluation order.
    /// @param denominatorMask Bit i is one when `factors[i]` is a denominator.
    /// @return status Ok, Invalid, or Overflow.
    /// @return result Exact ceiling when status is Ok; otherwise zero.
    function tryCeil(uint256[] memory factors, uint256 denominatorMask)
        internal
        pure
        returns (RatioStatus status, uint256 result)
    {
        uint256 factorCount = factors.length;
        if (factorCount < 2 || factorCount > MAX_FACTORS) return (RatioStatus.Invalid, 0);

        uint256 factorMask = (uint256(1) << factorCount) - 1;
        if (denominatorMask == 0 || denominatorMask == factorMask || denominatorMask != (denominatorMask & factorMask))
        {
            return (RatioStatus.Invalid, 0);
        }

        uint256 numeratorCount = 0;
        uint256 denominatorCount = 0;
        uint256 numerator0 = 0;
        uint256 numerator1 = 0;
        uint256 denominator0 = 0;
        bool numeratorIsZero = false;
        for (uint256 i; i < factorCount; ++i) {
            uint256 factor = factors[i];
            if ((denominatorMask & (uint256(1) << i)) != 0) {
                if (factor == 0) return (RatioStatus.Invalid, 0);
                if (denominatorCount == 0) denominator0 = factor;
                unchecked {
                    ++denominatorCount;
                }
            } else {
                if (numeratorCount == 0) numerator0 = factor;
                if (numeratorCount == 1) numerator1 = factor;
                if (factor == 0) numeratorIsZero = true;
                unchecked {
                    ++numeratorCount;
                }
            }
        }
        if (numeratorIsZero) return (RatioStatus.Ok, 0);

        if (numeratorCount == 1 && denominatorCount == 1) {
            result = numerator0 / denominator0;
            if (numerator0 % denominator0 == 0) return (RatioStatus.Ok, result);
            if (result == type(uint256).max) return (RatioStatus.Overflow, 0);
            return (RatioStatus.Ok, result + 1);
        }
        if (numeratorCount == 2 && denominatorCount == 1) {
            (uint256 high,) = Math.mul512(numerator0, numerator1);
            if (denominator0 <= high) return (RatioStatus.Overflow, 0);
            result = Math.mulDiv(numerator0, numerator1, denominator0);
            if (mulmod(numerator0, numerator1, denominator0) == 0) return (RatioStatus.Ok, result);
            if (result == type(uint256).max) return (RatioStatus.Overflow, 0);
            return (RatioStatus.Ok, result + 1);
        }

        uint256[] memory numerator = new uint256[](factorCount + 1);
        uint256[] memory denominator = new uint256[](factorCount + 1);
        numerator[0] = 1;
        denominator[0] = 1;
        uint256 numeratorLength = 1;
        uint256 denominatorLength = 1;
        for (uint256 i; i < factorCount; ++i) {
            uint256 factor = factors[i];
            if ((denominatorMask & (uint256(1) << i)) != 0) {
                denominatorLength = _multiplyInPlace(denominator, denominatorLength, factor);
            } else {
                numeratorLength = _multiplyInPlace(numerator, numeratorLength, factor);
            }
        }

        int256 ratioComparison = _compare(numerator, numeratorLength, denominator, denominatorLength);
        if (ratioComparison < 0) return (RatioStatus.Ok, 1);
        if (_compareShiftedDenominator(numerator, numeratorLength, denominator, denominatorLength) >= 0) {
            return (RatioStatus.Overflow, 0);
        }

        uint256[] memory candidateProduct = new uint256[](factorCount + 1);
        for (uint256 bit = 256; bit != 0;) {
            unchecked {
                --bit;
            }
            uint256 candidate = result | (uint256(1) << bit);
            uint256 candidateLength = _multiplyInto(denominator, denominatorLength, candidate, candidateProduct);
            if (_compare(candidateProduct, candidateLength, numerator, numeratorLength) <= 0) result = candidate;
        }

        uint256 floorLength = _multiplyInto(denominator, denominatorLength, result, candidateProduct);
        if (_compare(candidateProduct, floorLength, numerator, numeratorLength) == 0) {
            return (RatioStatus.Ok, result);
        }
        if (result == type(uint256).max) return (RatioStatus.Overflow, 0);
        return (RatioStatus.Ok, result + 1);
    }

    function _multiplyInPlace(uint256[] memory limbs, uint256 length, uint256 factor) private pure returns (uint256) {
        if (factor == 1) return length;
        uint256 carry = 0;
        for (uint256 i; i < length; ++i) {
            (uint256 high, uint256 low) = Math.mul512(limbs[i], factor);
            unchecked {
                uint256 sum = low + carry;
                // high <= factor - 1, so adding this carry bit cannot overflow.
                if (sum < low) ++high;
                limbs[i] = sum;
                carry = high;
            }
        }
        if (carry == 0) return length;
        limbs[length] = carry;
        return length + 1;
    }

    function _multiplyInto(uint256[] memory limbs, uint256 length, uint256 factor, uint256[] memory out)
        private
        pure
        returns (uint256)
    {
        uint256 carry = 0;
        for (uint256 i; i < length; ++i) {
            (uint256 high, uint256 low) = Math.mul512(limbs[i], factor);
            unchecked {
                uint256 sum = low + carry;
                if (sum < low) ++high;
                out[i] = sum;
                carry = high;
            }
        }
        out[length] = carry;
        return carry == 0 ? length : length + 1;
    }

    function _compare(uint256[] memory a, uint256 aLength, uint256[] memory b, uint256 bLength)
        private
        pure
        returns (int256)
    {
        if (aLength < bLength) return -1;
        if (aLength > bLength) return 1;
        for (uint256 i = aLength; i != 0;) {
            unchecked {
                --i;
            }
            if (a[i] < b[i]) return -1;
            if (a[i] > b[i]) return 1;
        }
        return 0;
    }

    function _compareShiftedDenominator(
        uint256[] memory numerator,
        uint256 numeratorLength,
        uint256[] memory denominator,
        uint256 denominatorLength
    ) private pure returns (int256) {
        uint256 shiftedLength = denominatorLength + 1;
        if (numeratorLength < shiftedLength) return -1;
        if (numeratorLength > shiftedLength) return 1;

        for (uint256 i = shiftedLength; i != 0;) {
            unchecked {
                --i;
            }
            uint256 denominatorWord = i == 0 ? 0 : denominator[i - 1];
            if (numerator[i] < denominatorWord) return -1;
            if (numerator[i] > denominatorWord) return 1;
        }
        return 0;
    }
}
