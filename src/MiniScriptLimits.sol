// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @notice Shared structural limits used by MiniScript analysis and execution.
library MiniScriptLimits {
    /// @notice Maximum number of nested CALLI and STATICLINK frames below a root script.
    uint256 internal constant MAX_RECURSION_DEPTH = 16;

    /// @notice Maximum bytes in one inline recursive ABI descriptor.
    uint256 internal constant MAX_ABI_DESCRIPTOR_BYTES = 1024;
    /// @notice Maximum nodes in one recursive ABI descriptor tree.
    uint256 internal constant MAX_ABI_DESCRIPTOR_NODES = 256;
    /// @notice Maximum nested tuple and array depth in a recursive ABI descriptor.
    uint256 internal constant MAX_ABI_DESCRIPTOR_DEPTH = 16;
    /// @notice Maximum direct children in one ABI tuple.
    uint256 internal constant MAX_ABI_TUPLE_CHILDREN = 64;
    /// @notice Maximum elements in one fixed or runtime-sized ABI array.
    uint256 internal constant MAX_ABI_ARRAY_ELEMENTS = 256;
    /// @notice Maximum byte length accepted by one dynamic bytes value.
    uint256 internal constant MAX_ABI_DYNAMIC_BYTES = 8192;
    /// @notice Maximum authenticated argument words consumed by one recursive ABI call.
    uint256 internal constant MAX_ABI_TAPE_WORDS = 384;
    /// @notice Maximum selector-inclusive calldata emitted by one recursive ABI call.
    uint256 internal constant MAX_ABI_CALLDATA_BYTES = 16_384;
    /// @notice Maximum expanded descriptor nodes visited in one validation or encoding pass.
    uint256 internal constant MAX_ABI_EXPANDED_NODES = 4096;
    /// @notice Maximum selected return words pushed by one READWORDS instruction.
    uint256 internal constant MAX_READ_WORDS = 8;
}
