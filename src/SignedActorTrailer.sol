// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @notice Encoding shared by Interact and OKModule for a dynamically sized
///         execution-actor signature appended to calldata.
library SignedActorTrailer {
    bytes32 internal constant MAGIC = keccak256("ChainwallSignedActorTrailerV2");
    uint256 internal constant FOOTER_LENGTH = 56;
    uint256 internal constant MAX_SIGNATURE_LENGTH = 4096;

    error ActorZero();
    error SignatureEmpty();
    error SignatureTooLong(uint256 length);
    error MalformedTrailer();

    function append(bytes memory callData, address actor, bytes memory signature) internal pure returns (bytes memory) {
        // Each appended trailer must bind a nonzero actor and bounded signature; an invalid trailer cannot be
        // skipped.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (actor == address(0)) revert ActorZero();
        uint256 signatureLength = signature.length;
        // Each appended trailer must bind a nonzero actor and bounded signature; an invalid trailer cannot be
        // skipped.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (signatureLength == 0) revert SignatureEmpty();
        // Each appended trailer must bind a nonzero actor and bounded signature; an invalid trailer cannot be
        // skipped.
        // forge-lint: disable-next-line(require-revert-in-loop)
        if (signatureLength > MAX_SIGNATURE_LENGTH) revert SignatureTooLong(signatureLength);
        // The fixed-width footer records the signature boundary for decoding.
        return bytes.concat(callData, signature, abi.encodePacked(actor, SafeCast.toUint32(signatureLength), MAGIC));
    }

    /// @return present False only when the versioned magic is absent. A present
    ///         but malformed trailer reverts instead of silently changing actor semantics.
    /// @dev Return a validated slice so actor-only callers never copy a signature.
    function decode(bytes calldata callData)
        internal
        pure
        returns (bool present, address actor, bytes calldata signature)
    {
        uint256 length = callData.length;
        if (length < FOOTER_LENGTH) return (false, address(0), callData[0:0]);

        bytes32 magic;
        uint32 signatureLength;
        assembly ("memory-safe") {
            let end := add(callData.offset, length)
            magic := calldataload(sub(end, 32))
            signatureLength := shr(224, calldataload(sub(end, 36)))
            actor := shr(96, calldataload(sub(end, 56)))
        }
        if (magic != MAGIC) return (false, address(0), callData[0:0]);
        if (actor == address(0)) revert ActorZero();
        if (signatureLength == 0) revert SignatureEmpty();
        if (signatureLength > MAX_SIGNATURE_LENGTH) revert SignatureTooLong(signatureLength);
        if (uint256(signatureLength) + FOOTER_LENGTH + 4 > length) revert MalformedTrailer();

        uint256 end = length - FOOTER_LENGTH;
        return (true, actor, callData[end - signatureLength:end]);
    }
}
