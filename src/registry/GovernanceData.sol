// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @dev Immutable, non-executable data. The leading STOP prevents interpreting the data as code.
contract GovernanceData {
    constructor(bytes memory data) {
        require(data.length < 24_576, "GovernanceData:size");
        bytes memory runtime = bytes.concat(hex"00", data);
        assembly ("memory-safe") {
            return(add(runtime, 32), mload(runtime))
        }
    }
}

library GovernanceDataLib {
    function read(address pointer) internal view returns (bytes memory data) {
        data = new bytes(pointer.code.length - 1);
        assembly ("memory-safe") {
            extcodecopy(pointer, add(data, 32), 1, mload(data))
        }
    }
}
