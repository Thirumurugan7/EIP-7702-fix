// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @notice MiniScript host configuration needed by Safe-native execution.
interface IMiniScriptExecutionHost {
    function engine() external view returns (address);
    function miniScriptHostConfig() external view returns (address engine_, address registry_);
}
