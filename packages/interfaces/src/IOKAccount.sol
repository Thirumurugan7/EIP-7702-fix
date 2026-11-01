// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @notice Minimal account interface required for native account-mode execution.
interface IOKAccount {
    /// @notice Return the MiniScript engine used for vault execution.
    function chainwallEngine() external view returns (address);

    /// @notice Execute one Registry interaction in the account's vault context.
    /// @param interactionId Public interaction identifier.
    /// @param args Initial interaction arguments.
    /// @param maxSteps Shared MiniScript execution-tree step cap.
    /// @param maxNativeValue Maximum native value the interaction may spend.
    /// @param actor Authenticated policy actor exposed through subject context.
    /// @param policyId Policy selected for this execution.
    /// @return stackTop Final MiniScript result word.
    function executeInteraction(
        bytes32 interactionId,
        uint256[] calldata args,
        uint256 maxSteps,
        uint256 maxNativeValue,
        address actor,
        bytes32 policyId
    ) external returns (uint256 stackTop);
}
