// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @notice Policy-program host and dependency-analysis interface used by Interact.
interface IMiniScript {
    /// @notice Immutable root context exposed to policy and linked scripts through `SUBJECT`.
    struct SubjectContext {
        /// @notice Subject envelope version. Must be 2.
        uint256 version;
        /// @notice Base interaction whose execution is being authorized.
        bytes32 interactionId;
        /// @notice Native value authorized for the root interaction.
        uint256 nativeValue;
        /// @notice Actor whose policy authorization permits the operation.
        address actor;
        /// @notice Safe or account vault on whose behalf the interaction executes.
        address vault;
        /// @notice Nonzero policy selected for the root interaction.
        bytes32 policyId;
        /// @notice Original arguments supplied to the root interaction.
        uint256[] interactionArgs;
    }

    /// @notice Execute raw bytecode from the configured authorized caller.
    /// @dev Tenant factories do not deploy an owner-authorized host for this
    ///      diagnostic surface. Production interactions use vault-native execution.
    function run(bytes calldata script, uint256[] calldata args, uint256 maxSteps)
        external
        payable
        returns (uint256 stackTop);

    /// @notice Execute a zero-value policy program with immutable interaction context.
    /// @param script Byte-encoded MiniScript program.
    /// @param args Initial frame arguments.
    /// @param maxSteps Maximum opcodes across the execution tree.
    /// @param subject Authenticated root interaction, actor, vault, value, and arguments.
    /// @return stackTop Final word returned by the root frame.
    function runPolicyProgram(
        bytes calldata script,
        uint256[] calldata args,
        uint256 maxSteps,
        SubjectContext calldata subject
    ) external returns (uint256 stackTop);

    /// @notice Hash the public interaction and every executable catalog dependency it can reach.
    /// @param interactionId Public interaction whose dependency graph is analyzed.
    /// @return bindingHash Zero when the interaction has no public script, including private commitments.
    function getExecutionDependencyHash(bytes32 interactionId) external view returns (bytes32 bindingHash);

    /// @notice Hash dependencies reachable from an inline policy program.
    /// @param program Policy MiniScript bytecode.
    /// @param subjectInteractionId Interaction whose linked namespace is visible to the program.
    /// @return dependencyHash Exact dependency binding, or zero when analysis is incomplete.
    /// @return complete True when every reachable dependency was public and structurally analyzable.
    function getProgramDependencyHash(bytes calldata program, bytes32 subjectInteractionId)
        external
        view
        returns (bytes32 dependencyHash, bool complete);
}
