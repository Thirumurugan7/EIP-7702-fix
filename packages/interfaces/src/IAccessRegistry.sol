// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @title IAccessRegistry
/// @notice Minimal registry surface required by Chainwall's access-control policy.
/// @dev The execution contracts intentionally depend on this small view interface so they can work with the
///      diamond registry without importing every facet.
interface IAccessRegistry {
    /// @notice Return whether `user` is allowlisted as a human actor.
    function isUser(address user) external view returns (bool);
    /// @notice Return whether `safe` is an allowlisted Safe vault.
    function isSafeAllowed(address safe) external view returns (bool);
    /// @notice Return whether `account` is an allowlisted account vault.
    function isAccountAllowed(address account) external view returns (bool);
    /// @notice Return whether a policy id exists.
    function policyExists(bytes32 policyId) external view returns (bool);
    /// @notice Return the group hashes and thresholds that define a policy.
    function getPolicyCriteria(bytes32 policyId) external view returns (bytes32[] memory, uint256[] memory);
    /// @notice Return the optional policy program attached to `policyId`.
    function getPolicyProgram(bytes32 policyId)
        external
        view
        returns (bytes memory program, uint32 maxSteps, bytes32 programHash, uint64 version);
    /// @notice Return whether `user` is currently a member of `groupHash`.
    function isGroupMemberByHash(bytes32 groupHash, address user) external view returns (bool);
    /// @notice Return whether `actor` currently holds `capability`.
    function hasCapability(bytes32 capability, address actor) external view returns (bool);
}
