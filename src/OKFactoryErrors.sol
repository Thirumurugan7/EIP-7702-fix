// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @title OKFactoryErrors
/// @notice Shared custom errors used by OKFactory and its fixed stage modules.
/// @dev The public OKFactory wrapper re-declares the user-facing deployment errors so selectors remain addressable as
///      `OKFactory.ErrorName.selector`, while the delegatecall modules use this library to avoid circular references.
library OKFactoryErrors {
    /// @notice Thrown when the factory config address is zero during deployment.
    error ConfigZero();
    /// @notice Thrown when a new instance is requested with a zero owner.
    error OwnerZero();
    /// @notice Thrown when stage 2 is requested for a registry that is not currently staged.
    error NotPending();
    /// @notice Thrown when stage-1 finalize is requested for a registry that has not been bootstrapped.
    error NotBootstrapped();
    /// @notice Thrown when unsupported deployment flags are provided.
    error UnsupportedFlags();
    /// @notice Thrown when the staged registry no longer authorizes the predicted system actors.
    error SystemActorsNotAuthorized();
    /// @notice Thrown when staged registry ownership no longer matches the expected protected bootstrap owner.
    /// @param expected Factory owner required until stage 2 completes tenant handoff.
    /// @param actual Current owner observed during a staged transition.
    error RegistryOwner(address expected, address actual);
    /// @notice Thrown when the derived stage-2 deployment bindings drift after stage 1.
    error StageDeploymentChanged();
    /// @notice Thrown when a stage module is called directly instead of through the factory.
    error DirectModuleCallUnsupported();
}
