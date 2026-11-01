// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {OKFactoryAddressDerivation} from "./OKFactoryAddressDerivation.sol";
import {OKFactoryConfig} from "./OKFactoryConfig.sol";

/// @title OKFactoryPredictor
/// @notice Canonical on-chain helper that mirrors the factory address derivation.
/// @dev Full address preview is now handled by {OKFactoryAddressDerivation} for scripts, tests, and SDK code.
///      OKFactory trusts this helper only when the configured predictor bytecode exactly matches this runtime.
///      That preserves immutable wiring while rejecting arbitrary custom predictors on-chain.
///      The usual off-chain flow is:
///      1. Predict all stage-2 addresses from the same `OKFactoryConfig`.
///      2. Run stage 1.
///      3. Compare against the bindings emitted by the factory during bootstrap.
contract OKFactoryPredictor {
    /// @notice Derive stage-2 bindings for an index-independent deterministic tenant deployment.
    /// @param deploymentKey Domain-separated key already committed during stage-1 bootstrap.
    function deriveDeterministicStageBindings(
        OKFactoryConfig config,
        address factory,
        address registryAddr,
        bytes32 deploymentKey,
        uint8 flags
    )
        external
        view
        returns (
            address miniScript,
            address interact,
            address safeFactory,
            address accountFactory,
            bytes32 stage2Commitment
        )
    {
        OKFactoryAddressDerivation.Stage2Addresses memory addrs =
            OKFactoryAddressDerivation.predictStage2AddressesForDeploymentKey(
                config, factory, registryAddr, deploymentKey, flags
            );
        miniScript = addrs.miniScript;
        interact = addrs.interact;
        safeFactory = addrs.safeFactory;
        accountFactory = addrs.accountFactory;
        stage2Commitment = OKFactoryAddressDerivation.stage2Commitment(addrs);
    }
}
