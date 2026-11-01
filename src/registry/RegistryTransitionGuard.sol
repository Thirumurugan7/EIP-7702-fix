// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {ExecutionCatalogStorage} from "./RegistryShared.sol";
import {TimelockLib} from "./TimelockLib.sol";

/// @notice Monotonic revision postconditions shared by Registry code transitions.
library RegistryTransitionGuard {
    struct Snapshot {
        uint64 catalogVersion;
        uint64 runtimeVersion;
        uint64 actionSemanticsGeneration;
    }

    error CatalogVersionRolledBack(uint64 beforeVersion, uint64 afterVersion);
    error RuntimeVersionRolledBack(uint64 beforeVersion, uint64 afterVersion);
    error ActionSemanticsGenerationRolledBack(uint64 beforeGeneration, uint64 afterGeneration);
    error TransitionRevisionNotAdvanced();

    function snapshot() internal view returns (Snapshot memory beforeState) {
        beforeState.catalogVersion = ExecutionCatalogStorage.version();
        beforeState.runtimeVersion = ExecutionCatalogStorage.runtimeVersion();
        beforeState.actionSemanticsGeneration = TimelockLib.actionSemanticsGeneration();
    }

    /// @notice Reject migration code that lowers a monotonic authorization revision.
    function requireNotRolledBack(Snapshot memory beforeState) internal view {
        uint64 catalogVersion = ExecutionCatalogStorage.version();
        if (catalogVersion < beforeState.catalogVersion) {
            revert CatalogVersionRolledBack(beforeState.catalogVersion, catalogVersion);
        }
        uint64 runtimeVersion = ExecutionCatalogStorage.runtimeVersion();
        if (runtimeVersion < beforeState.runtimeVersion) {
            revert RuntimeVersionRolledBack(beforeState.runtimeVersion, runtimeVersion);
        }
        uint64 actionGeneration = TimelockLib.actionSemanticsGeneration();
        if (actionGeneration < beforeState.actionSemanticsGeneration) {
            revert ActionSemanticsGenerationRolledBack(beforeState.actionSemanticsGeneration, actionGeneration);
        }
    }

    /// @notice Validate migration output, invalidate old intents, and prove all revisions advanced.
    function advanceFrom(Snapshot memory beforeState) internal {
        requireNotRolledBack(beforeState);
        ExecutionCatalogStorage.bumpRuntime();
        TimelockLib.bumpActionSemanticsGeneration();
        if (
            ExecutionCatalogStorage.version() <= beforeState.catalogVersion
                || ExecutionCatalogStorage.runtimeVersion() <= beforeState.runtimeVersion
                || TimelockLib.actionSemanticsGeneration() <= beforeState.actionSemanticsGeneration
        ) revert TransitionRevisionNotAdvanced();
    }
}
