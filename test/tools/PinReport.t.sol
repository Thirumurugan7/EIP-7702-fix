// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.36;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

/// @notice Prints the runtime codehash of every contract pinned in src/ProtocolCodehashes.sol for the
///         active Foundry profile, as `PIN <CONSTANT_PREFIX> <hash>` lines consumed by update-pins.py.
/// @dev The engine has constructor-set immutables, so it and its two CREATE children are measured from a
///      real deployment. The others have none and are measured from their build artifacts.
contract PinReport is Test {
    function _pin(string memory name, bytes32 h) private pure {
        console2.log(string.concat("PIN ", name, " ", vm.toString(h)));
    }

    function _artifact(string memory name, string memory artifact) private view {
        _pin(name, keccak256(vm.getDeployedCode(artifact)));
    }

    function test_report() public {
        _artifact("CANONICAL_PREDICTOR_CODEHASH", "OKFactoryPredictor.sol:OKFactoryPredictor");
        _artifact("CANONICAL_STAGE1_MODULE_CODEHASH", "OKFactoryStage1Module.sol:OKFactoryStage1Module");
        _artifact("CANONICAL_STAGE2_MODULE_CODEHASH", "OKFactoryStage2Module.sol:OKFactoryStage2Module");
        _artifact("CANONICAL_AUTH_ACCOUNT_MODULE_CODEHASH", "OKFactoryAuthAccountModule.sol:OKFactoryAuthAccountModule");
        _artifact("INTERACT_OPS_MODULE_CODEHASH", "InteractOpsModule.sol:InteractOpsModule");
        _artifact("REGISTRY_PAUSE_MODULE_CODEHASH", "RegistryPauseModule.sol:RegistryPauseModule");
        _artifact(
            "REGISTRY_TIMELOCK_EXECUTION_MODULE_CODEHASH",
            "RegistryTimelockExecutionModule.sol:RegistryTimelockExecutionModule"
        );
        _artifact("TIMELOCK_POLICY_RUNNER_CODEHASH", "TimelockPolicyProgramRunner.sol:TimelockPolicyProgramRunner");

        address engine = deployCode("MiniScriptEngine.sol:MiniScriptEngine");
        _pin("MINISCRIPT_ENGINE_CODEHASH", engine.codehash);
        _pin("MINISCRIPT_ANALYZER_CODEHASH", vm.computeCreateAddress(engine, 1).codehash);
        _pin("MINISCRIPT_ABI_ENCODER_CODEHASH", vm.computeCreateAddress(engine, 2).codehash);
    }
}
