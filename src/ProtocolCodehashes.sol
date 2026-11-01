// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

/// @title ProtocolCodehashes
/// @notice Accepted runtime codehashes for canonical protocol-managed deployment components.
/// @dev Recompute and verify runtime code hashes under both the default and production profiles whenever
///      source, compiler settings, or metadata settings change. Update dependent release bindings together.
library ProtocolCodehashes {
    /// @dev Canonical OKFactoryPredictor codehash for the default Foundry profile.
    bytes32 internal constant CANONICAL_PREDICTOR_CODEHASH_DEFAULT =
        0x119f1ea7701047a378577b0f4b16b6902f0179ac16bff350b6c556a6fc13efa6;

    /// @dev Canonical OKFactoryPredictor codehash for the production Foundry profile.
    ///      The protocol accepts both repo-supported profiles so production deployments do not depend on the local
    ///      development profile matching production byte-for-byte.
    bytes32 internal constant CANONICAL_PREDICTOR_CODEHASH_PRODUCTION =
        0x884ced7ebdd618bd25235051571083352c3a8ad44c6d6b9f4f355b0c91c81d38;

    /// @dev Canonical OKFactoryStage1Module codehash for the default Foundry profile.
    bytes32 internal constant CANONICAL_STAGE1_MODULE_CODEHASH_DEFAULT =
        0x4c801afc0655451fb76c0b0f7e87fd76b2506c73715b69201c480e00133fcdf9;

    /// @dev Canonical OKFactoryStage1Module codehash for the production Foundry profile.
    bytes32 internal constant CANONICAL_STAGE1_MODULE_CODEHASH_PRODUCTION =
        0x79c5939b508b4a481a49b047eb97aa099d7ddd64717f299d0f6a3e4a72c1c63f;

    /// @dev Canonical OKFactoryStage2Module codehash for the default Foundry profile.
    bytes32 internal constant CANONICAL_STAGE2_MODULE_CODEHASH_DEFAULT =
        0x60310a24f25162c40cdf338c92883dcaf7905e6335028669b3706156b21fd75c;

    /// @dev Canonical OKFactoryStage2Module codehash for the production Foundry profile.
    bytes32 internal constant CANONICAL_STAGE2_MODULE_CODEHASH_PRODUCTION =
        0x8dd1034f3aff95619cd9c76792e1b5f96654f2d7d12b96661b39dc05d6c81f74;

    /// @dev Canonical OKFactoryAuthAccountModule codehash for the default Foundry profile.
    bytes32 internal constant CANONICAL_AUTH_ACCOUNT_MODULE_CODEHASH_DEFAULT =
        0xbfb78e3a714ffc79f93c40eaab64ec89300c1597873d9ae5ee5e0172f53ff56b;

    /// @dev Canonical OKFactoryAuthAccountModule codehash for the production Foundry profile.
    bytes32 internal constant CANONICAL_AUTH_ACCOUNT_MODULE_CODEHASH_PRODUCTION =
        0xf8f775e3dcad6a36b4afe4e8119d7c9ef394401e1297d1243fce57f78cd374db;

    /// @dev Canonical MiniScriptEngine codehash for the default Foundry profile.
    bytes32 internal constant MINISCRIPT_ENGINE_CODEHASH_DEFAULT =
        0xd173247f3b8db6028f80a381680675c484963ae6bf29f28ed9939040472a08c6;

    /// @dev Canonical MiniScriptEngine codehash for the production Foundry profile.
    bytes32 internal constant MINISCRIPT_ENGINE_CODEHASH_PRODUCTION =
        0x4cc7f3f5df109bb2210cb63cd0865f43fd00671f8e01e139785f9ee9139235f6;

    /// @dev Canonical MiniScriptAnalyzer codehash for the default Foundry profile.
    bytes32 internal constant MINISCRIPT_ANALYZER_CODEHASH_DEFAULT =
        0x2e4bfacf6b17f01090760a54cb9130a08f7d50a6924051c2ba16572176cca8d9;

    /// @dev Canonical MiniScriptAnalyzer codehash for the production Foundry profile.
    bytes32 internal constant MINISCRIPT_ANALYZER_CODEHASH_PRODUCTION =
        0xc45b74704e9eb2d587d936c9899f3e0a7932e2d079af03ad0aeb13a4b7f2cba4;

    /// @dev Canonical MiniScriptABIEncoder codehash for the default Foundry profile.
    bytes32 internal constant MINISCRIPT_ABI_ENCODER_CODEHASH_DEFAULT =
        0x3136565577e30e8ea04447a8ac066d0399837687a5436a61f49285b1c5fe00f1;

    /// @dev Canonical MiniScriptABIEncoder codehash for the production Foundry profile.
    bytes32 internal constant MINISCRIPT_ABI_ENCODER_CODEHASH_PRODUCTION =
        0xfdee783e333775ee2c19dfb54e581aca9a5d5702898f0f41beb05ac9550647ad;

    /// @dev Canonical InteractOpsModule codehash for the default Foundry profile.
    bytes32 internal constant INTERACT_OPS_MODULE_CODEHASH_DEFAULT =
        0x403d09910edcb7ab57039c4fd03ea98346ed2f38b1ed4b7424e3798338b83b7d;

    /// @dev Canonical InteractOpsModule codehash for the production Foundry profile.
    bytes32 internal constant INTERACT_OPS_MODULE_CODEHASH_PRODUCTION =
        0x9263c853e12f32c964ea69bb1263eae71dc92a59fc907105090b8afed5b506b0;

    /// @dev Canonical RegistryPauseModule codehash for the default Foundry profile.
    bytes32 internal constant REGISTRY_PAUSE_MODULE_CODEHASH_DEFAULT =
        0x215df7a4f077922707f8c270b0923c5dac612cbc43eb5685ae6c9de5aa84622f;

    /// @dev Canonical RegistryPauseModule codehash for the production Foundry profile.
    bytes32 internal constant REGISTRY_PAUSE_MODULE_CODEHASH_PRODUCTION =
        0x03053d70ff86f26df2bdf9fe57aadc50a5ea48ff7cb2aaec4aaffe71434a2911;

    /// @dev Canonical RegistryTimelockExecutionModule codehash for the default Foundry profile.
    bytes32 internal constant REGISTRY_TIMELOCK_EXECUTION_MODULE_CODEHASH_DEFAULT =
        0xa0adc82a7537d1b89ad1ec02e564e1abf61d369f341b112add59f23341b439c9;

    /// @dev Canonical RegistryTimelockExecutionModule codehash for the production Foundry profile.
    bytes32 internal constant REGISTRY_TIMELOCK_EXECUTION_MODULE_CODEHASH_PRODUCTION =
        0x12311128cf2ece2a59c38de84b73d6ff27d2c7e9621b8756a98d92c8b5ed9243;

    /// @dev Canonical TimelockPolicyProgramRunner codehash for the default Foundry profile.
    bytes32 internal constant TIMELOCK_POLICY_RUNNER_CODEHASH_DEFAULT =
        0x2b48a51e76e3f670dabf163c3bfb5728942f5b03962239b88d96cb62aa68aafb;

    /// @dev Canonical TimelockPolicyProgramRunner codehash for the production Foundry profile.
    bytes32 internal constant TIMELOCK_POLICY_RUNNER_CODEHASH_PRODUCTION =
        0xb9597c62d2fe4e251a5982c1180bcec77db09c22a1087f7726faa44110b3b2f7;

    function isAcceptedPredictorCodehash(bytes32 predictorCodehash) internal pure returns (bool) {
        return predictorCodehash == CANONICAL_PREDICTOR_CODEHASH_DEFAULT
            || predictorCodehash == CANONICAL_PREDICTOR_CODEHASH_PRODUCTION;
    }

    function isAcceptedStage1ModuleCodehash(bytes32 moduleCodehash) internal pure returns (bool) {
        return moduleCodehash == CANONICAL_STAGE1_MODULE_CODEHASH_DEFAULT
            || moduleCodehash == CANONICAL_STAGE1_MODULE_CODEHASH_PRODUCTION;
    }

    function isAcceptedStage2ModuleCodehash(bytes32 moduleCodehash) internal pure returns (bool) {
        return moduleCodehash == CANONICAL_STAGE2_MODULE_CODEHASH_DEFAULT
            || moduleCodehash == CANONICAL_STAGE2_MODULE_CODEHASH_PRODUCTION;
    }

    function isAcceptedAuthAccountModuleCodehash(bytes32 moduleCodehash) internal pure returns (bool) {
        return moduleCodehash == CANONICAL_AUTH_ACCOUNT_MODULE_CODEHASH_DEFAULT
            || moduleCodehash == CANONICAL_AUTH_ACCOUNT_MODULE_CODEHASH_PRODUCTION;
    }

    function isAcceptedMiniScriptEngineCodehash(bytes32 codeHash) internal pure returns (bool) {
        return codeHash == MINISCRIPT_ENGINE_CODEHASH_DEFAULT || codeHash == MINISCRIPT_ENGINE_CODEHASH_PRODUCTION;
    }

    /// @notice Return whether a runtime hash is an approved canonical MiniScript analyzer.
    /// @param codeHash Runtime bytecode hash to validate.
    /// @return True for either reproducible Foundry profile artifact.
    function isAcceptedMiniScriptAnalyzerCodehash(bytes32 codeHash) internal pure returns (bool) {
        return codeHash == MINISCRIPT_ANALYZER_CODEHASH_DEFAULT || codeHash == MINISCRIPT_ANALYZER_CODEHASH_PRODUCTION;
    }

    /// @notice Return whether a runtime hash is an approved recursive ABI encoder.
    function isAcceptedMiniScriptABIEncoderCodehash(bytes32 codeHash) internal pure returns (bool) {
        return
            codeHash == MINISCRIPT_ABI_ENCODER_CODEHASH_DEFAULT
                || codeHash == MINISCRIPT_ABI_ENCODER_CODEHASH_PRODUCTION;
    }

    /// @notice Return whether a runtime is an approved Interact delegatecall module.
    function isAcceptedInteractOpsModuleCodehash(bytes32 codeHash) internal pure returns (bool) {
        return codeHash == INTERACT_OPS_MODULE_CODEHASH_DEFAULT || codeHash == INTERACT_OPS_MODULE_CODEHASH_PRODUCTION;
    }

    /// @notice Return whether a runtime is an accepted Registry pause delegatecall module.
    function isAcceptedRegistryPauseModuleCodehash(bytes32 codeHash) internal pure returns (bool) {
        return
            codeHash == REGISTRY_PAUSE_MODULE_CODEHASH_DEFAULT || codeHash == REGISTRY_PAUSE_MODULE_CODEHASH_PRODUCTION;
    }

    /// @notice Return whether a runtime is an accepted Registry timelock delegatecall module.
    function isAcceptedRegistryTimelockExecutionModuleCodehash(bytes32 codeHash) internal pure returns (bool) {
        return codeHash == REGISTRY_TIMELOCK_EXECUTION_MODULE_CODEHASH_DEFAULT
            || codeHash == REGISTRY_TIMELOCK_EXECUTION_MODULE_CODEHASH_PRODUCTION;
    }

    /// @notice Validate an engine and its exact profile-matched CREATE children.
    /// @dev Checking only the engine runtime is insufficient: constructor code
    ///      can deploy substituted children and then return the accepted runtime.
    function isAcceptedMiniScriptDeployment(address engine) internal view returns (bool) {
        bytes32 engineCodehash = engine.codehash;
        bytes32 analyzerCodehash = _miniScriptChild(engine, 1).codehash;
        bytes32 encoderCodehash = _miniScriptChild(engine, 2).codehash;
        if (engineCodehash == MINISCRIPT_ENGINE_CODEHASH_DEFAULT) {
            return analyzerCodehash == MINISCRIPT_ANALYZER_CODEHASH_DEFAULT
                && encoderCodehash == MINISCRIPT_ABI_ENCODER_CODEHASH_DEFAULT;
        }
        if (engineCodehash == MINISCRIPT_ENGINE_CODEHASH_PRODUCTION) {
            return analyzerCodehash == MINISCRIPT_ANALYZER_CODEHASH_PRODUCTION
                && encoderCodehash == MINISCRIPT_ABI_ENCODER_CODEHASH_PRODUCTION;
        }
        return false;
    }

    /// @notice Return whether two deployments implement the same MiniScript language release.
    /// @dev Equal addresses are inherently identical. Separate deployments must
    ///      either be current canonical builds or match across the engine and both
    ///      deterministic child runtimes. The latter keeps older same-release
    ///      deployments compatible without trusting only the parent runtime.
    function isCompatibleMiniScriptDeployment(address left, address right) internal view returns (bool) {
        if (left.code.length == 0 || right.code.length == 0) return false;
        if (left == right) return true;
        if (isAcceptedMiniScriptDeployment(left) && isAcceptedMiniScriptDeployment(right)) return true;

        address leftAnalyzer = _miniScriptChild(left, 1);
        address rightAnalyzer = _miniScriptChild(right, 1);
        address leftEncoder = _miniScriptChild(left, 2);
        address rightEncoder = _miniScriptChild(right, 2);
        return left.codehash == right.codehash && leftAnalyzer.code.length != 0 && rightAnalyzer.code.length != 0
            && leftAnalyzer.codehash == rightAnalyzer.codehash && leftEncoder.code.length != 0
            && rightEncoder.code.length != 0 && leftEncoder.codehash == rightEncoder.codehash;
    }

    function isAcceptedTimelockPolicyRunnerCodehash(bytes32 codeHash) internal pure returns (bool) {
        return
            codeHash == TIMELOCK_POLICY_RUNNER_CODEHASH_DEFAULT
                || codeHash == TIMELOCK_POLICY_RUNNER_CODEHASH_PRODUCTION;
    }

    function _miniScriptChild(address engine, uint8 nonce) private pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", engine, bytes1(nonce))))));
    }
}
