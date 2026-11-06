// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

import {Delegation7702} from "./Delegation7702.sol";
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
        0x0fb5ef621a6c0dd8ed5c3c22894a29c6185c0e28300bd86d0cd86dbb721e80b9;

    /// @dev Canonical OKFactoryStage1Module codehash for the production Foundry profile.
    bytes32 internal constant CANONICAL_STAGE1_MODULE_CODEHASH_PRODUCTION =
        0x813cc2ce8cbbe8748deb2641fc1cada51d49642bad8155e8fcf2ef8f75776a02;

    /// @dev Canonical OKFactoryStage2Module codehash for the default Foundry profile.
    bytes32 internal constant CANONICAL_STAGE2_MODULE_CODEHASH_DEFAULT =
        0x24e921a4c2cce5f4aacc223bf9e7feae720e2de7917ddb6f389674bb42f44cc4;

    /// @dev Canonical OKFactoryStage2Module codehash for the production Foundry profile.
    bytes32 internal constant CANONICAL_STAGE2_MODULE_CODEHASH_PRODUCTION =
        0x0be23f70c634bbc33a5ce2a2ac1ca4d02c6faac15c97eeaafb00a5a8468158fa;

    /// @dev Canonical OKFactoryAuthAccountModule codehash for the default Foundry profile.
    bytes32 internal constant CANONICAL_AUTH_ACCOUNT_MODULE_CODEHASH_DEFAULT =
        0xbfb78e3a714ffc79f93c40eaab64ec89300c1597873d9ae5ee5e0172f53ff56b;

    /// @dev Canonical OKFactoryAuthAccountModule codehash for the production Foundry profile.
    bytes32 internal constant CANONICAL_AUTH_ACCOUNT_MODULE_CODEHASH_PRODUCTION =
        0xf8f775e3dcad6a36b4afe4e8119d7c9ef394401e1297d1243fce57f78cd374db;

    /// @dev Canonical MiniScriptEngine codehash for the default Foundry profile.
    bytes32 internal constant MINISCRIPT_ENGINE_CODEHASH_DEFAULT =
        0x97358a102b8bcc7611eb5a7a31a8af9d641531fdee5a1a27049eaff221ef79ab;

    /// @dev Canonical MiniScriptEngine codehash for the production Foundry profile.
    bytes32 internal constant MINISCRIPT_ENGINE_CODEHASH_PRODUCTION =
        0x32509141c992b8a9c7c95fd3f4417de35a6ea5ee89475c92bbe7fcf068e59068;

    /// @dev Canonical MiniScriptAnalyzer codehash for the default Foundry profile.
    bytes32 internal constant MINISCRIPT_ANALYZER_CODEHASH_DEFAULT =
        0x2deb68be2bacc946601a71318e690fb5327e32ec64e3130b342aedf14329b1c8;

    /// @dev Canonical MiniScriptAnalyzer codehash for the production Foundry profile.
    bytes32 internal constant MINISCRIPT_ANALYZER_CODEHASH_PRODUCTION =
        0x3c991e499001b150003ab11fed8d7446f008119865533881f557cbe0ba72dc88;

    /// @dev Canonical MiniScriptABIEncoder codehash for the default Foundry profile.
    bytes32 internal constant MINISCRIPT_ABI_ENCODER_CODEHASH_DEFAULT =
        0x881e6d8dd37d9928c009c5e373548b34ac0e275da21a2a0a2659413c707ea187;

    /// @dev Canonical MiniScriptABIEncoder codehash for the production Foundry profile.
    bytes32 internal constant MINISCRIPT_ABI_ENCODER_CODEHASH_PRODUCTION =
        0x1625b7b5b6681c2449c13abd246212a8b1923640c193e9b621730f7825ebe091;

    /// @dev Canonical InteractOpsModule codehash for the default Foundry profile.
    bytes32 internal constant INTERACT_OPS_MODULE_CODEHASH_DEFAULT =
        0x679ee52a85f17c413ba586826a70d3374ce2fac175947bb258909e357198f8ec;

    /// @dev Canonical InteractOpsModule codehash for the production Foundry profile.
    bytes32 internal constant INTERACT_OPS_MODULE_CODEHASH_PRODUCTION =
        0xf173e1cd95f7a6d35cd67d75b77f9dc928a927356414f7c9cf488334d5c73f7b;

    /// @dev Canonical RegistryPauseModule codehash for the default Foundry profile.
    bytes32 internal constant REGISTRY_PAUSE_MODULE_CODEHASH_DEFAULT =
        0x53c9ff8f8098163c9a71ee9f2fd5f648d2bc1202a6d4420ab4be20fea7841077;

    /// @dev Canonical RegistryPauseModule codehash for the production Foundry profile.
    bytes32 internal constant REGISTRY_PAUSE_MODULE_CODEHASH_PRODUCTION =
        0x7be20abae2ee8f3bf0bbdaa6a313b0180caffc480ff41a5b9ab623b25bdd58ba;

    /// @dev Canonical RegistryTimelockExecutionModule codehash for the default Foundry profile.
    bytes32 internal constant REGISTRY_TIMELOCK_EXECUTION_MODULE_CODEHASH_DEFAULT =
        0x5f3341f4082f6e7f495e100552b700099200ded34a1e43dc5a4527a1c0b900a1;

    /// @dev Canonical RegistryTimelockExecutionModule codehash for the production Foundry profile.
    bytes32 internal constant REGISTRY_TIMELOCK_EXECUTION_MODULE_CODEHASH_PRODUCTION =
        0x112ab9d83673d9dce48d8a5f998178f25d1e6529f87c142c4fce3669f551919b;

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
        if (!Delegation7702.hasContractCode(left) || !Delegation7702.hasContractCode(right)) return false;
        if (left == right) return true;
        if (isAcceptedMiniScriptDeployment(left) && isAcceptedMiniScriptDeployment(right)) return true;

        address leftAnalyzer = _miniScriptChild(left, 1);
        address rightAnalyzer = _miniScriptChild(right, 1);
        address leftEncoder = _miniScriptChild(left, 2);
        address rightEncoder = _miniScriptChild(right, 2);
        return left.codehash == right.codehash && Delegation7702.hasContractCode(leftAnalyzer) && Delegation7702.hasContractCode(rightAnalyzer)
            && leftAnalyzer.codehash == rightAnalyzer.codehash && Delegation7702.hasContractCode(leftEncoder)
            && Delegation7702.hasContractCode(rightEncoder) && leftEncoder.codehash == rightEncoder.codehash;
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
