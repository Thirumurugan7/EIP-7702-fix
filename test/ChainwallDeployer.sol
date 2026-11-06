// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.36;

import {Test} from "forge-std/Test.sol";

import {OKFactory} from "../src/OKFactory.sol";
import {OKFactoryConfig} from "../src/OKFactoryConfig.sol";
import {OKFactoryState} from "../src/OKFactoryState.sol";

/// @notice Deploys the complete Chainwall factory family from the local build artifacts in out/
///         on an Arbitrum One fork, then deploys one tenant through the three factory stages.
/// @dev External dependencies are the real Arbitrum One deployments that the official Chainwall
///      factory config also points to (read from 0x33DeD9A544aCd23E03cC445239b38c7a5980490C):
///      Safe 1.3.0 singleton, Safe 1.3.0 proxy factory and ERC-4337 EntryPoint v0.8.
abstract contract ChainwallDeployer is Test {
    address internal constant SAFE_SINGLETON = 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552;
    address internal constant SAFE_PROXY_FACTORY = 0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2;
    address internal constant ENTRY_POINT_V0_8 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
    bytes32 internal constant RP_ID_HASH = 0xb2c7832159b5a0738accd665d3db3a8c97fce34088c11e1b7c287e643ddc9399;
    string internal constant ORIGIN = "https://chainwall.eth.limo";

    OKFactory internal factory;
    OKFactoryConfig internal config;
    address internal engine;
    address internal termsRegistry;

    address internal registry;
    OKFactoryState.FactoryInstance internal instance;

    function _fork() internal {
        vm.createSelectFork(vm.envOr("ARB_RPC_URL", string("https://arb1.arbitrum.io/rpc")));
        assertEq(block.chainid, 42161, "not an Arbitrum One fork");
    }

    /// @dev Empty: deploy from the current build in out/. "out-orig/": deploy the unpatched release that
    ///      test/tools/build-original.sh compiled from the base commit.
    string internal artifactRoot;

    /// @dev "File.sol:Name" for the current build, or "<root>File.sol/Name.json" for another build.
    function _artifact(string memory artifact) internal view returns (string memory) {
        if (bytes(artifactRoot).length == 0) return artifact;
        string[] memory parts = vm.split(artifact, ":");
        return string.concat(artifactRoot, parts[0], "/", parts[1], ".json");
    }

    function _d(string memory artifact) internal returns (address a) {
        a = deployCode(_artifact(artifact));
        require(a != address(0) && a.code.length != 0, string.concat("deploy failed: ", artifact));
    }

    function _d(string memory artifact, bytes memory args) internal returns (address a) {
        a = deployCode(_artifact(artifact), args);
        require(a != address(0) && a.code.length != 0, string.concat("deploy failed: ", artifact));
    }

    function _deployFactoryFamily() internal {
        OKFactoryConfig.FacetAddresses memory f;
        f.users = _d("RegistryUsersFacet.sol:RegistryUsersFacet");
        f.accounts = _d("RegistryAccountsFacet.sol:RegistryAccountsFacet");
        f.orgs = _d("RegistryOrgsFacet.sol:RegistryOrgsFacet");
        f.contractsFacet = _d("RegistryContractsFacet.sol:RegistryContractsFacet");
        f.interactions = _d("RegistryInteractionsFacet.sol:RegistryInteractionsFacet");
        f.metadata = _d("RegistryMetadataFacet.sol:RegistryMetadataFacet");
        f.policies = _d("RegistryPoliciesFacet.sol:RegistryPoliciesFacet");
        f.policyState = _d("RegistryPolicyStateFacet.sol:RegistryPolicyStateFacet");
        f.timelock = _d("RegistryTimelockFacet.sol:RegistryTimelockFacet");
        f.timelockUpgrade = _d("RegistryTimelockUpgradeFacet.sol:RegistryTimelockUpgradeFacet");
        f.timelockRelease = _d("RegistryTimelockReleaseFacet.sol:RegistryTimelockReleaseFacet");
        f.tokens = _d("RegistryTokensFacet.sol:RegistryTokensFacet");
        f.tokenCommits = _d("RegistryTokenCommitsFacet.sol:RegistryTokenCommitsFacet");
        f.sync = _d("RegistrySyncFacet.sol:RegistrySyncFacet");
        f.syncQuery = _d("RegistrySyncQueryFacet.sol:RegistrySyncQueryFacet");
        f.auth = _d("RegistryAuthFacet.sol:RegistryAuthFacet");
        f.capabilities = _d("RegistryCapabilitiesFacet.sol:RegistryCapabilitiesFacet");
        f.terms = _d("RegistryTermsFacet.sol:RegistryTermsFacet");
        f.cut = _d("DiamondCutFacet.sol:DiamondCutFacet");
        f.loupe = _d("DiamondLoupeFacet.sol:DiamondLoupeFacet");

        address registryImpl = _d("RegistryDiamond.sol:RegistryDiamond");
        address miniScriptImpl = _d("MiniScript.sol:MiniScript");
        address interactImpl = _d("Interact.sol:Interact");
        engine = _d("MiniScriptEngine.sol:MiniScriptEngine");
        address accountFactoryImpl = _d("AccountFactory.sol:AccountFactory");
        address okAccountImpl = _d("OKAccount.sol:OKAccount");
        address predictor = _d("OKFactoryPredictor.sol:OKFactoryPredictor");

        address components = _d("SafeFactory.sol:SafeComponentsFactory");
        address safeFactoryImpl = _d(
            "SafeFactory.sol:SafeFactoryWithCreate2",
            abi.encode(SAFE_SINGLETON, SAFE_PROXY_FACTORY, interactImpl, false, components)
        );

        OKFactoryConfig.WebAuthnConfig memory w;
        w.factoryImpl = _d("WebAuthnAuthAccountFactory.sol:WebAuthnAuthAccountFactory");
        w.accountImpl = _d("WebAuthnAuthAccount.sol:WebAuthnAuthAccount");
        w.entryPoint = ENTRY_POINT_V0_8;
        w.rpIdHash = RP_ID_HASH;
        w.origin = ORIGIN;
        w.requireUserVerification = true;

        config = OKFactoryConfig(
            _d(
                "OKFactoryConfig.sol:OKFactoryConfig",
                abi.encode(
                    SAFE_SINGLETON,
                    SAFE_PROXY_FACTORY,
                    safeFactoryImpl,
                    f,
                    registryImpl,
                    miniScriptImpl,
                    interactImpl,
                    engine,
                    accountFactoryImpl,
                    okAccountImpl,
                    predictor,
                    w
                )
            )
        );

        address stage1 = _d("OKFactoryStage1Module.sol:OKFactoryStage1Module");
        address stage2 = _d("OKFactoryStage2Module.sol:OKFactoryStage2Module");
        address authModule = _d("OKFactoryAuthAccountModule.sol:OKFactoryAuthAccountModule");
        termsRegistry = _d("TermsRegistry.sol:TermsRegistry", abi.encode(address(this)));

        factory = OKFactory(
            _d("OKFactory.sol:OKFactory", abi.encode(address(config), stage1, stage2, authModule, termsRegistry))
        );
    }

    function _deployTenant(address owner, uint8 flags, bytes32 salt) internal {
        factory.deployInstanceStage1Deterministic(owner, flags, salt);
        registry = factory.getRegistryByDeploymentKey(factory.deriveInstanceDeploymentKey(salt, owner, flags));
        require(registry != address(0), "stage 1a: registry not recorded");
        factory.deployInstanceStage1Finalize(registry);
        factory.deployInstanceStage2(registry);
        instance = factory.getInstance(registry);
    }
}
