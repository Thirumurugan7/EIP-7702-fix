// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.36;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {AccountFactory} from "../src/AccountFactory.sol";
import {Interact} from "../src/Interact.sol";
import {MiniScript} from "../src/MiniScript.sol";
import {MiniScriptEngine} from "../src/MiniScriptEngine.sol";
import {OKAccount} from "../src/OKAccount.sol";
import {OKFactory} from "../src/OKFactory.sol";
import {OKFactoryAuthAccountModule} from "../src/OKFactoryAuthAccountModule.sol";
import {OKFactoryConfig} from "../src/OKFactoryConfig.sol";
import {OKFactoryPredictor} from "../src/OKFactoryPredictor.sol";
import {OKFactoryStage1Module} from "../src/OKFactoryStage1Module.sol";
import {OKFactoryStage2Module} from "../src/OKFactoryStage2Module.sol";
import {RegistryDiamond} from "../src/RegistryDiamond.sol";
import {SafeComponentsFactory, SafeFactoryWithCreate2} from "../src/SafeFactory.sol";
import {TermsRegistry} from "../src/TermsRegistry.sol";
import {WebAuthnAuthAccount} from "../src/WebAuthnAuthAccount.sol";
import {WebAuthnAuthAccountFactory} from "../src/WebAuthnAuthAccountFactory.sol";
import {DiamondCutFacet} from "../src/registry/facets/DiamondCutFacet.sol";
import {DiamondLoupeFacet} from "../src/registry/facets/DiamondLoupeFacet.sol";
import {RegistryAccountsFacet} from "../src/registry/facets/RegistryAccountsFacet.sol";
import {RegistryAuthFacet} from "../src/registry/facets/RegistryAuthFacet.sol";
import {RegistryCapabilitiesFacet} from "../src/registry/facets/RegistryCapabilitiesFacet.sol";
import {RegistryContractsFacet} from "../src/registry/facets/RegistryContractsFacet.sol";
import {RegistryInteractionsFacet} from "../src/registry/facets/RegistryInteractionsFacet.sol";
import {RegistryMetadataFacet} from "../src/registry/facets/RegistryMetadataFacet.sol";
import {RegistryOrgsFacet} from "../src/registry/facets/RegistryOrgsFacet.sol";
import {RegistryPoliciesFacet} from "../src/registry/facets/RegistryPoliciesFacet.sol";
import {RegistryPolicyStateFacet} from "../src/registry/facets/RegistryPolicyStateFacet.sol";
import {RegistrySyncFacet} from "../src/registry/facets/RegistrySyncFacet.sol";
import {RegistrySyncQueryFacet} from "../src/registry/facets/RegistrySyncQueryFacet.sol";
import {RegistryTermsFacet} from "../src/registry/facets/RegistryTermsFacet.sol";
import {RegistryTimelockFacet} from "../src/registry/facets/RegistryTimelockFacet.sol";
import {RegistryTimelockReleaseFacet} from "../src/registry/facets/RegistryTimelockReleaseFacet.sol";
import {RegistryTimelockUpgradeFacet} from "../src/registry/facets/RegistryTimelockUpgradeFacet.sol";
import {RegistryTokenCommitsFacet} from "../src/registry/facets/RegistryTokenCommitsFacet.sol";
import {RegistryTokensFacet} from "../src/registry/facets/RegistryTokensFacet.sol";
import {RegistryUsersFacet} from "../src/registry/facets/RegistryUsersFacet.sol";

/// @notice Deploys one complete Chainwall factory family: facets, implementations, engine, config,
///         stage modules, terms registry and OKFactory. Each contract is its own transaction.
///
///         Dry run (no transactions are sent):
///           FOUNDRY_PROFILE=production FOUNDRY_SOLC=/path/to/oksolc \
///             forge script script/DeployFactoryFamily.s.sol --fork-url $RPC_URL --sender $DEPLOYER
///         Real deployment: add `--broadcast` and a signer (`--account NAME`, `--ledger`, ...).
///
///         Build with the production profile so the deployed modules match the *_PRODUCTION pins.
///         Environment (all optional; defaults are the Arbitrum One values the official config uses):
///           SAFE_SINGLETON, SAFE_PROXY_FACTORY, WEBAUTHN_RP_ID_HASH, WEBAUTHN_ORIGIN,
///           TERMS_REGISTRY_OWNER (defaults to the deployer)
/// @dev Deploying is a production use under the BUSL only for Official Factories published by
///      OKcontract. This script does not make a deployment official.
contract DeployFactoryFamily is Script {
    address internal constant ENTRY_POINT_V0_8 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;

    function run() external returns (OKFactory factory) {
        address safeSingleton = vm.envOr("SAFE_SINGLETON", 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552);
        address safeProxyFactory = vm.envOr("SAFE_PROXY_FACTORY", 0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2);

        vm.startBroadcast();
        (, address deployer,) = vm.readCallers();
        address termsOwner = vm.envOr("TERMS_REGISTRY_OWNER", deployer);

        OKFactoryConfig.FacetAddresses memory f;
        f.users = address(new RegistryUsersFacet());
        f.accounts = address(new RegistryAccountsFacet());
        f.orgs = address(new RegistryOrgsFacet());
        f.contractsFacet = address(new RegistryContractsFacet());
        f.interactions = address(new RegistryInteractionsFacet());
        f.metadata = address(new RegistryMetadataFacet());
        f.policies = address(new RegistryPoliciesFacet());
        f.policyState = address(new RegistryPolicyStateFacet());
        f.timelock = address(new RegistryTimelockFacet());
        f.timelockUpgrade = address(new RegistryTimelockUpgradeFacet());
        f.timelockRelease = address(new RegistryTimelockReleaseFacet());
        f.tokens = address(new RegistryTokensFacet());
        f.tokenCommits = address(new RegistryTokenCommitsFacet());
        f.sync = address(new RegistrySyncFacet());
        f.syncQuery = address(new RegistrySyncQueryFacet());
        f.auth = address(new RegistryAuthFacet());
        f.capabilities = address(new RegistryCapabilitiesFacet());
        f.terms = address(new RegistryTermsFacet());
        f.cut = address(new DiamondCutFacet());
        f.loupe = address(new DiamondLoupeFacet());

        address registryImpl = address(new RegistryDiamond());
        address miniScriptImpl = address(new MiniScript());
        Interact interactImpl = new Interact();
        address engine = address(new MiniScriptEngine());
        address accountFactoryImpl = address(new AccountFactory());
        address okAccountImpl = address(new OKAccount());
        address predictor = address(new OKFactoryPredictor());
        SafeComponentsFactory components = new SafeComponentsFactory();
        address safeFactoryImpl =
            address(new SafeFactoryWithCreate2(safeSingleton, safeProxyFactory, interactImpl, false, components));

        OKFactoryConfig.WebAuthnConfig memory w;
        w.factoryImpl = address(new WebAuthnAuthAccountFactory());
        w.accountImpl = address(new WebAuthnAuthAccount());
        w.entryPoint = ENTRY_POINT_V0_8;
        w.rpIdHash =
            vm.envOr("WEBAUTHN_RP_ID_HASH", bytes32(0xb2c7832159b5a0738accd665d3db3a8c97fce34088c11e1b7c287e643ddc9399));
        w.origin = vm.envOr("WEBAUTHN_ORIGIN", string("https://chainwall.eth.limo"));
        w.requireUserVerification = true;

        OKFactoryConfig config = new OKFactoryConfig(
            safeSingleton,
            safeProxyFactory,
            safeFactoryImpl,
            f,
            registryImpl,
            miniScriptImpl,
            address(interactImpl),
            engine,
            accountFactoryImpl,
            okAccountImpl,
            predictor,
            w
        );

        address stage1 = address(new OKFactoryStage1Module());
        address stage2 = address(new OKFactoryStage2Module());
        address authModule = address(new OKFactoryAuthAccountModule());
        TermsRegistry termsRegistry = new TermsRegistry(termsOwner);
        factory = new OKFactory(config, stage1, stage2, authModule, termsRegistry);
        vm.stopBroadcast();

        console2.log("deployer        ", deployer);
        console2.log("OKFactory       ", address(factory));
        console2.log("OKFactoryConfig ", address(config));
        console2.log("TermsRegistry   ", address(termsRegistry));
        console2.log("MiniScriptEngine", engine);
        console2.log("Registry impl   ", registryImpl);
        console2.log("Interact impl   ", address(interactImpl));
        console2.log("Users facet     ", f.users);
    }
}
